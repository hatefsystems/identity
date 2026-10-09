package identitygrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

func proofKey(t *testing.T) *keys.SigningKey {
	t.Helper()
	key, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func proofClaims(nonce string) map[string]any {
	return map[string]any{"jti": uuid.NewString(), "htm": "GET", "htu": testURI, "iat": time.Now().Unix(), "nonce": nonce, "ath": dpop.AccessTokenHash(testToken)}
}

func signProof(t *testing.T, key *keys.SigningKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": key.Alg, "jwk": key.PublicJWK})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key.Signer.(*ecdsa.PrivateKey), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func boundConfig(t *testing.T, key *keys.SigningKey, validator *dpop.Validator) Config {
	t.Helper()
	cfg := testConfig(t)
	claims := validClaims()
	claims.DPoPJKT = key.KID
	cfg.Validator = tokenValidatorFunc(func(context.Context, string, string) (token.ValidatedAccessToken, error) { return claims, nil })
	if validator != nil {
		cfg.DPoP = validator
	}
	return cfg
}

func proofRequest(proof string) *identityv1.ValidateTokenRequest {
	req := validRequest()
	req.AuthorizationScheme, req.HttpMethod, req.HttpUri, req.DpopProof = "DPoP", "GET", testURI, proof
	return req
}

func issueNonce(t *testing.T, validator *dpop.Validator, key *keys.SigningKey, origin string) string {
	t.Helper()
	nonce, err := validator.IssueNonce(rpcContext(t), "rs:"+origin, key.KID)
	if err != nil || nonce == "" {
		t.Fatalf("issue fixture nonce: %v", err)
	}
	return nonce
}

func redisDPoP(t *testing.T, client redis.UniversalClient) *dpop.Validator {
	t.Helper()
	replay, err := dpop.NewRedisReplayGuard(client)
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := dpop.NewRedisNonceStore(client)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := dpop.NewValidator(replay, nonces)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func assertProofOutcome(t *testing.T, response *identityv1.ValidateTokenResponse, err error, outcome identityv1.DpopOutcome) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	assertNoClaims(t, response)
	if response.DpopOutcome != outcome || (response.DpopNonce != "") != (outcome == identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE) {
		t.Fatalf("wrong proof-only outcome: %v", response)
	}
}

func TestDPoPSharedNonceAndReplayAcrossMTLSReplicas(t *testing.T) {
	memory := miniredis.RunT(t)
	key := proofKey(t)
	var clients []identityv1.IdentityServiceClient
	var configs []Config
	for i := range 2 {
		redisClient := redis.NewClient(&redis.Options{Addr: memory.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
		t.Cleanup(func() { _ = redisClient.Close() })
		cfg := boundConfig(t, key, redisDPoP(t, redisClient))
		caller := testCaller
		if i == 1 {
			caller = testOther
			cfg.Policies[testOther] = cfg.Policies[testCaller]
		}
		clients = append(clients, newMTLSHarness(t, cfg, allGrants(caller)).client(t, caller))
		configs = append(configs, cfg)
	}
	req := proofRequest(signProof(t, key, proofClaims("")))
	challenge, err := clients[0].ValidateToken(rpcContext(t), req)
	assertProofOutcome(t, challenge, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
	claims := proofClaims(challenge.DpopNonce)
	req.DpopProof = signProof(t, key, claims)
	if response, err := clients[1].ValidateToken(rpcContext(t), req); err != nil || !response.GetActive() || response.GetDpopOutcome() != identityv1.DpopOutcome_DPOP_OUTCOME_UNSPECIFIED || response.GetDpopNonce() != "" {
		t.Fatalf("cross-replica nonce rejected: %v %v", response, err)
	}
	usedNonce, err := clients[0].ValidateToken(rpcContext(t), req)
	assertProofOutcome(t, usedNonce, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
	claims["nonce"] = usedNonce.DpopNonce
	req.DpopProof = signProof(t, key, claims)
	replayed, err := clients[0].ValidateToken(rpcContext(t), req)
	assertProofOutcome(t, replayed, err, identityv1.DpopOutcome_DPOP_OUTCOME_INVALID_PROOF)

	nonce := issueNonce(t, configs[0].DPoP, key, testOrigin)
	req = proofRequest(signProof(t, key, proofClaims(nonce)))
	type result struct {
		response *identityv1.ValidateTokenResponse
		err      error
	}
	results := make(chan result, 24)
	var wg sync.WaitGroup
	for i := range cap(results) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := clients[i%len(clients)].ValidateToken(rpcContext(t), proto.Clone(req).(*identityv1.ValidateTokenRequest))
			results <- result{response, err}
		}()
	}
	wg.Wait()
	close(results)
	active := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.GetActive() {
			active++
		} else {
			assertNoClaims(t, result.response)
			if result.response.DpopOutcome != identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE && result.response.DpopOutcome != identityv1.DpopOutcome_DPOP_OUTCOME_INVALID_PROOF {
				t.Fatal("concurrent proof lost typed outcome")
			}
		}
	}
	if active != 1 {
		t.Fatalf("concurrent proof admitted %d times", active)
	}
}

func TestDPoPStatelessFailuresPreserveNonceAndReplayStateMTLS(t *testing.T) {
	for _, invalid := range []string{"missing proof", "malformed proof", "wrong key", "tampered signature", "missing jti", "wrong method", "wrong URI", "different trailing slash", "wrong ath", "missing ath", "stale iat", "future iat", "wrong scheme"} {
		t.Run(invalid, func(t *testing.T) {
			key := proofKey(t)
			cfg := boundConfig(t, key, nil)
			client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
			nonce := issueNonce(t, cfg.DPoP, key, testOrigin)
			claims := proofClaims(nonce)
			goodProof := signProof(t, key, claims)
			req := proofRequest(goodProof)
			switch invalid {
			case "missing proof":
				req.DpopProof = ""
			case "malformed proof":
				req.DpopProof = "not.a.valid.proof"
			case "wrong key":
				req.DpopProof = signProof(t, proofKey(t), claims)
			case "tampered signature":
				parts := strings.Split(req.DpopProof, ".")
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				sig[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				req.DpopProof = strings.Join(parts, ".")
			case "wrong scheme":
				req.AuthorizationScheme = "Bearer"
			default:
				switch invalid {
				case "missing jti":
					delete(claims, "jti")
				case "wrong method":
					claims["htm"] = "POST"
				case "wrong URI":
					claims["htu"] = testOrigin + "/objects/two"
				case "different trailing slash":
					claims["htu"] = testURI + "/"
				case "wrong ath":
					claims["ath"] = dpop.AccessTokenHash("different-access-token")
				case "missing ath":
					delete(claims, "ath")
				case "stale iat":
					claims["iat"] = time.Now().Add(-2 * time.Minute).Unix()
				case "future iat":
					claims["iat"] = time.Now().Add(time.Minute).Unix()
				}
				req.DpopProof = signProof(t, key, claims)
			}
			response, err := client.ValidateToken(rpcContext(t), req)
			assertProofOutcome(t, response, err, identityv1.DpopOutcome_DPOP_OUTCOME_INVALID_PROOF)
			response, err = client.ValidateToken(rpcContext(t), proofRequest(goodProof))
			if err != nil || !response.GetActive() {
				t.Fatalf("stateless rejection consumed nonce/replay state: %v %v", response, err)
			}
		})
	}
}

func TestDPoPSchemeAndInactiveTokenCannotExposeClaimsMTLS(t *testing.T) {
	for _, scenario := range []string{"bound bearer without proof", "unbound DPoP", "unbound bearer with proof", "inactive token with valid proof"} {
		t.Run(scenario, func(t *testing.T) {
			key := proofKey(t)
			cfg := boundConfig(t, key, nil)
			req := proofRequest(signProof(t, key, proofClaims("")))
			want := identityv1.DpopOutcome_DPOP_OUTCOME_INVALID_PROOF
			switch scenario {
			case "bound bearer without proof":
				req = validRequest()
			case "unbound DPoP", "unbound bearer with proof":
				cfg.Validator = testConfig(t).Validator
				if scenario == "unbound bearer with proof" {
					req.AuthorizationScheme = "Bearer"
				}
			case "inactive token with valid proof":
				cfg.Validator = tokenValidatorFunc(func(context.Context, string, string) (token.ValidatedAccessToken, error) {
					return validClaims(), token.ErrInactiveToken
				})
				want = identityv1.DpopOutcome_DPOP_OUTCOME_UNSPECIFIED
			}
			client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
			response, err := client.ValidateToken(rpcContext(t), req)
			assertProofOutcome(t, response, err, want)
		})
	}
}

func TestDPoPPolicyDenialDoesNotConsumeAuthorityMTLS(t *testing.T) {
	key := proofKey(t)
	cfg := boundConfig(t, key, nil)
	var validations atomic.Int64
	core := cfg.Validator
	cfg.Validator = tokenValidatorFunc(func(ctx context.Context, compact, audience string) (token.ValidatedAccessToken, error) {
		validations.Add(1)
		return core.Validate(ctx, compact, audience)
	})
	grants := allGrants(testCaller)
	grants[identityv1.IdentityService_ValidateToken_FullMethodName] = []string{testCaller, testOther}
	h := newMTLSHarness(t, cfg, grants)
	client := h.client(t, testCaller)
	req := proofRequest(signProof(t, key, proofClaims(issueNonce(t, cfg.DPoP, key, testOrigin))))
	for _, forbidden := range []string{"audience", "origin", "origin port", "missing caller policy"} {
		candidate := proto.Clone(req).(*identityv1.ValidateTokenRequest)
		call := client
		switch forbidden {
		case "audience":
			candidate.ExpectedAudience = testAudience + "/not-granted"
		case "origin":
			candidate.HttpUri = "https://resource.test.attacker.test/objects/one"
		case "origin port":
			candidate.HttpUri = "https://resource.test:8443/objects/one"
		case "missing caller policy":
			call = h.client(t, testOther)
		}
		if response, err := call.ValidateToken(rpcContext(t), candidate); response != nil || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("policy %s: %v %v", forbidden, response, err)
		}
	}
	if validations.Load() != 0 {
		t.Fatal("unapproved resource policy reached token authority")
	}
	if response, err := client.ValidateToken(rpcContext(t), req); err != nil || !response.GetActive() {
		t.Fatalf("policy denial consumed valid proof state: %v %v", response, err)
	}
}

func TestDPoPResourceNormalizationAndRealmIsolationMTLS(t *testing.T) {
	key := proofKey(t)
	cfg := boundConfig(t, key, nil)
	otherOrigin := "https://second-resource.test"
	cfg.Policies[testCaller] = ValidationPolicy{Audiences: []string{testAudience}, Origins: []string{testOrigin, otherOrigin}}
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	claims := proofClaims(issueNonce(t, cfg.DPoP, key, testOrigin))
	claims["htu"] = testURI + "?proof_query=excluded"
	req := proofRequest(signProof(t, key, claims))
	req.HttpUri = "https://RESOURCE.TEST:443/objects/one?observed_query=excluded"
	if response, err := client.ValidateToken(rpcContext(t), req); err != nil || !response.GetActive() {
		t.Fatalf("scheme-based normalization/query exclusion failed: %v %v", response, err)
	}

	nonce := issueNonce(t, cfg.DPoP, key, testOrigin)
	claims = proofClaims(nonce)
	claims["htu"] = otherOrigin + "/objects/one"
	req = proofRequest(signProof(t, key, claims))
	req.HttpUri = otherOrigin + "/objects/one"
	response, err := client.ValidateToken(rpcContext(t), req)
	assertProofOutcome(t, response, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
	if response, err := client.ValidateToken(rpcContext(t), proofRequest(signProof(t, key, proofClaims(nonce)))); err != nil || !response.GetActive() {
		t.Fatalf("different resource consumed another realm's nonce: %v %v", response, err)
	}
}

type replayFunc func(context.Context, string, time.Time) (bool, error)

func (f replayFunc) Remember(ctx context.Context, key string, expiry time.Time) (bool, error) {
	return f(ctx, key, expiry)
}

type nonceFuncs struct {
	issue    func(context.Context, string, string) (string, error)
	validate func(context.Context, string, string, string) (bool, error)
}

func (f nonceFuncs) Issue(ctx context.Context, realm, jkt string) (string, error) {
	return f.issue(ctx, realm, jkt)
}

func (f nonceFuncs) Validate(ctx context.Context, realm, jkt, nonce string) (bool, error) {
	return f.validate(ctx, realm, jkt, nonce)
}

func TestDPoPDependencyFailuresAreNeverInactiveMTLS(t *testing.T) {
	for _, phase := range []string{"issue", "nonce", "replay"} {
		for _, tc := range []struct {
			err  error
			code codes.Code
		}{
			{errors.New("backend private@example.invalid " + testToken), codes.Unavailable},
			{fmt.Errorf("nonce dependency: %w", context.Canceled), codes.Canceled},
			{fmt.Errorf("replay dependency: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
		} {
			t.Run(phase+"/"+tc.code.String(), func(t *testing.T) {
				key := proofKey(t)
				replay := replayFunc(func(context.Context, string, time.Time) (bool, error) {
					if phase == "replay" {
						return false, tc.err
					}
					return true, nil
				})
				nonces := nonceFuncs{
					issue: func(context.Context, string, string) (string, error) { return "", tc.err },
					validate: func(context.Context, string, string, string) (bool, error) {
						if phase == "nonce" {
							return false, tc.err
						}
						return true, nil
					},
				}
				validator, err := dpop.NewValidator(replay, nonces)
				if err != nil {
					t.Fatal(err)
				}
				cfg := boundConfig(t, key, validator)
				nonce := "recognized-fixture-nonce"
				if phase == "issue" {
					nonce = ""
				}
				client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
				response, err := client.ValidateToken(rpcContext(t), proofRequest(signProof(t, key, proofClaims(nonce))))
				if response != nil || status.Code(err) != tc.code || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "@example") {
					t.Fatalf("dependency failure response=%v err=%v", response, err)
				}
			})
		}
	}
}

func TestDPoPRedisOutageFailsClosedMTLS(t *testing.T) {
	memory := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: memory.Addr(), DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond, MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = redisClient.Close() })
	key := proofKey(t)
	cfg := boundConfig(t, key, redisDPoP(t, redisClient))
	client := newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	nonce := issueNonce(t, cfg.DPoP, key, testOrigin)
	memory.Close()
	response, err := client.ValidateToken(rpcContext(t), proofRequest(signProof(t, key, proofClaims(nonce))))
	if response != nil || status.Code(err) != codes.Unavailable {
		t.Fatalf("Redis outage fell back to proof acceptance/negative assertion: %v %v", response, err)
	}
}
