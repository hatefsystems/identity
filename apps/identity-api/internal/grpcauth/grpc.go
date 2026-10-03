package grpcauth

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type identityContextKey struct{}

// IdentityFromContext returns the workload identity admitted by an interceptor.
// It is not a user identity and conveys no user-level permission.
func IdentityFromContext(ctx context.Context) (spiffeid.ID, bool) {
	id, ok := ctx.Value(identityContextKey{}).(spiffeid.ID)
	return id, ok && !id.IsZero()
}

// UnaryServerInterceptor verifies and authorizes each call before its handler.
func (a *Authorizer) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		var method string
		if info != nil {
			method = info.FullMethod
		}
		ctx, err := a.authorize(ctx, method)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor authorizes stream creation only. It neither repeats
// authorization per message nor terminates admitted streams on trust changes.
func (a *Authorizer) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		var method string
		if info != nil {
			method = info.FullMethod
		}
		ctx, err := a.authorize(stream.Context(), method)
		if err != nil {
			return err
		}
		return handler(srv, &authorizedStream{ServerStream: stream, ctx: ctx})
	}
}

type authorizedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authorizedStream) Context() context.Context { return s.ctx }

// ServerOptions installs SPIFFE mTLS and both admission guards. Pass these
// options before additional business interceptor chains and never override the
// transport credentials. No services, listener, or source lifecycle are owned.
func (a *Authorizer) ServerOptions(svids x509svid.Source) ([]grpc.ServerOption, error) {
	if svids == nil {
		return nil, errors.New("grpcauth: SVID source is required")
	}
	config := tlsconfig.MTLSServerConfig(svids, a.bundles, tlsconfig.AuthorizeMemberOf(a.trustDomain))
	config.MinVersion = tls.VersionTLS13
	// go-spiffe verifies through VerifyPeerCertificate, which resumed TLS
	// sessions skip. Require a fresh handshake on each new connection.
	config.SessionTicketsDisabled = true
	return []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(config)),
		grpc.ChainUnaryInterceptor(a.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(a.StreamServerInterceptor()),
	}, nil
}
