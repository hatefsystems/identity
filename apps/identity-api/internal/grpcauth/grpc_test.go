package grpcauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type testServerStream struct {
	ctx                                        context.Context
	header, sentHeader, trailer                metadata.MD
	sent, received                             any
	headerErr, sendHeaderErr, sendErr, recvErr error
}

func (s *testServerStream) Context() context.Context       { return s.ctx }
func (s *testServerStream) SetHeader(md metadata.MD) error { s.header = md; return s.headerErr }
func (s *testServerStream) SendHeader(md metadata.MD) error {
	s.sentHeader = md
	return s.sendHeaderErr
}
func (s *testServerStream) SetTrailer(md metadata.MD) { s.trailer = md }
func (s *testServerStream) SendMsg(m any) error       { s.sent = m; return s.sendErr }
func (s *testServerStream) RecvMsg(m any) error       { s.received = m; return s.recvErr }

type testContextKey struct{}
type untrustedContextKey string

func TestUnaryContextAndHandlerResultPreserved(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	base := testPeerContext(ca.issue(t, testClientID, nil).Certificates)
	base = context.WithValue(base, testContextKey{}, "original-value")
	base = metadata.NewIncomingContext(base, metadata.Pairs("request-id", "original-metadata"))
	base, cancel := context.WithDeadline(base, now.Add(10*time.Minute))
	defer cancel()
	r := &testRecorder{}
	a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{testMethod: {testClientID}}, newTestClock(now))
	request, response := new(int), new(int)
	sentinel := errors.New("unchanged handler error")
	calls := 0
	got, err := a.UnaryServerInterceptor()(base, request, &grpc.UnaryServerInfo{FullMethod: testMethod}, func(ctx context.Context, req any) (any, error) {
		calls++
		if req != request {
			t.Error("request changed")
		}
		checkContextPreserved(base, ctx, t)
		cancel()
		if ctx.Err() != context.Canceled {
			t.Errorf("derived cancellation = %v", ctx.Err())
		}
		return response, sentinel
	})
	if calls != 1 || got != response || err != sentinel {
		t.Fatalf("handler result changed: calls=%d response=%v err=%v", calls, got, err)
	}
	if len(r.snapshot()) != 0 {
		t.Error("handler error emitted access denial")
	}
	if id, ok := IdentityFromContext(base); ok || !id.IsZero() {
		t.Error("original context acquired identity")
	}
}

func TestStreamWrapperPreservesContextAndMethods(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	certs := ca.issue(t, testClientID, nil).Certificates
	for _, withDeadline := range []bool{false, true} {
		base := testPeerContext(certs)
		base = context.WithValue(base, testContextKey{}, "original-value")
		base = metadata.NewIncomingContext(base, metadata.Pairs("request-id", "original-metadata"))
		var cancel context.CancelFunc
		if withDeadline {
			base, cancel = context.WithDeadline(base, now.Add(10*time.Minute))
		} else {
			base, cancel = context.WithCancel(base)
		}
		r := &testRecorder{}
		a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{testMethod: {testClientID}}, newTestClock(now))
		headerErr, sendHeaderErr, sendErr, recvErr := errors.New("set header"), errors.New("send header"), errors.New("send message"), errors.New("receive message")
		original := &testServerStream{ctx: base, headerErr: headerErr, sendHeaderErr: sendHeaderErr, sendErr: sendErr, recvErr: recvErr}
		server, sent, received := new(int), new(int), new(int)
		header, sentHeader, trailer := metadata.Pairs("header", "one"), metadata.Pairs("sent", "two"), metadata.Pairs("trailer", "three")
		sentinel := status.Error(codes.DataLoss, "unchanged stream result")
		calls := 0
		err := a.StreamServerInterceptor()(server, original, &grpc.StreamServerInfo{FullMethod: testMethod, IsClientStream: true, IsServerStream: true}, func(srv any, stream grpc.ServerStream) error {
			calls++
			if srv != server {
				t.Error("server instance changed")
			}
			checkContextPreserved(base, stream.Context(), t)
			if err := stream.SetHeader(header); err != headerErr {
				t.Errorf("SetHeader error = %v", err)
			}
			if err := stream.SendHeader(sentHeader); err != sendHeaderErr {
				t.Errorf("SendHeader error = %v", err)
			}
			stream.SetTrailer(trailer)
			if err := stream.SendMsg(sent); err != sendErr {
				t.Errorf("SendMsg error = %v", err)
			}
			if err := stream.RecvMsg(received); err != recvErr {
				t.Errorf("RecvMsg error = %v", err)
			}
			cancel()
			if stream.Context().Err() != context.Canceled {
				t.Error("cancellation did not reach wrapped stream")
			}
			return sentinel
		})
		cancel()
		if calls != 1 || err != sentinel {
			t.Fatalf("handler calls=%d err=%v", calls, err)
		}
		if !reflect.DeepEqual(original.header, header) || !reflect.DeepEqual(original.sentHeader, sentHeader) || !reflect.DeepEqual(original.trailer, trailer) || original.sent != sent || original.received != received {
			t.Error("wrapped methods did not delegate unchanged")
		}
		if len(r.snapshot()) != 0 {
			t.Error("handler failure emitted access denial")
		}
		if id, ok := IdentityFromContext(original.Context()); ok || !id.IsZero() {
			t.Error("original stream context acquired identity")
		}
	}
}

func TestIdentityAbsentAndNilMethodInfoFailsClosed(t *testing.T) {
	t.Parallel()
	for _, ctx := range []context.Context{context.Background(), metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-spiffe-id", testClientID)), context.WithValue(context.Background(), untrustedContextKey("spiffe-id"), testClientID)} {
		if id, ok := IdentityFromContext(ctx); ok || !id.IsZero() {
			t.Fatalf("unverified context identity = %q, %v", id, ok)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t, now)
	ctx := testPeerContext(ca.issue(t, testClientID, nil).Certificates)
	for _, stream := range []bool{false, true} {
		r := &testRecorder{}
		a := newTestAuthorizer(t, testBundle(ca.cert), r, map[string][]string{testMethod: {testClientID}}, newTestClock(now))
		var err error
		if stream {
			err = a.StreamServerInterceptor()(nil, &testServerStream{ctx: ctx}, nil, func(any, grpc.ServerStream) error { t.Error("nil method invoked stream handler"); return nil })
		} else {
			_, err = a.UnaryServerInterceptor()(ctx, nil, nil, func(context.Context, any) (any, error) { t.Error("nil method invoked unary handler"); return nil, nil })
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("nil info error = %v", err)
		}
		checkDenial(t, r.snapshot(), "unknown", codes.PermissionDenied, testClientID)
		if options, err := a.ServerOptions(nil); err == nil || options != nil {
			t.Fatalf("ServerOptions(nil) = %v, %v", options, err)
		}
	}
}

func checkContextPreserved(original, wrapped context.Context, t *testing.T) {
	t.Helper()
	if id, ok := IdentityFromContext(wrapped); !ok || id.String() != testClientID {
		t.Errorf("identity = %q, %v", id, ok)
	}
	if wrapped.Value(testContextKey{}) != original.Value(testContextKey{}) {
		t.Error("context value changed")
	}
	wantDeadline, wantOK := original.Deadline()
	gotDeadline, gotOK := wrapped.Deadline()
	if gotOK != wantOK || !gotDeadline.Equal(wantDeadline) {
		t.Error("deadline changed or an expiry deadline was imposed")
	}
	if wrapped.Done() != original.Done() {
		t.Error("cancellation channel changed")
	}
	wantMD, _ := metadata.FromIncomingContext(original)
	gotMD, _ := metadata.FromIncomingContext(wrapped)
	if !reflect.DeepEqual(gotMD, wantMD) {
		t.Error("metadata changed")
	}
	wantPeer, _ := peer.FromContext(original)
	gotPeer, _ := peer.FromContext(wrapped)
	if wantPeer != gotPeer {
		t.Error("peer state changed")
	}
}
