//go:build integration

package lifecycle_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

type lifecycleBroker struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream
	opts   lifecycle.StreamOptions
}

func lifecycleConnect(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, err := nats.Connect(lifecycleDependency(t, "NATS_URL"), nats.Timeout(3*time.Second), nats.MaxReconnects(100), nats.ReconnectWait(100*time.Millisecond))
	if err != nil {
		t.Fatal("configured NATS integration dependency is unavailable")
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return nc, js
}

func newLifecycleBroker(ctx context.Context, t *testing.T, maxBytes int64) lifecycleBroker {
	t.Helper()
	nc, js := lifecycleConnect(t)
	opts := lifecycle.StreamOptions{Name: "LIFECYCLE_TEST_" + strings.ReplaceAll(uuid.NewString(), "-", ""), MaxBytes: maxBytes, MaxAge: time.Hour}
	stream, err := lifecycle.ProvisionStream(ctx, js, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := js.DeleteStream(ctx, opts.Name); err != nil {
			t.Errorf("delete owned lifecycle stream: %v", err)
		}
	})
	return lifecycleBroker{nc: nc, js: js, stream: stream, opts: opts}
}

func lifecyclePublisher(t *testing.T, beginner lifecycle.Beginner, js lifecycle.JetStreamPublisher, name string, batchSize int32) *lifecycle.Publisher {
	t.Helper()
	publisher, err := lifecycle.NewPublisher(beginner, js, name, lifecycle.PublisherConfig{BatchSize: batchSize, PublishTimeout: time.Second, BatchTimeout: 10 * time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func lifecycleRun(ctx context.Context, t *testing.T, publisher *lifecycle.Publisher, want int) {
	t.Helper()
	if n, err := publisher.RunOnce(ctx); err != nil || n != want {
		t.Fatalf("publisher delivered %d, want %d: %v", n, want, err)
	}
}

func lifecycleConsumer(ctx context.Context, t *testing.T, stream jetstream.Stream, durable string) jetstream.Consumer {
	t.Helper()
	consumer, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: durable, AckPolicy: jetstream.AckExplicitPolicy, DeliverPolicy: jetstream.DeliverAllPolicy,
		FilterSubjects: []string{lifecycle.SubjectCreated, lifecycle.SubjectUpdated, lifecycle.SubjectSuspended, lifecycle.SubjectDeleted},
	})
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func lifecycleReceive(ctx context.Context, t *testing.T, consumer jetstream.Consumer, count int) []*identityv1.UserLifecycleEvent {
	t.Helper()
	batch, err := consumer.Fetch(count, jetstream.FetchMaxWait(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var events []*identityv1.UserLifecycleEvent
	for msg := range batch.Messages() {
		event, err := lifecycle.UnmarshalEvent(msg.Data())
		if err != nil || event.EventType != msg.Subject() || msg.Headers().Get(jetstream.MsgIDHeader) != event.EventId {
			t.Fatalf("invalid delivered envelope/subject/stable ID: %v", err)
		}
		if err := msg.DoubleAck(ctx); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := batch.Error(); err != nil || len(events) != count {
		t.Fatalf("consumer received %d, want %d: %v", len(events), count, err)
	}
	return events
}

func lifecycleMessages(ctx context.Context, t *testing.T, stream jetstream.Stream) uint64 {
	t.Helper()
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return info.State.Msgs
}

func TestLifecycleCommittedFourSubjectBroadcastIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	publisher := lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10)
	first := lifecycleConsumer(f.ctx, t, b.stream, "service_a")
	second := lifecycleConsumer(f.ctx, t, b.stream, "service_b")
	tx := lifecycleTx(t, f)
	user, err := lifecycle.CreateUser(f.ctx, tx, db.CreateUserParams{Email: "not-in-message@lifecycle.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	lifecycleRun(f.ctx, t, publisher, 0)
	if lifecycleMessages(f.ctx, t, b.stream) != 0 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox") != 0 {
		t.Fatal("queued creation escaped before business commit")
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	lifecycleChange(t, f, user.ID, "suspended")
	lifecycleChange(t, f, user.ID, "pending_deletion")
	lifecycleExec(t, f, "UPDATE users SET deleted_at=now()-interval '31 days' WHERE id=$1", user.ID)
	for _, want := range []int64{1, 0} {
		tx := lifecycleTx(t, f)
		if n, err := lifecycleDelete(f.ctx, tx, user.ID); err != nil || n != want {
			t.Fatalf("physical deletion count=%d want=%d err=%v", n, want, err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM users WHERE id=$1", user.ID) != 0 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND subject=$2", user.ID, lifecycle.SubjectDeleted) != 1 {
		t.Fatal("physical deletion did not leave exactly one terminal intent without a user FK")
	}
	for range 4 {
		lifecycleRun(f.ctx, t, publisher, 1)
	}
	lifecycleRun(f.ctx, t, publisher, 0)
	late := lifecycleConsumer(f.ctx, t, b.stream, "late_service")
	wantSubjects := []string{lifecycle.SubjectCreated, lifecycle.SubjectSuspended, lifecycle.SubjectUpdated, lifecycle.SubjectDeleted}
	var baseline []*identityv1.UserLifecycleEvent
	for _, consumer := range []jetstream.Consumer{first, second, late} {
		events := lifecycleReceive(f.ctx, t, consumer, 4)
		for i, event := range events {
			if event.UserId != user.ID.String() || event.EventType != wantSubjects[i] || event.GetRevision() != uint64(i+1) {
				t.Fatalf("publication order/revision mismatch: %v", event)
			}
			if i == 2 && event.GetStatus() != identityv1.UserStatus_USER_STATUS_PENDING_DELETION || i == 3 && (event.Status != nil || len(event.ChangedFields) != 0) {
				t.Fatal("temporary deletion and terminal tombstone were conflated")
			}
			if baseline != nil && !proto.Equal(event, baseline[i]) {
				t.Fatal("independent consumers received different lifecycle envelopes")
			}
			if bytes.Contains(contractPayload(t, event), []byte(user.Email)) {
				t.Fatal("shared lifecycle event disclosed contact value")
			}
		}
		baseline = events
	}
	info, err := b.stream.Info(f.ctx)
	if err != nil || info.Config.Storage != jetstream.FileStorage || info.Config.Retention != jetstream.LimitsPolicy || info.Config.Discard != jetstream.DiscardNew || info.State.Msgs != 4 || info.Config.Duplicates != 2*time.Minute || info.Config.MaxMsgSize != lifecycle.MaxMessageBytes || info.Config.Replicas != 1 {
		t.Fatalf("broadcast retention/topology invalid: %+v %v", info, err)
	}
	if n := lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE published_at IS NOT NULL AND attempts=1"); n != 4 {
		t.Fatalf("acknowledged delivery bookkeeping count=%d", n)
	}
}

func TestLifecycleMixedV1V2AndLegacyBroadcastIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	u := lifecycleCreate(t, f)
	svc, err := profile.New(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := svc.Update(f.ctx, u.ID, u.AuthVersion, "Private shared name", "1"); err != nil || result.Profile.LifecycleRevision != "2" {
		t.Fatalf("profile event transaction failed: %v", err)
	}
	lifecycleChange(t, f, u.ID, "suspended")
	legacyUser, legacyEvent := uuid.New(), uuid.New()
	lifecycleExec(t, f, `INSERT INTO event_outbox(id,subject,payload) VALUES ($1,$2,$3)`, legacyEvent, lifecycle.SubjectDeleted, `{"user_id":"`+legacyUser.String()+`"}`)
	publisher := lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10)
	lifecycleRun(f.ctx, t, publisher, 2)
	lifecycleRun(f.ctx, t, publisher, 1)
	lifecycleRun(f.ctx, t, publisher, 1)
	lifecycleRun(f.ctx, t, publisher, 0)
	consumer := lifecycleConsumer(f.ctx, t, b.stream, "mixed_replay")
	events := lifecycleReceive(f.ctx, t, consumer, 4)
	var revisions []uint64
	var named *identityv1.UserLifecycleEvent
	for _, event := range events {
		if event.UserId == legacyUser.String() {
			if event.SchemaVersion != 1 || event.Revision != nil || event.EventType != lifecycle.SubjectDeleted || event.EventId != legacyEvent.String() {
				t.Fatal("legacy replay invented v2 or a revision")
			}
			continue
		}
		revisions = append(revisions, event.GetRevision())
		if event.GetRevision() == 2 {
			named = event
			if event.SchemaVersion != 2 || event.EventType != lifecycle.SubjectUpdated || len(event.ChangedFields) != 1 || event.ChangedFields[0] != "display_name" {
				t.Fatal("profile publication lost v2 changed-fields metadata")
			}
		} else if event.SchemaVersion != 1 {
			t.Fatal("existing creation/suspension producer changed schema version")
		}
		if bytes.Contains(contractPayload(t, event), []byte("Private shared name")) || bytes.Contains(contractPayload(t, event), []byte(u.Email)) {
			t.Fatal("profile/contact value entered durable broadcast")
		}
	}
	if named == nil || len(revisions) != 3 || revisions[0] != 1 || revisions[1] != 2 || revisions[2] != 3 {
		t.Fatal("mixed-version outbox publication lost per-account order")
	}
	// Independent late readers must be able to replay identical v1/v2/legacy rows.
	late := lifecycleConsumer(f.ctx, t, b.stream, "late_mixed_replay")
	for i, event := range lifecycleReceive(f.ctx, t, late, 4) {
		if !proto.Equal(event, events[i]) {
			t.Fatal("late mixed-version replay changed persisted metadata")
		}
	}
}

func TestLifecycleBrokerOutageAndFullStreamIntegration(t *testing.T) {
	for _, mode := range []string{"closed connection", "missing stream", "full stream"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleDatabase(t)
			b := newLifecycleBroker(f.ctx, t, lifecycle.MaxMessageBytes)
			user := lifecycleCreate(t, f)
			var js lifecycle.JetStreamPublisher = b.js
			name := b.opts.Name
			switch mode {
			case "closed connection":
				closed, closedJS := lifecycleConnect(t)
				closed.Close()
				js = closedJS
			case "missing stream":
				name += "_ABSENT"
			case "full stream":
				full := false
				for range 32 {
					_, err := b.js.Publish(f.ctx, lifecycle.SubjectCreated, bytes.Repeat([]byte("x"), 4096))
					if err != nil {
						full = true
						break
					}
				}
				if !full {
					t.Fatal("bounded stream did not reject new messages at capacity")
				}
				// Fill the remainder too; a 4 KiB refusal alone leaves room for
				// the much smaller metadata-only account notification.
				for range lifecycle.MaxMessageBytes {
					if _, err := b.js.Publish(f.ctx, lifecycle.SubjectCreated, []byte("x")); err != nil {
						break
					}
				}
			}
			before := lifecycleMessages(f.ctx, t, b.stream)
			publisher := lifecyclePublisher(t, f.pool, js, name, 1)
			if n, err := publisher.RunOnce(f.ctx); n != 0 || !errors.Is(err, lifecycle.ErrPublish) {
				t.Fatalf("unacknowledged intent treated as delivered: n=%d err=%v", n, err)
			}
			if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NULL AND attempts=1 AND next_attempt_at>now()", user.ID) != 1 || lifecycleMessages(f.ctx, t, b.stream) != before {
				t.Fatal("outage/full stream lost durable intent or evicted accepted history")
			}
			if mode == "full stream" {
				if err := b.stream.Purge(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			lifecycleExec(t, f, "UPDATE event_outbox SET next_attempt_at=now()")
			lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 1), 1)
			if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NOT NULL AND attempts=2", user.ID) != 1 {
				t.Fatal("recovered broker did not deliver retained intent")
			}
		})
	}
}

type lifecycleCommitFault struct{ lifecycle.Beginner }
type lifecycleRollbackCommit struct{ pgx.Tx }

func (b lifecycleCommitFault) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.Beginner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return lifecycleRollbackCommit{Tx: tx}, nil
}

func (tx lifecycleRollbackCommit) Commit(ctx context.Context) error {
	if err := tx.Rollback(ctx); err != nil {
		return err
	}
	return errors.New("injected rollback after broker PubAck")
}

type lifecycleObservedPublisher struct {
	js       jetstream.JetStream
	ids      []string
	payloads [][]byte
	acks     []*jetstream.PubAck
}

func (p *lifecycleObservedPublisher) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	p.ids = append(p.ids, msg.Header.Get(jetstream.MsgIDHeader))
	p.payloads = append(p.payloads, append([]byte(nil), msg.Data...))
	ack, err := p.js.PublishMsg(ctx, msg, opts...)
	p.acks = append(p.acks, ack)
	return ack, err
}

func TestLifecyclePubAckBeforeDatabaseCommitIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	user := lifecycleCreate(t, f)
	observed := &lifecycleObservedPublisher{js: b.js}
	faulty := lifecyclePublisher(t, lifecycleCommitFault{Beginner: f.pool}, observed, b.opts.Name, 1)
	if n, err := faulty.RunOnce(f.ctx); n != 0 || !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("commit fault reported delivery success: %d %v", n, err)
	}
	if len(observed.acks) != 1 || observed.acks[0] == nil || observed.acks[0].Duplicate || lifecycleMessages(f.ctx, t, b.stream) != 1 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NULL AND attempts=0", user.ID) != 1 {
		t.Fatal("fault was not between real broker acknowledgement and durable DB commit")
	}
	lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, observed, b.opts.Name, 1), 1)
	if len(observed.acks) != 2 || observed.acks[1] == nil || !observed.acks[1].Duplicate || observed.ids[0] != observed.ids[1] || !bytes.Equal(observed.payloads[0], observed.payloads[1]) || lifecycleMessages(f.ctx, t, b.stream) != 1 {
		t.Fatal("retry changed stable identity/payload or bypassed broker deduplication")
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NOT NULL AND attempts=1", user.ID) != 1 {
		t.Fatal("deduplicated PubAck did not commit retry bookkeeping")
	}
}

type lifecycleBlockingPublisher struct {
	js      jetstream.JetStream
	entered chan struct{}
	release chan struct{}
}

func (p *lifecycleBlockingPublisher) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	close(p.entered)
	select {
	case <-p.release:
		return p.js.PublishMsg(ctx, msg, opts...)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestLifecycleConcurrentWorkersDoNotOvertakeIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	user := lifecycleCreate(t, f)
	lifecycleChange(t, f, user.ID, "suspended")
	blocked := &lifecycleBlockingPublisher{js: b.js, entered: make(chan struct{}), release: make(chan struct{})}
	worker := lifecyclePublisher(t, f.pool, blocked, b.opts.Name, 1)
	type result struct {
		n   int
		err error
	}
	finished := make(chan result, 1)
	go func() {
		n, err := worker.RunOnce(f.ctx)
		finished <- result{n, err}
	}()
	select {
	case <-blocked.entered:
	case <-f.ctx.Done():
		t.Fatal("first worker never acquired head")
	}
	// Create an unrelated account only after the first worker has its head lock.
	other := lifecycleCreate(t, f)
	lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10), 1)
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NOT NULL", user.ID) != 0 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NOT NULL", other.ID) != 1 {
		t.Fatal("locked head was overtaken or unrelated user was blocked")
	}
	close(blocked.release)
	select {
	case result := <-finished:
		if result.err != nil || result.n != 1 {
			t.Fatalf("first worker failed: %+v", result)
		}
	case <-f.ctx.Done():
		t.Fatal("first worker did not finish")
	}
	lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10), 1)
	events := lifecycleReceive(f.ctx, t, lifecycleConsumer(f.ctx, t, b.stream, "ordered"), 3)
	if events[0].UserId != other.ID.String() || events[1].UserId != user.ID.String() || events[1].GetRevision() != 1 || events[2].UserId != user.ID.String() || events[2].GetRevision() != 2 {
		t.Fatal("concurrent publication violated per-user order")
	}
}

func TestLifecycleDeferredAndPoisonedHeadsIntegration(t *testing.T) {
	for _, poison := range []bool{false, true} {
		t.Run(map[bool]string{false: "deferred", true: "poisoned"}[poison], func(t *testing.T) {
			f := newLifecycleDatabase(t)
			b := newLifecycleBroker(f.ctx, t, 1024*1024)
			user := lifecycleCreate(t, f)
			lifecycleChange(t, f, user.ID, "suspended")
			if poison {
				lifecycleExec(t, f, "UPDATE event_outbox SET payload='{}' WHERE lifecycle_user_id=$1 AND lifecycle_revision=1", user.ID)
			} else {
				lifecycleExec(t, f, "UPDATE event_outbox SET next_attempt_at=now()+interval '1 hour' WHERE lifecycle_user_id=$1 AND lifecycle_revision=1", user.ID)
			}
			other := lifecycleCreate(t, f)
			publisher := lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10)
			n, err := publisher.RunOnce(f.ctx)
			if n != 1 || poison && !errors.Is(err, lifecycle.ErrPublish) || !poison && err != nil {
				t.Fatalf("blocked head handling n=%d err=%v", n, err)
			}
			if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NOT NULL", user.ID) != 0 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND published_at IS NOT NULL", other.ID) != 1 {
				t.Fatal("deferred/poisoned head was overtaken or unrelated progress stopped")
			}
			lifecycleRun(f.ctx, t, publisher, 0)
			backlog, err := publisher.Backlog(f.ctx)
			if err != nil || backlog.Pending != 2 || poison && (backlog.Invalid != 1 || backlog.Attempts != 1) || !poison && (backlog.Invalid != 0 || backlog.Attempts != 0) {
				t.Fatalf("blocked intent was lost from aggregate backlog: %+v %v", backlog, err)
			}
		})
	}
}

func TestLifecycleLegacyMalformedAndAdminIsolationIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	legacyID, userID := uuid.New(), uuid.New()
	at := time.Now().UTC().Truncate(time.Microsecond)
	legacy := fmt.Sprintf(`{"user_id":%q}`, userID.String())
	lifecycleExec(t, f, "INSERT INTO event_outbox(id,subject,payload,created_at) VALUES ($1,$2,$3,$4)", legacyID, lifecycle.SubjectDeleted, legacy, at)
	for _, payload := range []string{
		`{}`, `{"user_id":null}`, `{"user_id":"not-a-uuid"}`,
		fmt.Sprintf(`{"user_id":%q,"email":"must-not-publish"}`, userID),
		fmt.Sprintf(`{"user_id":%q,"user_id":%q}`, userID, userID),
		fmt.Sprintf(`{"user_id":%q} {}`, userID),
	} {
		lifecycleExec(t, f, "INSERT INTO event_outbox(subject,payload) VALUES ($1,$2)", lifecycle.SubjectDeleted, payload)
	}
	lifecycleExec(t, f, "INSERT INTO event_outbox(subject,payload) VALUES ($1,$2)", lifecycle.SubjectUpdated, legacy)
	lifecycleExec(t, f, "INSERT INTO event_outbox(subject,payload,admin_action) VALUES ($1,$2,true),('audit.security',$2,true),('other.subject',$2,false)", lifecycle.SubjectDeleted, legacy)
	publisher := lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 20)
	if n, err := publisher.RunOnce(f.ctx); n != 1 || !errors.Is(err, lifecycle.ErrPublish) {
		t.Fatalf("legacy/malformed handling n=%d err=%v", n, err)
	}
	events := lifecycleReceive(f.ctx, t, lifecycleConsumer(f.ctx, t, b.stream, "legacy"), 1)
	event := events[0]
	if event.EventId != legacyID.String() || event.UserId != userID.String() || event.Revision != nil || event.Status != nil || len(event.ChangedFields) != 0 || !event.OccurredAt.AsTime().Equal(at) {
		t.Fatalf("legacy tombstone invented history: %v", event)
	}
	var stored string
	if err := f.pool.QueryRow(f.ctx, "SELECT payload FROM event_outbox WHERE id=$1", legacyID).Scan(&stored); err != nil || stored != legacy {
		t.Fatalf("legacy adaptation rewrote persisted payload: %v", err)
	}
	backlog, err := publisher.Backlog(f.ctx)
	if err != nil || backlog.Pending != 7 || backlog.Invalid != 7 || backlog.Attempts != 7 {
		t.Fatalf("malformed intent not retained/alertable: %+v %v", backlog, err)
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE (admin_action OR subject='other.subject') AND published_at IS NULL AND attempts=0") != 3 {
		t.Fatal("lifecycle publisher touched audit-marked or non-lifecycle rows")
	}
}

func TestLifecycleFileStorageBrokerRestartIntegration(t *testing.T) {
	container := strings.TrimSpace(os.Getenv("LIFECYCLE_TEST_NATS_CONTAINER"))
	if container == "" {
		t.Skip("explicit labeled disposable broker restart is not configured")
	}
	if container != "ldp-task63-nats" && container != "admin-test-nats" {
		t.Fatal("refusing inspection of an unrecognized broker container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	inspectCommand := exec.CommandContext(ctx, "docker", "inspect", "--type", "container", "ldp-task63-nats")
	if container == "admin-test-nats" {
		inspectCommand = exec.CommandContext(ctx, "docker", "inspect", "--type", "container", "admin-test-nats")
	}
	inspection, err := inspectCommand.Output()
	if err != nil {
		t.Fatal("configured disposable broker requires working Docker inspection")
	}
	var containers []struct {
		Name   string
		Config struct{ Labels map[string]string }
	}
	if err := json.Unmarshal(inspection, &containers); err != nil || len(containers) != 1 || containers[0].Config.Labels["ldp.task"] != "6.3" || (containers[0].Name != "/ldp-task63-nats" && containers[0].Name != "/admin-test-nats") {
		t.Fatal("refusing restart: container is not an explicitly named Task 6.3 disposable broker")
	}
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(ctx, t, 1024*1024)
	user := lifecycleCreate(t, f)
	lifecycleRun(ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 1), 1)
	consumer := lifecycleConsumer(ctx, t, b.stream, "restart_durable")
	before, err := b.stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restartCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	restartCommand := exec.CommandContext(restartCtx, "docker", "restart", "ldp-task63-nats")
	if container == "admin-test-nats" {
		restartCommand = exec.CommandContext(restartCtx, "docker", "restart", "admin-test-nats")
	}
	err = restartCommand.Run()
	stop()
	if err != nil {
		t.Fatal("explicit disposable broker restart failed")
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if b.nc.IsConnected() {
			probe, stop := context.WithTimeout(ctx, time.Second)
			info, err := b.stream.Info(probe)
			stop()
			if err == nil {
				if !info.Created.Equal(before.Created) || info.State.Msgs != 1 || info.Config.Storage != jetstream.FileStorage {
					t.Fatal("restart replaced stream identity or lost file-backed history")
				}
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("disposable broker did not return after restart")
		case <-ticker.C:
		}
	}
	events := lifecycleReceive(ctx, t, consumer, 1)
	if events[0].UserId != user.ID.String() || events[0].GetRevision() != 1 {
		t.Fatal("durable consumer did not recover pre-restart lifecycle event")
	}
}
