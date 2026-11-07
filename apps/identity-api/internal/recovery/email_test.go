package recovery

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func TestRecoveryUsesCanonicalEmailForRealAndDecoySubjects(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "decoy", true: "active"}[active], func(t *testing.T) {
			canonical := "\u00fcser@example.test"
			user := db.User{ID: uuid.New(), Email: canonical, Status: "suspended"}
			if active {
				user.Status = "active"
			}
			store := newFlowStore(user)
			codes, err := New(Config{}, store)
			if err != nil {
				t.Fatal(err)
			}
			transactions := &flowTransactionSpy{}
			flow, err := NewFlowService(codes, store, transactions, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := decoyRecoverySubject(canonical)
			if active {
				want = user.ID
			}
			for _, input := range []string{canonical, " U\u0308SER@EXAMPLE.TEST "} {
				if _, err := flow.Start(context.Background(), input); err != nil || transactions.userID != want {
					t.Fatalf("canonical recovery subject differs: %v", err)
				}
			}
		})
	}
}

func TestRecoveryRejectsInvalidEmailBeforeSavingAuthority(t *testing.T) {
	store := newFlowStore(db.User{ID: uuid.New(), Email: "known@example.test", Status: "active"})
	codes, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}
	transactions := &flowTransactionSpy{}
	flow, err := NewFlowService(codes, store, transactions, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"a\u200cb@example.test", "a\ufffdb@example.test", "a..b@example.test", "\xff@example.test"} {
		if _, err := flow.Start(context.Background(), input); !errors.Is(err, ErrInvalidCode) || transactions.hash != "" {
			t.Fatalf("invalid recovery identity allocated authority: %v", err)
		}
	}
}
