package auth

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestAuditDetailLogsAnEncodingFailureAndYieldsNoDetail cites no criterion:
// every detail this package records is built from fixed keys and string
// values, so an encoding failure is a mistake reachable only from source, the
// fifth exception in CLAUDE.md's Testing Standards. It pins that such a
// mistake is logged rather than silently recorded as an empty detail.
func TestAuditDetailLogsAnEncodingFailureAndYieldsNoDetail(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zap.DebugLevel)
	svc := &Service{logger: zap.New(core)}

	detail := svc.auditDetail(map[string]any{"bad": make(chan int)})

	if detail != nil {
		t.Errorf("auditDetail() = %s, want nil", detail)
	}

	if got := logs.FilterMessage("auth: encoding audit detail").Len(); got != 1 {
		t.Errorf("got %d %q entries, want 1", got, "auth: encoding audit detail")
	}
}

// TestAuditDetailEncodesPlainFields cites no criterion, for the reason given
// on TestAuditDetailLogsAnEncodingFailureAndYieldsNoDetail: it pins that the
// helper passes a successful encoding through.
func TestAuditDetailEncodesPlainFields(t *testing.T) {
	t.Parallel()

	svc := &Service{logger: zap.NewNop()}

	if got := string(svc.auditDetail(map[string]any{"rule": "open"})); got != `{"rule":"open"}` {
		t.Errorf("auditDetail() = %s, want %s", got, `{"rule":"open"}`)
	}
}
