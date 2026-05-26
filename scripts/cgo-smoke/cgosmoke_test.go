package cgosmoke

import "testing"

// Test names deliberately avoid the "TestCgo" prefix: the conformance harness
// SKIPs TestCgo* (the std-lib runtime cgo tests need a C toolchain it can't
// provide), and that regex would otherwise swallow this whole fixture.

func TestSmokeCAdd(t *testing.T) {
	if got := CAdd(2, 40); got != 42 {
		t.Fatalf("CAdd = %d; want 42", got)
	}
}

func TestSmokeCallback(t *testing.T) {
	if got := Callback(5); got != 10 {
		t.Fatalf("Callback = %d; want 10", got)
	}
}

func TestSmokeThreadCallback(t *testing.T) {
	if got := ThreadCallback(); got != 42 {
		t.Fatalf("ThreadCallback = %d; want 42", got)
	}
}
