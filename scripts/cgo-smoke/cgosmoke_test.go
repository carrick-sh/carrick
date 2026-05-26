package cgosmoke

import "testing"

func TestCgoBasicCall(t *testing.T) {
	if got := CAdd(2, 40); got != 42 {
		t.Fatalf("CAdd = %d; want 42", got)
	}
}

func TestCgoCallback(t *testing.T) {
	if got := Callback(5); got != 10 {
		t.Fatalf("Callback = %d; want 10", got)
	}
}

func TestCgoThreadCallback(t *testing.T) {
	if got := ThreadCallback(); got != 42 {
		t.Fatalf("ThreadCallback = %d; want 42", got)
	}
}
