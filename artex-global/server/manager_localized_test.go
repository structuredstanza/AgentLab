package server

import "testing"

// SetWorkers(n<=0) returns before touching m.pg, so an empty Manager needs no DB.
func TestSetWorkersRejectsNonPositive(t *testing.T) {
	err := (&Manager{}).SetWorkers(0)
	if err == nil {
		t.Fatal("SetWorkers(0) must be rejected")
	}
}
