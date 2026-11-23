package db

import (
	"strings"
	"testing"
)

func TestDSLRejectsEmptySubstringExclusion(t *testing.T) {
	for _, dsl := range []string{`ip!=""`, `domain!=""`, `port>1 AND ip!=""`} {
		err := ValidateDSL(dsl)
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("%s: want actionable rejection, got %v", dsl, err)
		}
	}
	for _, dsl := range []string{`ip!=10.0.0.1`, `domain!=staging`, `technology!=nginx`, `technology!=""`, `port!=80`, `ip=""`} {
		if err := ValidateDSL(dsl); err != nil {
			t.Errorf("%s: unexpected error %v", dsl, err)
		}
	}
}
