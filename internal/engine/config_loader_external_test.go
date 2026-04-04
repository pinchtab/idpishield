package engine_test

import (
	"testing"

	idpishield "github.com/pinchtab/idpishield"
)

func TestLoadEnvVars_DoesNotAffectNewDirectly(t *testing.T) {
	t.Setenv("IDPISHIELD_BAN_SUBSTRINGS", "should-not-appear")

	shield, err := idpishield.New(idpishield.Config{Mode: idpishield.ModeBalanced})
	if err != nil {
		t.Fatalf("failed to create shield: %v", err)
	}

	result := shield.Assess("should-not-appear", "")
	if result.Score != 0 {
		t.Fatalf("expected score 0 when only env var is set, got %d", result.Score)
	}
}
