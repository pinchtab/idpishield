package integrationtests

import (
	"testing"

	idpishield "github.com/pinchtab/idpishield"
)

func mustNewShield(t *testing.T, cfg idpishield.Config) *idpishield.Shield {
	t.Helper()
	shield, err := idpishield.New(cfg)
	if err != nil {
		t.Fatalf("failed to create shield: %v", err)
	}
	return shield
}
