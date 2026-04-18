package engine_test

import (
	"testing"

	idpishield "github.com/pinchtab/idpishield"
)

type validationScanner struct {
	name string
}

func (s *validationScanner) Name() string { return s.name }

func (s *validationScanner) Scan(ctx idpishield.ScanContext) idpishield.ScanResult {
	return idpishield.ScanResult{}
}

func TestNew_NilScannerReturnsError(t *testing.T) {
	_, err := idpishield.New(idpishield.Config{
		Mode:          idpishield.ModeBalanced,
		ExtraScanners: []idpishield.Scanner{nil},
	})
	if err == nil {
		t.Fatalf("expected error for nil scanner")
	}
}

func TestNew_EmptyNameReturnsError(t *testing.T) {
	_, err := idpishield.New(idpishield.Config{
		Mode:          idpishield.ModeBalanced,
		ExtraScanners: []idpishield.Scanner{&validationScanner{name: ""}},
	})
	if err == nil {
		t.Fatalf("expected error for empty scanner name")
	}
}

func TestNew_DuplicateNameReturnsError(t *testing.T) {
	_, err := idpishield.New(idpishield.Config{
		Mode: idpishield.ModeBalanced,
		ExtraScanners: []idpishield.Scanner{
			&validationScanner{name: "dup"},
			&validationScanner{name: "dup"},
		},
	})
	if err == nil {
		t.Fatalf("expected duplicate name error")
	}
}

func TestNew_ReservedNameReturnsError(t *testing.T) {
	_, err := idpishield.New(idpishield.Config{
		Mode:          idpishield.ModeBalanced,
		ExtraScanners: []idpishield.Scanner{&validationScanner{name: "secrets"}},
	})
	if err == nil {
		t.Fatalf("expected reserved-name error")
	}
}

func TestNew_ValidScannerSucceeds(t *testing.T) {
	_, err := idpishield.New(idpishield.Config{
		Mode:          idpishield.ModeBalanced,
		ExtraScanners: []idpishield.Scanner{&validationScanner{name: "custom-test"}},
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}
