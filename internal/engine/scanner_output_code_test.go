package engine

import "testing"

func TestScanOutputCode_DetectsHarmful(t *testing.T) {
	text := "```bash\nrm -rf /tmp/data\n```"
	result := scanOutputCode(text, outputCodeConfig{})
	if !result.HasCode {
		t.Fatalf("expected code detected")
	}
	if !result.HasHarmfulCode {
		t.Fatalf("expected harmful code detected, got %+v", result)
	}
}

func TestScanOutputCode_AllowCodeReducesSensitivity(t *testing.T) {
	text := "```go\npackage main\nfunc main(){}\n```"
	result := scanOutputCode(text, outputCodeConfig{AllowCode: true})
	if !result.HasCode {
		t.Fatalf("expected code detected")
	}
	if result.HasHarmfulCode {
		t.Fatalf("did not expect harmful code, got %+v", result)
	}
}
