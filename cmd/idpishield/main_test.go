package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSanitize_DefaultConfigRedactsIP(t *testing.T) {
	output := runSanitizeForTest(t, "Server IP is 203.0.113.7", "--json")
	if !strings.Contains(output, "[REDACTED-IP-ADDRESS]") {
		t.Fatalf("expected default CLI sanitize to redact IPs, got %q", output)
	}
}

func TestRunSanitize_NoRedactIPsDisablesIPRedaction(t *testing.T) {
	output := runSanitizeForTest(t, "Server IP is 203.0.113.7", "--json", "--no-redact-ips")
	if strings.Contains(output, "[REDACTED-IP-ADDRESS]") {
		t.Fatalf("expected --no-redact-ips to preserve IPs, got %q", output)
	}
}

func runSanitizeForTest(t *testing.T, input string, flags ...string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	args := append(append([]string{}, flags...), path)
	runErr := runSanitize(args)

	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	if runErr != nil {
		t.Fatalf("runSanitize returned error: %v", runErr)
	}

	return string(out)
}
