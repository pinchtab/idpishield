package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	idpi "github.com/pinchtab/idpi-shield"
)

func TestWithBearerAuthAcceptsBearerToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := withBearerAuth(next, "secret-token")
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret-token")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}

func TestWithBearerAuthAcceptsAPIKeyHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := withBearerAuth(next, "secret-token")
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("X-API-Key", "secret-token")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}

func TestWithBearerAuthRejectsInvalidToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := withBearerAuth(next, "secret-token")
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestApplyProfileDefaultsProduction(t *testing.T) {
	cfg := idpi.Config{}

	if err := applyProfileDefaults("production", &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.StrictMode {
		t.Fatal("expected strict mode to be enabled in production profile")
	}
	if cfg.MaxInputBytes == 0 || cfg.MaxDecodeDepth == 0 || cfg.MaxDecodedVariants == 0 {
		t.Fatal("expected production profile to set analysis limits")
	}
	if cfg.ServiceRetries == 0 || cfg.ServiceCircuitFailureThreshold == 0 {
		t.Fatal("expected production profile to set service resilience defaults")
	}
	if cfg.ServiceCircuitCooldown < 10*time.Second {
		t.Fatalf("expected production cooldown to be set, got %v", cfg.ServiceCircuitCooldown)
	}
}

func TestApplyProfileDefaultsInvalid(t *testing.T) {
	cfg := idpi.Config{}
	if err := applyProfileDefaults("weird", &cfg); err == nil {
		t.Fatal("expected error for invalid profile")
	}
}
