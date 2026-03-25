package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewServiceClientBoundsAndDefaults(t *testing.T) {
	client := newServiceClient("http://example.com", 100*time.Millisecond, -3, -2, 0)
	if client.retries != 0 {
		t.Fatalf("expected retries to be clamped to 0, got %d", client.retries)
	}
	if client.failureThreshold != 0 {
		t.Fatalf("expected failureThreshold to be clamped to 0, got %d", client.failureThreshold)
	}

	client = newServiceClient("http://example.com", 100*time.Millisecond, 10, 2, 0)
	if client.retries != 3 {
		t.Fatalf("expected retries to be clamped to 3, got %d", client.retries)
	}
	if client.cooldown <= 0 {
		t.Fatal("expected cooldown default to be applied when threshold is enabled")
	}
}

func TestServiceClientAssessRetriesThenSuccess(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"score":72,"level":"high","blocked":true,"reason":"from-service"}`)
	}))
	defer server.Close()

	client := newServiceClient(server.URL, 500*time.Millisecond, 1, 0, 0)
	res, err := client.assess(context.Background(), "text", "https://example.com", "deep")
	if err != nil {
		t.Fatalf("expected retry path to succeed, got error: %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts.Load())
	}
	if res == nil || res.Score == 0 {
		t.Fatalf("expected non-empty result, got %+v", res)
	}
	if res.Patterns == nil || res.Categories == nil {
		t.Fatalf("expected normalized slices, got patterns=%v categories=%v", res.Patterns, res.Categories)
	}
}

func TestServiceClientAssessDoesNotRetryNonRetryable(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	client := newServiceClient(server.URL, 300*time.Millisecond, 3, 0, 0)
	_, err := client.assess(context.Background(), "text", "", "deep")
	if err == nil {
		t.Fatal("expected non-retryable failure")
	}
	if attempts.Load() != 1 {
		t.Fatalf("expected a single attempt for non-retryable errors, got %d", attempts.Load())
	}
}

func TestServiceClientCircuitOpensAfterThreshold(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := newServiceClient(server.URL, 300*time.Millisecond, 0, 2, 250*time.Millisecond)

	_, _ = client.assess(context.Background(), "x", "", "deep")
	_, _ = client.assess(context.Background(), "x", "", "deep")
	_, err := client.assess(context.Background(), "x", "", "deep")

	if err == nil || !strings.Contains(err.Error(), "circuit open") {
		t.Fatalf("expected circuit open error, got %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected third call to be short-circuited, attempts=%d", attempts.Load())
	}
}

func TestServiceClientCircuitClosesAfterCooldown(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := newServiceClient(server.URL, 300*time.Millisecond, 0, 1, 80*time.Millisecond)

	_, _ = client.assess(context.Background(), "x", "", "deep")
	_, openErr := client.assess(context.Background(), "x", "", "deep")
	if openErr == nil || !strings.Contains(openErr.Error(), "circuit open") {
		t.Fatalf("expected circuit open on immediate second call, got %v", openErr)
	}

	time.Sleep(100 * time.Millisecond)
	_, err := client.assess(context.Background(), "x", "", "deep")
	if err == nil {
		t.Fatal("expected service status error after cooldown, got nil")
	}
	if strings.Contains(err.Error(), "circuit open") {
		t.Fatalf("expected cooldown to allow a new request, got %v", err)
	}
	if attempts.Load() < 2 {
		t.Fatalf("expected request to be attempted again after cooldown, attempts=%d", attempts.Load())
	}
}
