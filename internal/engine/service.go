package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// serviceClient communicates with the idpi-shield Python service (Tier 2).
// Handles HTTP transport, serialization, timeouts, and graceful fallback.
type serviceClient struct {
	baseURL          string
	httpClient       *http.Client
	retries          int
	failureThreshold int
	cooldown         time.Duration

	consecutiveFailures atomic.Int32
	circuitOpenUntil    atomic.Int64 // unix nanoseconds
}

func newServiceClient(baseURL string, timeout time.Duration, retries, failureThreshold int, cooldown time.Duration) *serviceClient {
	if retries < 0 {
		retries = 0
	}
	if retries > 3 {
		retries = 3
	}
	if failureThreshold < 0 {
		failureThreshold = 0
	}
	if failureThreshold > 0 && cooldown <= 0 {
		cooldown = 15 * time.Second
	}

	return &serviceClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
		retries:          retries,
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
	}
}

// assessRequest is the JSON request body for POST /assess.
type assessRequest struct {
	Text string `json:"text"`
	URL  string `json:"url,omitempty"`
	Mode string `json:"mode"`
}

// assess sends text to the service for deep semantic analysis.
// Returns the service's RiskResult or an error (caller should fall back to local result).
func (s *serviceClient) assess(ctx context.Context, text, sourceURL, mode string) (*RiskResult, error) {
	if s.isCircuitOpen(time.Now()) {
		return nil, fmt.Errorf("idpishield: service circuit open")
	}

	reqBody := assessRequest{
		Text: text,
		URL:  sourceURL,
		Mode: mode,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("idpishield: marshal request: %w", err)
	}

	attempts := s.retries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		result, retryable, err := s.assessOnce(ctx, data)
		if err == nil {
			s.recordSuccess()
			return result, nil
		}

		lastErr = err
		s.recordFailure(retryable)
		if !retryable || attempt == attempts-1 {
			break
		}

		backoff := time.Duration(50*(1<<attempt)) * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("idpishield: service request canceled: %w", ctx.Err())
		case <-time.After(backoff):
		}
	}

	return nil, lastErr
}

func (s *serviceClient) isCircuitOpen(now time.Time) bool {
	until := s.circuitOpenUntil.Load()
	if until == 0 {
		return false
	}

	if now.UnixNano() < until {
		return true
	}

	s.circuitOpenUntil.Store(0)
	return false
}

func (s *serviceClient) recordSuccess() {
	s.consecutiveFailures.Store(0)
	s.circuitOpenUntil.Store(0)
}

func (s *serviceClient) recordFailure(retryable bool) {
	if !retryable || s.failureThreshold <= 0 {
		return
	}

	failures := s.consecutiveFailures.Add(1)
	if int(failures) < s.failureThreshold {
		return
	}

	s.circuitOpenUntil.Store(time.Now().Add(s.cooldown).UnixNano())
	s.consecutiveFailures.Store(0)
}

func (s *serviceClient) assessOnce(ctx context.Context, payload []byte) (*RiskResult, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/assess", bytes.NewReader(payload))
	if err != nil {
		return nil, false, fmt.Errorf("idpishield: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, fmt.Errorf("idpishield: service request: %w", err)
		}
		return nil, true, fmt.Errorf("idpishield: service request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
		return nil, retryable, fmt.Errorf("idpishield: service returned status %d", resp.StatusCode)
	}

	var result RiskResult
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return nil, false, fmt.Errorf("idpishield: decode response: %w", err)
	}

	// Ensure slices are never nil for JSON consistency
	if result.Patterns == nil {
		result.Patterns = []string{}
	}
	if result.Categories == nil {
		result.Categories = []string{}
	}

	return &result, false, nil
}
