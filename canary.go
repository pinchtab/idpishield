// Package idpishield provides defence against Indirect Prompt Injection (IDPI)
// attacks. This file implements the canary token subsystem.
package idpishield

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// canaryPrefix and canarySuffix wrap the random token.
// The format intentionally resembles an HTML comment so it is invisible
// to most renderers but remains present verbatim in raw LLM input/output.
const (
	canaryPrefix = "<!--CANARY-"
	canarySuffix = "-->"
)

// CanaryResult is returned by CheckCanary and reports whether the injected
// canary token was detected in the LLM response.
type CanaryResult struct {
	// Token is the canary value that was originally injected into the prompt.
	Token string

	// Found is true when the canary token appears in the LLM response,
	// indicating possible prompt leakage or goal hijacking.
	Found bool
}

// generateCanaryToken returns a cryptographically random canary token with
// the format:  <!--CANARY-<16 lowercase hex chars>-->
// 8 random bytes produce 16 hex characters, giving 2^64 unique values.
// Returns a non-nil error only if the system entropy source fails.
func generateCanaryToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return canaryPrefix + hex.EncodeToString(b) + canarySuffix, nil
}

// injectCanary appends the canary token on a new line at the end of prompt.
// Returns:
//   - injectedPrompt : original prompt with the token appended
//   - token          : the canary string the caller must hold for later checking
//   - err            : non-nil only if entropy generation fails
func injectCanary(prompt string) (injectedPrompt string, token string, err error) {
	token, err = generateCanaryToken()
	if err != nil {
		return prompt, "", err
	}
	return prompt + "\n" + token, token, nil
}

// checkCanary reports whether token is present in response.
// An empty token always returns Found=false to prevent false positives.
func checkCanary(response, token string) CanaryResult {
	if token == "" {
		return CanaryResult{Token: token, Found: false}
	}
	trimmedResponse := strings.TrimSpace(response)
	if trimmedResponse == "" {
		return CanaryResult{Token: token, Found: false}
	}
	return CanaryResult{
		Token: token,
		Found: strings.Contains(trimmedResponse, token),
	}
}
