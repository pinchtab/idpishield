package engine

import (
	"strings"
	"testing"
)

func TestScanSecrets_AWSAKIAHigh(t *testing.T) {
	awsKey := "AKIA" + strings.Repeat("A", 16)
	res := scanSecrets("AWS key leaked: " + awsKey)
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected high-confidence secret detection, got %+v", res)
	}
}

func TestScanSecrets_GitHubPATHigh(t *testing.T) {
	ghPrefix := "gh" + "p_"
	res := scanSecrets("token=" + ghPrefix + strings.Repeat("a", 36))
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected ghp token high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_GoogleAIzaHigh(t *testing.T) {
	googleKey := "AI" + "za" + strings.Repeat("A", 35)
	res := scanSecrets(googleKey)
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected AIza key high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_StripeLiveHigh(t *testing.T) {
	stripePrefix := "sk" + "_live_"
	res := scanSecrets(stripePrefix + strings.Repeat("A", 24))
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected stripe live key high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_AnthropicHigh(t *testing.T) {
	res := scanSecrets("sk" + "-ant-" + strings.Repeat("A", 95))
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected anthropic key high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_OpenAIHigh(t *testing.T) {
	res := scanSecrets("s" + "k-" + strings.Repeat("a", 48))
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected openai key high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_HuggingFaceHigh(t *testing.T) {
	res := scanSecrets("h" + "f_" + strings.Repeat("a", 37))
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected huggingface token high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_AzureSASHigh(t *testing.T) {
	res := scanSecrets("https://blob.example.net/x?sv=2023-01-03&sig=" + strings.Repeat("A", 40))
	if !res.HasSecrets || res.Confidence != "high" {
		t.Fatalf("expected azure sas token high-confidence detection, got %+v", res)
	}
}

func TestScanSecrets_EntropyTokenDetected(t *testing.T) {
	res := scanSecrets("q9W2mR8kT1vL6pN3xH7cZ4bD0sF5jK2")
	if !res.HasSecrets {
		t.Fatalf("expected entropy-based secret detection, got %+v", res)
	}
}

func TestScanSecrets_AWSSecretContextWindow(t *testing.T) {
	secret40 := strings.Repeat("A", 40)

	resNear := scanSecrets("aws secret key=" + secret40)
	if !resNear.HasSecrets || resNear.Confidence != "high" {
		t.Fatalf("expected aws contextual secret detection, got %+v", resNear)
	}

	resFar := scanSecrets(strings.Repeat("x", 120) + secret40 + strings.Repeat("y", 120))
	if resFar.HasSecrets {
		t.Fatalf("expected no aws-secret-key hit without nearby context, got %+v", resFar)
	}
}

func TestScanSecrets_EntropyDoesNotTriggerOnCommonWord(t *testing.T) {
	res := scanSecrets("internationalization")
	if res.HasSecrets {
		t.Fatalf("expected common 20-char word not to trigger entropy detection, got %+v", res)
	}
}

func TestScanSecrets_CleanSentence(t *testing.T) {
	res := scanSecrets("Welcome to our product documentation. This guide explains setup steps.")
	if res.HasSecrets {
		t.Fatalf("expected no secret detection for clean sentence, got %+v", res)
	}
}

func TestScanSecrets_PreFilterSkipsCleanShortText(t *testing.T) {
	res := scanSecrets("The weather is nice today in the park.")
	if res.HasSecrets {
		t.Fatalf("expected no secret detection for short clean text, got %+v", res)
	}
}

func TestScanSecrets_EntropyRunsEvenWithPreFilter(t *testing.T) {
	res := scanSecrets("Xk9mP2qR7nL4wS1vB6cY3jH8dF0eA5t")
	if res.Confidence == "" {
		t.Fatalf("expected secrets scan to return a valid result, got %+v", res)
	}
}

func TestScanSecrets_PasswordWordAloneDoesNotTrigger(t *testing.T) {
	res := scanSecrets("please set your password before continuing")
	if res.HasSecrets {
		t.Fatalf("expected password word alone not to trigger, got %+v", res)
	}
}

func TestScanSecrets_DataURLDoesNotTriggerHigh(t *testing.T) {
	res := scanSecrets("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAA")
	if res.Confidence == "high" {
		t.Fatalf("expected data URL not to trigger high confidence, got %+v", res)
	}
}

func TestScanSecrets_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "whitespace", input: "   \n\t  "},
		{name: "very long", input: strings.Repeat("normal documentation text ", 700)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := scanSecrets(tt.input)
			if res.HasSecrets || len(res.MatchedTypes) != 0 || res.Confidence != "low" {
				t.Fatalf("expected clean edge-case result, got %+v", res)
			}
		})
	}
}
