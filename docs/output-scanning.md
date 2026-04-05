# Output Scanning

Output scanning analyzes model responses for output-side risks.

## What It Detects

- System prompt leakage indicators.
- Suspicious or malicious URLs.
- PII and secret-like values with optional redaction output.
- Harmful code patterns in generated code.
- Relevance drift against the original user prompt.

## Public API

Use `AssessOutput` when you only need output analysis:

```go
shield, err := idpishield.New(idpishield.Config{Mode: idpishield.ModeBalanced})
if err != nil {
    panic(err)
}
result := shield.AssessOutput(modelResponse, userPrompt)
```

Use `AssessPair` for full input-output coverage:

```go
inputResult, outputResult := shield.AssessPair(userPrompt, modelResponse)
```

## Configuration

- `AllowOutputCode`: reduce sensitivity for code-only output when code is expected.
- `BanOutputCode`: treat any code presence as suspicious.

## CLI

Run dedicated output scanning:

```bash
idpishield scan-output response.txt --original-prompt "summarize security controls"
```

Run output scanning through `scan`:

```bash
idpishield scan response.txt --as-output --original-prompt "summarize security controls"
```

## Output Fields

Output scans populate additional fields:

- `is_output_scan`
- `pii_found`
- `pii_types`
- `redacted_text`
- `relevance_score`
- `code_detected`
- `harmful_code_patterns`
