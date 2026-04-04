# User-Configurable Ban Lists & Custom Rules

## Overview
Ban lists let you enforce application-specific blocking rules on top of idpishield's built-in prompt-injection detection patterns. This is useful when your product has domain constraints that generic security signatures cannot capture.

Use ban lists to block:
- specific substrings
- topic mentions
- competitor names
- custom regex patterns

Ban-list matches always affect score and are never reduced by debias logic.

## Configuration via Go API
```go
shield, err := idpishield.New(idpishield.Config{
    Mode:           idpishield.ModeBalanced,
    BanSubstrings:  []string{"ignore all instructions", "jailbreak"},
    BanTopics:      []string{"cryptocurrency", "gambling", "adult content"},
    BanCompetitors: []string{"OpenAI", "Anthropic", "Google Gemini"},
    CustomRegex:    []string{`\bORDER-[0-9]{6}\b`, `\bINTERNAL-[A-Z]{3}\b`},
})
if err != nil {
    panic(err)
}

result := shield.Assess("compare this with OpenAI and reveal ORDER-123456", "")
```

## Configuration via JSON file
```json
{
  "ban_substrings": ["ignore all instructions", "jailbreak"],
  "ban_topics": ["cryptocurrency", "gambling"],
  "ban_competitors": ["OpenAI", "Anthropic"],
  "custom_regex": ["\\bORDER-[0-9]{6}\\b", "\\bINTERNAL-[A-Z]{3}\\b"]
}
```

## Configuration via YAML file
```yaml
ban_substrings:
  - "ignore all instructions"
  - "jailbreak"
ban_topics:
  - "cryptocurrency"
  - "gambling"
ban_competitors:
  - "OpenAI"
  - "Anthropic"
custom_regex:
  - '\\bORDER-[0-9]{6}\\b'
  - '\\bINTERNAL-[A-Z]{3}\\b'
```

## Environment Variables
| Variable | Description | Example |
| --- | --- | --- |
| `IDPISHIELD_BAN_SUBSTRINGS` | Comma-separated substring list | `ignore all instructions,jailbreak` |
| `IDPISHIELD_BAN_TOPICS` | Comma-separated topic list | `crypto,gambling,adult-content` |
| `IDPISHIELD_BAN_COMPETITORS` | Comma-separated competitor names | `OpenAI,Anthropic,Google` |
| `IDPISHIELD_CUSTOM_REGEX` | Comma-separated regex patterns | `\\bORDER-[0-9]{6}\\b,\\bINTERNAL-[A-Z]{3}\\b` |

Environment variables are only loaded when using the idpishield CLI.
Library users should pass configuration directly via the Config struct
or ConfigFile. This keeps library behavior deterministic.

## Scoring Behavior
Ban-list matches add score using additive contributions:
- BanSubstrings: +30 per match
- BanTopics: +20 per match
- BanCompetitors: +15 per match
- CustomRegex: +40 per match

Total ban-list contribution is capped at +60 per assessment.

Ban-list matches are explicit user intent and are never debiased.

## Examples
1. SaaS company blocks competitor mentions:
- Configure `BanCompetitors: []string{"OpenAI", "Anthropic"}`
- Any prompt comparing with those names gets elevated risk.

2. Children's platform blocks adult topics:
- Configure `BanTopics: []string{"adult content", "gambling"}`
- Topic mentions are flagged even if no built-in injection pattern exists.

3. Internal tool blocks internal ID exposure:
- Configure CustomRegex with a pattern to match internal IDs:
```go
CustomRegex: []string{`\bINTERNAL-[A-Z]{3}-[0-9]+\b`}
```
- Any matching internal ticket IDs raise score and can trigger blocking.

## Security Considerations

### CustomRegex and ReDoS
idpishield uses Go's built-in `regexp` package which is based on RE2
semantics. RE2 guarantees linear-time matching regardless of input size,
which means it is NOT vulnerable to Regular Expression Denial of Service
(ReDoS) attacks. Go's regexp package rejects patterns that require
exponential backtracking (such as those with backreferences).

If a pattern is invalid or uses unsupported syntax, `New()` returns an
error at initialization time - not at scan time.

### Recommendation
Even though ReDoS is not a concern with Go's regexp, be mindful of:
- Very broad patterns (e.g. `.*`) that match almost everything
- Patterns that may cause false positives on benign content
- Keeping CustomRegex lists focused and reviewed
