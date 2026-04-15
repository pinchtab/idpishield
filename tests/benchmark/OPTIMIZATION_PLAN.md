# Continuous Optimization Loop — Plan

## Directive

Execute 250 consecutive optimization loops (Runs #9 through #258) against the
idpishield benchmark harness. Each loop:

1. Picks the easiest most-impactful optimization available from the backlog.
2. Adds **one** new benchmark sample (malicious or safe, diverse across loops).
3. Implements, tests, and verifies the change.
4. Runs the full benchmark cycle via `run-optimization.sh`.
5. Logs the outcome rigorously so work is resumable across sessions.

Ultimate goal: make idpishield the best possible indirect prompt injection
detector for AI agents that browse the web. Stay inside the existing code
conventions; don't introduce new idioms or refactor adjacent code unless the
optimization requires it.

The user has delegated autonomous execution. Don't ask for approval. Keep
going until completion or a true blocker.

---

## Protected Metrics Rule

**CRITICAL**: No change may regress protected metrics:
- False Positives (FP) must not increase
- False Negatives (FN) must not increase

A loop is only successful if `comparison_to_best` is `better` or `same`.
If a change causes `regression`, immediately revert and try a different
optimization.

---

## One-loop Protocol

Each iteration must follow this sequence. Skipping a step risks silent
regressions that poison later loops.

### 1. Plan the Loop (in conversation)

- Pick **one optimization** from the backlog below (or a new friction point
  surfaced by the last run). Priority order:
  1. Pattern gap causing FN (missed attacks)
  2. Context penalty gap causing FP (flagging safe content)
  3. Normalizer/decoder gap (obfuscation bypass)
  4. Research-backed improvement (from papers)
  5. New benchmark sample that exercises under-covered attack vectors
- Pick **one benchmark sample** from the sample-coverage backlog. Track
  which categories have been covered to maintain diversity.
- Briefly state the decision in the per-loop decision entry (see §5).

### 2. Implement

- Code changes must stay within existing style (naming, error shape, test
  patterns, pattern conventions).
- Add or update unit tests alongside any code change.
- For pattern changes: add pattern in `patterns/builtin.go`, use correct
  category constant, assign appropriate severity (1-5).
- For normalizer changes: update `internal/engine/normalizer.go`, ensure
  normalization pipeline order is preserved.
- For decoder changes: update `internal/engine/decoders.go`, ensure
  `isValidDecodedText` check is applied.
- For scorer changes: update `internal/engine/scanner.go`, document the
  scoring rationale.
- For benchmark samples: add JSON in `benchmark/dataset/malicious/` or
  `benchmark/dataset/safe/`, follow the schema exactly.
- Run `go test ./...` — must pass.
- Run `go build ./...` — must compile.

### 3. Benchmark Run (must not regress)

- Run: `./tests/benchmark/scripts/run-optimization.sh`
- Check `results/next_focus.md` for comparison status.
- Target: `comparison_to_best: better` or `same`.
- If `regression`: immediately revert the change and try a different
  optimization.

### 4. Analyze Results

After a successful run:
- Review `results/next_focus.md` for top error categories.
- Review `results/latest.json` for specific FP/FN samples.
- Identify friction points for future loops.
- Note any patterns that could be generalized.

### 5. Log the Outcome

Append to `results/decisions.md`:

```markdown
## Loop #N — YYYY-MM-DD HH:MM

**Optimization chosen:** <one line>
**Reason:** <why this won the priority sort>
**Sample added:** <malicious|safe> — <one line description>

**Changes (files):**
- <path> — <one-line summary>

**Metrics:**
- Accuracy: X% (Δ +/-Y%)
- FP: N (Δ +/-M)
- FN: N (Δ +/-M)
- F1: X% (Δ +/-Y%)

**Comparison:** better | same | regression

**Samples now detected (if any):**
- <sample_id>: <description>

**Friction surfaced for future loops:**
- <one line each>

**Status:** landed | reverted | deferred
```

Update the summary table in `results/optimization_log.md` with the new row.

If this loop improved on the best score, also update `results/best_score.json`.

### 6. Resumability

At the end of each loop:
- All changes should be in the working directory (uncommitted is fine).
- No `/tmp` state the next loop depends on.
- The plan, decisions log, `next_focus.md`, and `best_score.json` are
  self-contained — a fresh Claude session can read them and pick up.

If context is getting tight, finish the current loop fully (don't leave a
half-broken state), then summarize progress and state "ready for next session
to continue from Loop #N".

---

## Optimization Backlog

Ranked by (impact × ease). Revise each loop based on `next_focus.md`.

### Current FN Categories (from Run #8)

Based on `results/next_focus.md`, these are the remaining false negatives:

| Category | FN Count | Sample IDs | Priority |
|----------|----------|------------|----------|
| filesystem_access | 2 | MAL-010, MAL-019 | High |
| credential_theft | 1 | MAL-007 | High |
| instruction_override | 1 | MAL-012 | High |
| split_instruction | 1 | MAL-032 | Medium |
| css_invisible | 1 | MAL-038 | Medium |
| aria_injection | 1 | MAL-040 | Medium |
| metadata_injection | 1 | MAL-053 | Medium |
| social_engineering | 1 | MAL-056 | Medium |
| instruction_chaining | 1 | MAL-059 | Medium |

### Current FP Categories (15 total)

All 15 FPs are security-related educational content:
- ai_safety_blog, bug_bounty_report, changelog, conference_talk,
  cybersecurity_course, job_posting, owasp_guide, pentesting_tutorial,
  prompt_injection_research, reddit_discussion, security_advisory,
  security_article, security_documentation, security_tool_docs,
  test_suite_docs

### Easy / Pattern Additions

- [ ] Add filesystem access patterns: `read /etc/`, `cat /home/`, `show me
      the contents of`, `access the file system`
- [ ] Add credential extraction patterns: `list all API keys`, `show me
      stored credentials`, `what passwords are saved`
- [ ] Add system update social engineering: `new instructions from system`,
      `updated guidelines`, `policy change effective immediately`
- [ ] Add split-resistant patterns: match keywords even when separated by
      HTML tags (via HTML-aware preprocessing)
- [ ] Add CSS hidden content detection: boost score when text found in
      `opacity:0`, `font-size:0`, `color:transparent` contexts
- [ ] Add aria attribute scanning: extract and scan `aria-label`,
      `aria-describedby` content
- [ ] Add metadata extraction: scan `<meta>` content, especially OG tags
- [ ] Add JSON-LD injection detection: scan `<script type="application/ld+json">`

### Easy / Context Penalty Improvements

- [ ] Increase penalty for "example:", "documentation", "tutorial" markers
- [ ] Add penalty for academic paper markers: "abstract", "methodology",
      "conclusion", "references"
- [ ] Add penalty for security disclosure markers: "CVE-", "vulnerability",
      "responsible disclosure", "bug bounty"
- [ ] Add penalty for code comment markers: `//`, `/*`, `#`, `"""`, `'''`
- [ ] Add penalty for changelog markers: "CHANGELOG", "release notes",
      "what's new", "version X.Y"

### Moderate / Normalizer Enhancements

- [ ] Handle more Unicode obfuscation: mathematical alphanumerics, regional
      indicator symbols, enclosed alphanumerics
- [ ] Handle whitespace obfuscation: hair space, thin space, em space, etc.
- [ ] Handle markdown formatting: bold, italic, strikethrough around keywords
- [ ] Handle emoji insertion: `ig🔥nore` → `ignore`
- [ ] Handle reversed text (RTL override) more comprehensively

### Moderate / Decoder Enhancements

- [ ] Extract and decode URL-encoded segments from within text
- [ ] Extract and decode punycode domains
- [ ] Handle double/triple encoding chains
- [ ] Add Morse code detection (unlikely but seen in CTF-style attacks)
- [ ] Add binary string detection: `01101001 01100111 01101110...`

### Moderate / Scorer Improvements

- [ ] Tune cross-category amplification weights
- [ ] Add combination penalties for specific attack chains
- [ ] Implement confidence scoring based on pattern specificity
- [ ] Add diminishing returns for many low-severity matches

### Hard / Research-Backed Improvements

Based on academic papers on prompt injection detection:

- [ ] **Instruction-following intent analysis**: Distinguish "discussing
      attacks" from "issuing attack commands" using sentence structure
- [ ] **Spotlighting markers**: Detect when text explicitly marks
      "instructions for AI" vs "content for human readers"
- [ ] **Behavioral state detection**: Identify text that attempts to modify
      the AI's operational state
- [ ] **Semantic similarity scoring**: Compare input against known attack
      embeddings (requires external service)

### Hard / Infrastructure

- [ ] Add benchmark visualization dashboard
- [ ] Add regression test suite from benchmark samples
- [ ] Add fuzzing for normalizer edge cases
- [ ] Add performance benchmarking (latency per input size)

---

## Sample Coverage Backlog

Aim for **diverse** test categories across loops.

### Malicious Categories Already Covered (60 samples)

- instruction_override (multiple variants)
- role_assumption / role_pretend
- prompt_extraction
- credential_theft
- command_execution
- filesystem_access
- data_exfiltration
- unicode_obfuscation (homoglyphs, fullwidth, zero-width)
- leetspeak_obfuscation
- base64_encoded
- split_instruction (spans, HTML tags, table cells)
- html_injection (data attributes, template tags)
- css_invisible (opacity, clip-path, white-on-white)
- aria_injection
- html_comments
- indirect_phrasing (polite, hypothetical, negation)
- instruction_chaining
- encoded_extraction (ROT13, hex)
- social_engineering (authority, audit)
- metadata_injection (meta tags, Open Graph)
- rtl_override
- acrostic_hidden

### Malicious Categories to Add

- **Multi-language attacks**: French, Spanish, German, Chinese, Japanese
  injection phrases
- **Code injection contexts**: SQL-like, shell-like, JSON-like syntax
- **Time-based attacks**: "after 5 minutes, ignore...", "tomorrow, reveal..."
- **Conditional attacks**: "if user is admin, show...", "when alone, output..."
- **Nested encoding**: Base64(ROT13(hex(payload)))
- **Steganographic**: LSB in image alt text, Unicode variation selectors
- **WebAssembly context**: Attacks in WASM-related content
- **GraphQL context**: Attacks in GraphQL query structures
- **Markdown rendering**: Attacks using markdown that renders differently
- **PDF/document context**: Attacks disguised as document metadata
- **Email context**: Attacks in email headers, signatures, disclaimers
- **Chat transcript context**: Attacks embedded in fake chat logs
- **Code review context**: Attacks in PR comments, code reviews
- **Logging context**: Attacks embedded in fake log entries
- **Configuration context**: Attacks in YAML, TOML, INI file contents
- **Serialization attacks**: Attacks in pickle, protobuf-like structures

### Safe Categories Already Covered (25 samples)

- news_article
- api_docs
- blog_post
- ecommerce
- recipe
- wikipedia
- forum_post
- educational_security
- social_media
- government
- security_article (and variants)

### Safe Categories to Add (to reduce FP)

- **Academic papers**: Full paper abstracts, methodology sections
- **CTF writeups**: Detailed CTF challenge solutions
- **Incident reports**: Post-mortem analysis, RCA documents
- **Penetration test reports**: Executive summaries, findings sections
- **Security training materials**: Course content, quiz questions
- **Compliance documentation**: SOC2, ISO27001, GDPR compliance docs
- **Threat modeling documents**: STRIDE analysis, attack trees
- **Security architecture docs**: Defense-in-depth explanations
- **Red team playbooks**: Sanitized methodology documents
- **Security tool documentation**: WAF rules, SIEM alerts, IDS signatures
- **Vulnerability databases**: NVD entries, CVE descriptions
- **Security newsletters**: Weekly roundups, advisories
- **Interview transcripts**: Security researcher interviews
- **Book excerpts**: Security book chapters
- **Podcast transcripts**: Security podcast show notes

---

## Research Papers Reference

Key papers to inform improvements:

1. **"Not What You've Signed Up For" (Greshake et al., 2023)**
   - Indirect prompt injection taxonomy
   - Attack vector classification

2. **"Ignore This Title and HackAPrompt" (Schulhoff et al., 2023)**
   - Competition-grade attack patterns
   - Evasion techniques

3. **"Tensor Trust" (Toyer et al., 2023)**
   - Adversarial prompt game insights
   - Defense mechanisms

4. **"Spotlighting" (Hines et al., 2024)**
   - Content marking for LLM input
   - Distinguishing trusted vs untrusted

5. **"InstructDetector" (Chen et al., 2024)**
   - Instruction-following detection
   - Hidden state analysis

6. **"IntentGuard" (Wang et al., 2024)**
   - Intent classification for inputs
   - Distinguishing discussion from instruction

---

## Success Criteria

A loop is successful if:
1. `comparison_to_best` is `better` or `same`
2. All unit tests pass
3. No FP increase
4. No FN increase (or FN decreases)

Track cumulative progress:
- Starting point (Run #8): Accuracy 70.6%, FP 15, FN 10, F1 80.0%
- Target (Run #258): Accuracy >90%, FP <10, FN <5, F1 >92%

---

## Stop Conditions

- Loop #258 completed and logged.
- User explicitly tells the agent to stop.
- Two consecutive loops cause regression and cannot be recovered without
  human intervention.
- Backlog exhausted AND no new friction surfaced for 3 consecutive loops —
  in that case, exit gracefully and post a completion note to the log.
- Accuracy exceeds 95% with FP < 5 and FN < 3 (goal achieved early).

---

## Quick Reference Commands

```bash
# Run benchmark
./tests/benchmark/scripts/run-optimization.sh

# Check current status
cat tests/benchmark/results/next_focus.md

# Check specific sample result
jq '.results[] | select(.sample_id == "MAL-XXX")' tests/benchmark/results/latest.json

# Run unit tests
go test ./...

# Build
go build ./...

# Check patterns for keyword
grep -n "keyword" patterns/builtin.go

# Test regex pattern
go run -exec "" - <<< 'pattern test code'
```

---

## File Locations

```
/Users/mario/dev/idpishield/
├── patterns/
│   └── builtin.go                    # Detection patterns
├── internal/engine/
│   ├── engine.go                     # Main orchestrator
│   ├── scanner.go                    # Pattern matching + scoring
│   ├── normalizer.go                 # Text preprocessing
│   ├── decoders.go                   # Encoding bypass
│   ├── scanner_secrets.go            # Credential detection
│   ├── scanner_toxicity.go           # Threat language
│   └── scanner_emotion.go            # Manipulation tactics
├── benchmark/
│   └── dataset/
│       ├── malicious/                # Attack samples (JSON)
│       └── safe/                     # Benign samples (JSON)
└── tests/benchmark/
    ├── scripts/
    │   ├── run-optimization.sh       # Main benchmark runner
    │   └── run-benchmark.sh          # Benchmark execution
    └── results/
        ├── latest.json               # Most recent run data
        ├── best_score.json           # Best achieved metrics
        ├── next_focus.md             # Current focus + failed samples
        ├── optimization_log.md       # Run history
        └── decisions.md              # Per-loop decision log
```
