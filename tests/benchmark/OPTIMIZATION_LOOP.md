# IDPI Shield Benchmark Optimization Loop

Agent-driven improvement loop for `idpishield` using the deterministic benchmark
as the objective function.

## Goal

Use benchmark results to improve the detector without gaming the dataset or
causing false-positive regressions.

## Core Principle

One benchmark run should produce one focused improvement proposal.

Priority order:

1. Do not increase false positives on safe samples
2. Reduce false negatives on malicious samples
3. Improve F1 / accuracy
4. Avoid material latency regressions

## Files

| File | Purpose |
|---|---|
| `scripts/run-benchmark.sh` | Runs the benchmark runner |
| `scripts/run-optimization.sh` | Runs benchmark + compares against best + writes focus notes |
| `results/best_score.json` | High-water mark from the best known run (generated) |
| `results/next_focus.md` | Current run summary and suggested next focus (generated) |
| `results/optimization_log.md` | Run history (generated/appended) |

## Loop

1. Run benchmark
   - `./scripts/run-optimization.sh`
2. Read generated artifacts
   - `results/latest.json`
   - `results/next_focus.md`
   - `results/best_score.json`
3. Identify one root cause
   - weak scanner rule
   - over-broad rule causing FPs
   - preprocessing gap
   - threshold/config mismatch
   - dataset gap
4. Make exactly one change
5. Re-run `./scripts/run-optimization.sh`
6. Keep only changes that improve or hold protected metrics

## Plateau Policy

If the loop hits a local minimum or plateaus for several iterations:

1. Stop tuning the same detector path repeatedly
2. Expand the benchmark with new realistic cases for uncovered scenarios
3. Resume optimization against the expanded benchmark

This keeps the loop from overfitting to the current dataset.

## Regression Policy

A run is a regression if any of these happen relative to `best_score.json`:

- `false_positives` increases
- `false_negatives` increases
- `f1_score` drops meaningfully while FP/FN are unchanged

## Suggested Improvement Types

1. Scanner rule refinement
2. Preprocessing normalization/deobfuscation improvement
3. Safer threshold or heuristic tuning
4. Benchmark expansion when the loop plateaus or coverage gaps are clearer than code gaps

## What Not To Do

- Don’t optimize for raw accuracy alone
- Don’t add broad rules that catch more attacks by spiking safe false positives
- Don’t make multiple unrelated changes in one iteration
- Don’t rewrite benchmark outputs manually
