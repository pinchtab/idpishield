# IDPI Shield Benchmark Harness

Scripted benchmark entrypoints for `idpishield`, modeled after the layout used in
`semantic/tests/benchmark`.

This harness wraps the existing Go benchmark runner in `/benchmark` rather than
replacing it. The benchmark dataset and implementation remain in:

- `/benchmark/dataset`
- `/benchmark/cmd/main.go`
- `/benchmark/*.go`

The purpose of this directory is to provide:

- a stable place for benchmark scripts
- committed benchmark configuration
- a predictable results directory

## Quick Start

```bash
cd tests/benchmark

# Run benchmark with default config
./scripts/run-benchmark.sh

# Run optimization loop
./scripts/run-optimization.sh

# Run benchmark with custom dataset/output paths
./scripts/run-benchmark.sh --dataset ../../benchmark/dataset --output ./results
```

## Layout

```text
tests/benchmark/
├── README.md
├── OPTIMIZATION_LOOP.md
├── config/
│   └── benchmark.json
├── results/
│   ├── .gitkeep
│   └── .gitignore
└── scripts/
    ├── run-benchmark.sh
    └── run-optimization.sh
```

## Output

Results are written to `tests/benchmark/results/` by default. The underlying Go
runner also keeps a stable `latest.json` file in the selected output directory.

## Notes

- This harness intentionally reuses the root `/benchmark` package and dataset.
- It does not duplicate benchmark logic.
- `./dev benchmark` runs this script.
- `./dev benchmark optimize` runs the optimization loop.

## Optimization Loop

Use this when you want another agent to improve `idpishield` against the benchmark
in a controlled loop:

1. Run `./scripts/run-optimization.sh`
2. Read:
   - `results/latest.json`
   - `results/next_focus.md`
   - `results/best_score.json` (if created)
   - `OPTIMIZATION_LOOP.md`
3. Make exactly one focused improvement
4. Re-run `./scripts/run-optimization.sh`
5. Keep the change only if protected metrics do not regress

When the loop plateaus for several iterations, shift from code tuning to
benchmark growth by adding new cases for under-covered scenarios before
continuing optimization.
