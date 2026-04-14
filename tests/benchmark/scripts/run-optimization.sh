#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="${SCRIPT_DIR}/.."
RESULTS_DIR="${BENCHMARK_DIR}/results"
RUN_BENCHMARK="${SCRIPT_DIR}/run-benchmark.sh"

BEST_FILE="${RESULTS_DIR}/best_score.json"
LATEST_FILE="${RESULTS_DIR}/latest.json"
NEXT_FOCUS_FILE="${RESULTS_DIR}/next_focus.md"
LOG_FILE="${RESULTS_DIR}/optimization_log.md"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd jq
require_cmd python3

mkdir -p "${RESULTS_DIR}"

set +e
bash "${RUN_BENCHMARK}" --json true "$@"
run_status=$?
set -e

if [[ ! -f "${LATEST_FILE}" ]]; then
  echo "Benchmark did not produce ${LATEST_FILE} (exit code ${run_status})" >&2
  exit 1
fi

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

current_json="$(jq -c '{
  timestamp: .timestamp,
  accuracy: .metrics.accuracy,
  precision: .metrics.precision,
  recall: .metrics.recall,
  f1_score: .metrics.f1_score,
  false_positives: .metrics.false_positives,
  false_negatives: .metrics.false_negatives,
  total_samples: .metrics.total_samples,
  summary: {
    true_positives: .metrics.true_positives,
    true_negatives: .metrics.true_negatives
  }
}' "${LATEST_FILE}")"

current_accuracy="$(jq -r '.accuracy' <<<"${current_json}")"
current_precision="$(jq -r '.precision' <<<"${current_json}")"
current_recall="$(jq -r '.recall' <<<"${current_json}")"
current_f1="$(jq -r '.f1_score' <<<"${current_json}")"
current_fp="$(jq -r '.false_positives' <<<"${current_json}")"
current_fn="$(jq -r '.false_negatives' <<<"${current_json}")"
previous_same_count=0

if [[ -f "${LOG_FILE}" ]]; then
  previous_same_count="$(python3 - "${LOG_FILE}" <<'PY'
import sys

path = sys.argv[1]
blocks = []
current = []
with open(path, encoding="utf-8") as f:
    for line in f:
        if line.startswith("## Run — "):
            if current:
                blocks.append(current)
            current = [line.rstrip("\n")]
        elif current:
            current.append(line.rstrip("\n"))
if current:
    blocks.append(current)

count = 0
for block in reversed(blocks):
    comparison = None
    for line in block:
        if line.startswith("- Comparison to best: "):
            comparison = line.split(": ", 1)[1].strip()
            break
    if comparison == "same":
        count += 1
    else:
        break
print(count)
PY
)"
fi

if [[ ! -f "${BEST_FILE}" ]]; then
  printf '%s\n' "${current_json}" > "${BEST_FILE}"
  comparison="baseline"
  comparison_reason="Initialized best_score.json from the current benchmark run."
else
  comparison="$(python3 - "${BEST_FILE}" "${LATEST_FILE}" <<'PY'
import json, sys

best_path, latest_path = sys.argv[1], sys.argv[2]
with open(best_path) as f:
    best = json.load(f)
with open(latest_path) as f:
    latest = json.load(f)

b_fp = int(best["false_positives"])
b_fn = int(best["false_negatives"])
b_f1 = float(best["f1_score"])
c_fp = int(latest["metrics"]["false_positives"])
c_fn = int(latest["metrics"]["false_negatives"])
c_f1 = float(latest["metrics"]["f1_score"])

if c_fp > b_fp or c_fn > b_fn:
    print("regression")
elif c_fp < b_fp or c_fn < b_fn or c_f1 > b_f1 + 1e-9:
    print("better")
else:
    print("same")
PY
)"

  case "${comparison}" in
    better)
      printf '%s\n' "${current_json}" > "${BEST_FILE}"
      comparison_reason="Updated best_score.json because protected metrics improved or held while F1 improved."
      ;;
    same)
      comparison_reason="Current run matches the protected-metric envelope of best_score.json."
      ;;
    regression)
      comparison_reason="Current run regressed on false positives or false negatives relative to best_score.json."
      ;;
    *)
      echo "Unexpected comparison result: ${comparison}" >&2
      exit 1
      ;;
  esac
fi

plateau_count=0
if [[ "${comparison}" == "same" ]]; then
  plateau_count=$((previous_same_count + 1))
fi

top_categories="$(jq -r '
  .by_category
  | to_entries
  | map({
      category: .key,
      false_positives: .value.false_positives,
      false_negatives: .value.false_negatives,
      total_errors: (.value.false_positives + .value.false_negatives)
    })
  | sort_by(-.total_errors, .category)
  | .[:5]
  | .[]
  | "- \(.category): FP=\(.false_positives), FN=\(.false_negatives), total=\(.total_errors)"
' "${LATEST_FILE}")"

failed_samples="$(jq -r '
  .results
  | map(select(.classification == "FP" or .classification == "FN"))
  | .[:10]
  | .[]
  | "- \(.sample_id) [\(.classification)] \(.category): \(.description)"
' "${LATEST_FILE}")"

{
  printf '# Benchmark Next Focus\n\n'
  printf 'Generated: %s\n\n' "${timestamp}"
  printf '## Current Metrics\n\n'
  printf -- '- Accuracy: %s\n' "${current_accuracy}"
  printf -- '- Precision: %s\n' "${current_precision}"
  printf -- '- Recall: %s\n' "${current_recall}"
  printf -- '- F1: %s\n' "${current_f1}"
  printf -- '- False Positives: %s\n' "${current_fp}"
  printf -- '- False Negatives: %s\n' "${current_fn}"
  printf -- '- Comparison to best: %s\n\n' "${comparison}"
  if [[ ${plateau_count} -gt 0 ]]; then
    printf -- '- Plateau count: %s\n\n' "${plateau_count}"
  fi
  printf '%s\n\n' "${comparison_reason}"
  printf '## Top Error Categories\n\n'
  printf '%s\n\n' "${top_categories:-- none}"
  printf '## Failed Samples To Inspect First\n\n'
  printf '%s\n\n' "${failed_samples:-- none}"
  printf '## Suggested Next Step\n\n'
  if [[ ${plateau_count} -ge 3 ]]; then
    printf '%s\n' 'The loop appears to be plateauing. Prefer expanding the benchmark with new'
    printf '%s\n' 'realistic cases for under-covered scenarios, then resume code optimization'
    printf '%s\n' 'against the expanded benchmark.'
  else
    printf '%s\n' 'Make exactly one focused change that reduces false negatives or false positives'
    printf '%s\n' 'without regressing the other protected metric. Re-run this script after the'
    printf '%s\n' 'change and keep the patch only if the comparison status is not `regression`.'
  fi
} > "${NEXT_FOCUS_FILE}"

{
  printf '\n## Run — %s\n\n' "${timestamp}"
  printf -- '- Accuracy: %s\n' "${current_accuracy}"
  printf -- '- Precision: %s\n' "${current_precision}"
  printf -- '- Recall: %s\n' "${current_recall}"
  printf -- '- F1: %s\n' "${current_f1}"
  printf -- '- False Positives: %s\n' "${current_fp}"
  printf -- '- False Negatives: %s\n' "${current_fn}"
  printf -- '- Comparison to best: %s\n' "${comparison}"
  if [[ ${plateau_count} -gt 0 ]]; then
    printf -- '- Plateau count: %s\n' "${plateau_count}"
  fi
  printf -- '- Note: %s\n' "${comparison_reason}"
} >> "${LOG_FILE}"

echo ""
echo "Optimization loop artifacts updated:"
echo "  - ${LATEST_FILE}"
echo "  - ${BEST_FILE}"
echo "  - ${NEXT_FOCUS_FILE}"
echo "  - ${LOG_FILE}"
echo ""
echo "Comparison to best: ${comparison}"

exit 0
