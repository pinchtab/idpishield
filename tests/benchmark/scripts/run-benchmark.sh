#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="${SCRIPT_DIR}/.."
ROOT_DIR="$(cd "${BENCHMARK_DIR}/../.." && pwd)"
CONFIG_FILE="${BENCHMARK_DIR}/config/benchmark.json"
GOCACHE_DIR="${ROOT_DIR}/.gocache"

DATASET_DIR="$(jq -r '.dataset' "${CONFIG_FILE}")"
OUTPUT_DIR="$(jq -r '.output' "${CONFIG_FILE}")"
STRICT="$(jq -r '.strict' "${CONFIG_FILE}")"
JSON_ONLY="$(jq -r '.json_only' "${CONFIG_FILE}")"

resolve_path() {
  local raw="$1"
  if [[ "$raw" = /* ]]; then
    printf "%s\n" "$raw"
  else
    (cd "${BENCHMARK_DIR}" && python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$raw")
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dataset) DATASET_DIR="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --strict) STRICT="$2"; shift 2 ;;
    --json) JSON_ONLY="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

DATASET_DIR="$(resolve_path "${DATASET_DIR}")"
OUTPUT_DIR="$(resolve_path "${OUTPUT_DIR}")"

mkdir -p "${BENCHMARK_DIR}/results"
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${GOCACHE_DIR}"

cd "${ROOT_DIR}"

echo ""
echo "  Running idpishield benchmark"
echo "  Dataset: ${DATASET_DIR}"
echo "  Output : ${OUTPUT_DIR}"
echo "  Strict : ${STRICT}"
echo ""

ARGS=(
  run ./benchmark/cmd/main.go
  -dataset "${DATASET_DIR}"
  -output "${OUTPUT_DIR}"
  -strict="${STRICT}"
)

if [[ "${JSON_ONLY}" == "true" ]]; then
  ARGS+=(-json)
fi

GOCACHE="${GOCACHE_DIR}" go "${ARGS[@]}"
