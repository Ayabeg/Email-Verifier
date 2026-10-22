#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

if [[ -x .venv/bin/email-verifier ]]; then
  verifier=(.venv/bin/email-verifier)
else
  verifier=(python3 -m email_verifier)
fi

echo "== Single-address smoke test (DNS disabled) =="
"${verifier[@]}" verify "person@example.com" --no-dns --pretty

echo
echo "== Bulk smoke test (DNS disabled, JSONL) =="
"${verifier[@]}" bulk examples/sample.csv \
  --input-format csv \
  --no-dns \
  --rate-limit 0 \
  --concurrency 2 \
  --stdout \
  --output-format jsonl
