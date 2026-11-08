#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 secure_audit.py samples --out demo_output --no-llm
printf '\nOpen demo_output/report.md to view the report.\n'
