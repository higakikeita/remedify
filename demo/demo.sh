#!/usr/bin/env bash
# 90-second remedify demo — fully offline & reproducible (uses committed
# example scans, no real trivy/network needed). Record with:
#
#   asciinema rec -c "demo/demo.sh" remedify-demo.cast
#   # then: agg remedify-demo.cast remedify-demo.gif   (asciinema/agg)
#
# The story: a scanner found the CVEs → remedify turns them into a plan →
# you apply it → re-scan → remedify PROVES what actually got fixed.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

R="python3 remedify.py"
p() { printf '\n\033[1;32m$ %s\033[0m\n' "$*"; sleep 1.2; }
pause() { sleep "${1:-2}"; }

clear
printf '\033[1m# Your scanner found the CVEs. Now what do you actually run?\033[0m\n'
pause 2

p "trivy image --format json -o scan.json myapp:1.0   # (pre-recorded)"
printf '   8 vulnerabilities across 8 OS packages\n'
pause 2

p "remedify scan.json"
$R demo/before.json 2>/dev/null | sed -n '1,24p'
pause 4

printf '\n\033[1m# One command per source package — backports & reboots called out.\033[0m\n'
pause 2

p "remedify scan.json --format shell > fix.sh   &&   sudo bash fix.sh"
printf '   ...applied. rebuild / redeploy ... then re-scan → after.json\n'
pause 2

printf '\n\033[1m# Upgraded, re-scanned — but did it actually work?\033[0m\n'
pause 2

p "remedify --baseline scan.json after.json"
$R --baseline demo/before.json demo/after.json 2>/dev/null | sed -n '1,20p'
pause 4

printf '\n\033[1m# Deterministic proof: what is fixed, what is still short, what is new.\033[0m\n'
printf '\033[1m# pip install remedify  ·  github.com/higakikeita/remedify\033[0m\n'
pause 3
