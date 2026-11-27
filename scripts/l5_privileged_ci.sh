#!/usr/bin/env bash
# Privileged L5 verification (run as root): root-dependent tests with skips
# treated as failures, the mutation gate, commit/recovery crash sweeps and the
# commit-oracle sensitivity proof (deliberate faults must all be detected).
# Usage: sudo bash scripts/l5_privileged_ci.sh <repo> <python> [logdir]
set -euo pipefail
REPO="$1"; PY="$2"; LOGS="${3:-/tmp/aios-l5-privileged-logs}"
[ "$(id -u)" = 0 ] || { echo "FAIL: must run as root"; exit 2; }
command -v setpriv >/dev/null || { echo "FAIL: setpriv missing"; exit 2; }
mkdir -p "$LOGS"
# Work on a root-owned copy that other uids can read (search-only ancestors),
# so the service-uid (1000) and attacker-uid (65534) tests can import it.
WORK=/var/tmp/aios-l5-ci; rm -rf "$WORK"; mkdir -m 755 "$WORK"
cp -a "$REPO"/. "$WORK"/; rm -rf "$WORK/.git"; chown -R root:root "$WORK"; chmod -R go-w,a+rX "$WORK"
cd "$WORK"
export AIOS_L5_REQUIRE_PRIVILEGED=1 PYTHONDONTWRITEBYTECODE=1
{
  echo "date: $(date -u +%FT%TZ)"; echo "python: $("$PY" --version 2>&1) ($PY)"; echo "id: $(id)"
  echo "kernel: $(uname -sr)"; echo "fs(/var/tmp): $(stat -f -c %T /var/tmp)"; echo "setpriv: $(command -v setpriv)"
  echo "git_sha: ${GITHUB_SHA:-unknown}"
} | tee "$LOGS/environment.txt"
L5_TESTS="tests/test_l5_p0_remediation.py tests/test_l5_review_fixes.py tests/test_f02_f14_regressions.py \
tests/test_f02_payload_integrity.py tests/test_f02_r3_journal_confinement.py tests/test_f02_replay_confinement.py \
tests/test_l5_journal_hardening.py tests/test_l5_event_ledger.py tests/test_stack_audit_remediation.py \
tests/test_m15.py tests/test_pr180_remediation.py tests/test_m2.py tests/test_l5_commit_sweep_oracle.py"
set +e
"$PY" -m pytest -q -rs -p no:cacheprovider --junitxml="$LOGS/l5-root-junit.xml" $L5_TESTS 2>&1 | tee "$LOGS/l5-root-pytest.log"
rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 0 ] || { echo "FAIL: root L5 tests rc=$rc"; exit 1; }
if grep -E "^SKIPPED|[0-9]+ skipped" "$LOGS/l5-root-pytest.log"; then
  echo "FAIL: skipped tests in the privileged job (prerequisites must be present)"; exit 1
fi
"$PY" scripts/l5_mutation_gate.py --json "$LOGS/mutation-gate.json" 2>&1 | tee "$LOGS/mutation-gate.log"
grep -E "^M1[345] +KILLED" "$LOGS/mutation-gate.log" | wc -l | grep -qx 3 || { echo "FAIL: M13/M14/M15 not all KILLED"; exit 1; }
"$PY" -I scripts/l5_recovery_crash_sweep.py --repo "$WORK" --target recover --modes eio,exc,exit,sigkill --json "$LOGS/sweep-recover.json" \
  2>&1 | tee "$LOGS/sweep-recover.log" | tail -3
"$PY" -I scripts/l5_recovery_crash_sweep.py --repo "$WORK" --target commit --modes eio,exc,exit,sigkill --json "$LOGS/sweep-commit.json" \
  2>&1 | tee "$LOGS/sweep-commit.log" | tail -3
"$PY" -I scripts/l5_commit_oracle_sensitivity.py --repo "$WORK" --json "$LOGS/oracle-sensitivity.json" \
  --logs "$LOGS/oracle-sensitivity" 2>&1 | tee "$LOGS/oracle-sensitivity.log" | tail -3
echo "PASS: privileged L5 verification complete"
