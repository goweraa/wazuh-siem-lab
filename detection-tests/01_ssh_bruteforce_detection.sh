#!/bin/bash
#
# Detection test 01: SSH brute-force -> possible compromise
# ---------------------------------------------------------
# This is a DEFENSIVE detection test. It generates ordinary authentication
# events against the lab's own monitored-server container so we can confirm
# the SIEM detects and alerts on them. Nothing here targets any system other
# than the local lab container this project starts.
#
# What it does:
#   1. Makes several SSH login attempts with a deliberately WRONG password
#      (this produces the auth-failure log lines a brute-force generates).
#   2. Makes one login with the CORRECT password (a successful auth event).
#
# Expected result in the SIEM (https://localhost:8443):
#   - Wazuh rule 5710  : individual authentication failures
#   - Wazuh rule 5712/5763 : brute-force correlation
#   - Custom rule 100100   : SIEM-LAB brute-force pattern (level 10)
#   - Custom rule 100101   : SIEM-LAB successful login after brute force (level 12)
#
set -u

HOST=127.0.0.1
PORT=2222
USER=analyst
WRONG_PW="wrong-password"
RIGHT_PW='Lab-Analyst-2026!'
ATTEMPTS="${1:-8}"

SSH_OPTS="-p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o PreferredAuthentications=password -o PubkeyAuthentication=no \
          -o ConnectTimeout=5 -o LogLevel=ERROR"

echo "[*] Detection test: SSH brute-force -> compromise, against lab host ${HOST}:${PORT}"
echo "[*] Step 1: ${ATTEMPTS} failed logins (wrong password) as '${USER}'"

for i in $(seq 1 "${ATTEMPTS}"); do
    sshpass -p "${WRONG_PW}" ssh ${SSH_OPTS} "${USER}@${HOST}" "true" >/dev/null 2>&1
    echo "    attempt ${i}: failed login sent (rc=$?)"
    sleep 1
done

echo "[*] Step 2: one SUCCESSFUL login (correct password) from the same source"
sshpass -p "${RIGHT_PW}" ssh ${SSH_OPTS} "${USER}@${HOST}" "echo lab-login-ok; id" 2>&1 \
    | sed 's/^/    /'

echo
echo "[*] Done. Open the Wazuh dashboard at https://localhost:8443 (admin / SecretPassword)"
echo "    -> Threat Hunting / Security events. Look for rule IDs 5710, 5712,"
echo "       100100 and 100101 in the last few minutes."
