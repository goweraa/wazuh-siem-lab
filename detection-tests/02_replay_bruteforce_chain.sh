#!/bin/bash
#
# Detection test 02: deterministic replay of a brute-force -> compromise chain
# ---------------------------------------------------------------------------
# This is a DEFENSIVE detection test. It writes a known sequence of sshd
# auth-log lines (several failures then one success, all from one source IP)
# directly into the monitored-server's /var/log/auth.log, using the
# container's own clock. This is a standard SOC technique: replay known log
# samples to validate that detection rules fire as designed, independent of
# live-service logging quirks.
#
# Nothing here touches any system other than the lab's own container.
#
# Expected result in the SIEM (https://localhost:8443):
#   - rule 5760    : individual SSH auth failures
#   - rule 5763    : Wazuh brute-force correlation
#   - rule 100100  : SIEM-LAB brute-force pattern (level 10)
#   - rule 100101  : SIEM-LAB successful login after brute force (level 12)
#
set -u

AGENT_CTR="wazuh-siem-lab_monitored-server_1"
MANAGER_CTR="wazuh-siem-lab_wazuh.manager_1"
SRC_IP="${1:-192.0.2.66}"     # TEST-NET-3 documentation range (RFC 5737)
FAILURES="${2:-7}"

echo "[*] Replaying brute-force -> compromise from ${SRC_IP} into the lab agent's auth.log"

podman exec "${AGENT_CTR}" sh -c '
  IP="'"${SRC_IP}"'"
  for i in $(seq 1 '"${FAILURES}"'); do
    echo "$(date "+%b %e %H:%M:%S") monitored-server sshd[$((8000+i))]: Failed password for analyst from $IP port $((40000+i)) ssh2" >> /var/log/auth.log
    sleep 1
  done
  sleep 2
  echo "$(date "+%b %e %H:%M:%S") monitored-server sshd[8099]: Accepted password for analyst from $IP port 40099 ssh2" >> /var/log/auth.log
'
echo "[*] Replay written (${FAILURES} failures + 1 success). Waiting for the SIEM to correlate..."

for _ in $(seq 1 12); do
  if podman exec "${MANAGER_CTR}" sh -c "grep -q '${SRC_IP}' /var/ossec/logs/alerts/alerts.log && grep -q '100101' /var/ossec/logs/alerts/alerts.log" 2>/dev/null; then
    break
  fi
  sleep 5
done

echo
echo "[*] Alert counts for this source IP:"
podman exec "${MANAGER_CTR}" sh -c '
  for r in 5760 5763 5715 100100 100101; do
    printf "    rule %-7s : %s\n" "$r" "$(grep -c "^Rule: $r " /var/ossec/logs/alerts/alerts.log)"
  done'
echo
echo "[*] Custom-rule alert detail:"
podman exec "${MANAGER_CTR}" sh -c "grep -A5 -E 'Rule: 10010[01] ' /var/ossec/logs/alerts/alerts.log | grep -A5 '${SRC_IP}' | tail -14"
echo
echo "[*] Open the dashboard at https://localhost:8443 (admin / SecretPassword)"
echo "    -> Threat Hunting -> filter rule.id:100101 to see the compromise alert."
