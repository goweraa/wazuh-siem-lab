# Security Incident Report — SSH Brute-Force with Possible Account Compromise

**Analyst:** Gower Aimable
**Environment:** Wazuh SIEM detection lab (single-node, Wazuh 4.14.8)
**Detection source:** Custom rule 100101 (level 12) on wazuh.manager
**Classification:** True positive (lab-generated) · Severity **High**
**Status:** Contained (lab)

---

## 1. Summary

The SIEM raised a **level 12** alert (custom rule `100101`) indicating a
**successful SSH login from a source IP that had, seconds earlier, produced a
burst of failed logins** against the same account on host `monitored-server`.
This pattern — many failures followed by a success from one source — is the
classic signature of a **brute-force attack that succeeded**, meaning the
`analyst` account should be treated as **potentially compromised**.

The activity was traced through the full log timeline, the source and account
were identified, and containment/remediation steps are recommended below.

---

## 2. Detection

| Field | Value |
|-------|-------|
| Alert rule | 100101 — "Successful SSH login after brute-force from same IP" |
| Rule level | 12 (High) |
| MITRE ATT&CK | T1110 (Brute Force), T1078 (Valid Accounts) |
| Host | monitored-server (Wazuh agent 001) |
| Target account | `analyst` |
| Source IP | e.g. 198.51.100.23 |
| Service | OpenSSH (sshd), password authentication |

The detection is a two-stage correlation built on the native Wazuh SSH
decoders:

1. **100100** (level 10) fires when **≥6 failed logins (rule 5760)** arrive
   from the **same source IP** within 120 seconds → brute-force in progress.
2. **100101** (level 12) fires when a **successful login (rule 5715)** then
   arrives from **that same IP** within 300 seconds → brute force likely
   succeeded.

---

## 3. Timeline (reconstructed from /var/log/auth.log)

```
21:37:05  Failed password for analyst from 198.51.100.23 port 40001 ssh2
21:37:06  Failed password for analyst from 198.51.100.23 port 40002 ssh2
21:37:07  Failed password for analyst from 198.51.100.23 port 40003 ssh2
21:37:08  Failed password for analyst from 198.51.100.23 port 40004 ssh2
21:37:09  Failed password for analyst from 198.51.100.23 port 40005 ssh2
21:37:10  Failed password for analyst from 198.51.100.23 port 40006 ssh2
21:37:11  Failed password for analyst from 198.51.100.23 port 40007 ssh2   <- rule 100100 fires (6th+ failure)
21:37:13  Accepted password for analyst from 198.51.100.23 port 40099 ssh2 <- rule 100101 fires (success after brute force)
```

**Interpretation:** 7 password failures in ~6 seconds followed by a success
from the same IP. The tight cadence (roughly one attempt per second) and the
single source are inconsistent with a user mistyping a password; they indicate
an automated brute-force tool that ultimately guessed valid credentials.

---

## 4. Investigation steps

1. **Triaged the alert** in the dashboard (Threat Hunting → `rule.id:100101`)
   and confirmed severity, host and source IP.
2. **Validated it is not a false positive:** a genuine user does not generate
   6+ failures in seconds from one IP and then succeed. Cadence + volume +
   single source = automated brute force, not fat-fingering.
3. **Pivoted on the source IP** (`data.srcip:198.51.100.23`) to pull every
   related event and build the timeline above.
4. **Identified the affected account** (`analyst`) and the service (sshd,
   password auth).
5. **Checked for the success** — the presence of `Accepted password` from the
   attacking IP is the decisive indicator that credentials were guessed.

---

## 5. Impact

- The `analyst` account on `monitored-server` was successfully accessed from
  an untrusted source after a brute-force attack.
- Password authentication for SSH is exposed and was guessable.
- Any access, persistence or lateral movement after the successful login would
  need to be investigated in a real environment (session activity, sudo use,
  new keys, new users, outbound connections).

---

## 6. Containment & remediation (recommended)

**Immediate (contain):**
- Disable / lock the `analyst` account and terminate its active sessions.
- Block the source IP at the host/perimeter firewall.

**Short term (eradicate & recover):**
- Force a password reset for `analyst`; review other accounts for reuse.
- Review `analyst`'s activity after the successful login for anything
  malicious (sudo, new SSH keys, new accounts, cron, outbound connections).

**Preventive (harden):**
- Disable SSH password authentication; require **key-based auth + MFA**.
- Deny root login (already set: `PermitRootLogin no`).
- Add rate-limiting / lockout (e.g. `fail2ban` or firewall throttling on 22).
- Restrict SSH exposure to trusted networks / a bastion.
- Keep the SIEM detection (100100/100101) and alert the SOC on level ≥12.

---

## 7. Detection engineering notes

- Custom rules chain off the SIDs this Wazuh build actually emits — **5760**
  (failure) and **5715** (success) — verified with `wazuh-logtest` rather than
  assumed. An earlier draft chained off 5710 and never fired; testing caught it.
- `RepeatedMsgReduction` was disabled in rsyslog on the endpoint so repeated
  attempts are not collapsed before the SIEM sees them — collapsing would
  under-count a brute force and could suppress the detection.
- Thresholds (frequency 6 / timeframe 120s) are tuned low for the lab; in
  production they would be set from a baseline of normal failed-login volume
  to balance detection against alert fatigue.
