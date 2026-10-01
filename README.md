# Wazuh SIEM Detection Lab — SSH Brute-Force → Compromise

A self-contained, reproducible **defensive-security lab**: a working SIEM
(Wazuh 4.14.8) monitoring a Linux server, with **custom detection rules**
that catch an SSH brute-force attack and — critically — flag when that
brute force is followed by a **successful login from the same source**
(a possible account compromise).

Built to practise the core SOC-analyst workflow end to end: generate
security events → collect and normalise logs → detect with tuned rules →
investigate and write up the incident.

---

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │              Wazuh SIEM                   │
  ┌───────────────┐      │  ┌──────────┐  ┌──────────┐  ┌────────┐  │
  │  monitored-   │ 1514 │  │  manager │→ │ indexer  │→ │dashboard│ │
  │  server       │─────►│  │(rules/   │  │(OpenSearch)│ │  (web) │  │
  │               │ agent│  │ analysisd)│  └──────────┘  └────────┘  │
  │ sshd + rsyslog│      │  └──────────┘                             │
  │ + Wazuh agent │      └─────────────────────────────────────────┘
  └───────────────┘
        ▲
        │ SSH auth attempts (detection tests)
```

- **wazuh.manager** — decodes agent events, runs the ruleset, raises alerts.
- **wazuh.indexer** — OpenSearch store for events and alerts.
- **wazuh.dashboard** — web UI for threat hunting / investigation.
- **monitored-server** — Ubuntu host running OpenSSH, rsyslog and the Wazuh
  agent. This is the endpoint a SOC analyst watches.

---

## What it detects

The base Wazuh ruleset already decodes each failed SSH login (rule **5760**),
each successful login (rule **5715**) and correlates repeated failures into a
brute-force alert (rule **5763**). This lab adds two higher-value custom rules
(`custom-rules/local_rules.xml`):

| Rule  | Level | Fires when… | MITRE ATT&CK |
|-------|-------|-------------|--------------|
| 100100 | 10 | ≥6 SSH auth failures from the **same source IP** within 120s | T1110 Brute Force |
| 100101 | 12 | a **successful** SSH login from a source IP that just triggered 100100 | T1110 + T1078 Valid Accounts |

Rule **100101** is the one that matters most to an analyst: it is the signal
that a brute-force attack **may have succeeded** and an account may be
compromised.

---

## Requirements

- Podman (rootless) + podman-compose, or Docker + docker compose
- ~4 GB free RAM, ~10 GB disk
- `vm.max_map_count >= 262144` (required by the indexer)
- `sshpass` (only for the live-traffic test 01)

---

## Run it

```bash
# 1. Generate the indexer/manager/dashboard TLS certificates (one time)
cd siem && podman-compose -f generate-indexer-certs.yml up && cd ..

# 2. Start the whole stack (first run pulls images + builds the agent image)
podman-compose up -d --build

# 3. Wait until the monitored-server agent shows "Active"
podman exec wazuh-siem-lab_wazuh.manager_1 /var/ossec/bin/agent_control -l

# 4. Open the dashboard
#    https://localhost:8443   (admin / SecretPassword)
```

> Ports are remapped for rootless Podman: dashboard on **8443** (not 443)
> and syslog on **5514** (not 514).
>
> All credentials in this repo are Wazuh's published lab defaults. Change
> them before exposing the stack beyond localhost.

---

## Run the detection tests

```bash
# Live traffic: real SSH login attempts via sshpass (proves the live
# agent -> manager -> rule pipeline; reliably fires 5760 + 100100).
bash detection-tests/01_ssh_bruteforce_detection.sh

# Deterministic replay: writes a known failure->success sequence from one
# source IP (reliably fires the full chain 5760 -> 100100 -> 5715 -> 100101).
bash detection-tests/02_replay_bruteforce_chain.sh
```

Then investigate in the dashboard: **Threat Hunting** → filter
`rule.id:100101` to see the compromise alert, pivot on the source IP, and
review the failure timeline that preceded it.

A worked investigation is written up in
[`report/incident-report.md`](report/incident-report.md).

---

## Notes / gotchas handled

- **Rootless privileged ports** — dashboard/syslog remapped to 8443/5514.
- **File-descriptor ulimit** — manager `nofile` set to the rootless hard cap.
- **rsyslog in a container** — log files and spool dir are chowned to the
  `syslog` user (rsyslog drops privileges), `imklog` is disabled (no
  `/proc/kmsg`), and `RepeatedMsgReduction` is turned **off** so the SIEM
  sees every attempt rather than a collapsed "repeated N times".
- **Correct parent rule IDs** — the custom rules chain off the SIDs this
  Wazuh version actually emits (5760 failure / 5715 success), verified with
  `wazuh-logtest`.

---

## Layout

```
compose.yml                     # the stack
siem/                           # Wazuh config + generated certs
monitored-server/               # Dockerfile + entrypoint for the SSH endpoint
custom-rules/local_rules.xml    # rules 100100 / 100101
detection-tests/                # 01 live traffic, 02 deterministic replay
report/incident-report.md       # worked SOC investigation write-up
```

*Lab for defensive-security practice only. All activity targets the lab's own
containers; the source IPs used in tests are RFC 5737 documentation ranges.*
