#!/bin/bash
# Start rsyslog (so sshd auth events land in /var/log/auth.log), then the
# Wazuh agent (which reads that file and ships events to the manager), then
# sshd in the foreground so the container stays alive and keeps producing
# auth logs for the SIEM to collect.
set -e

# ---- rsyslog setup -----------------------------------------------------
# rsyslog drops privileges to the 'syslog' user, so the log files and its
# work/spool dir must be writable by that user (a root-owned auth.log would
# silently receive nothing). We also disable RepeatedMsgReduction: a SIEM
# must see every attempt, not a collapsed "last message repeated N times".
mkdir -p /var/spool/rsyslog
chown -R syslog:adm /var/spool/rsyslog
touch /var/log/auth.log /var/log/syslog
chown syslog:adm /var/log/auth.log /var/log/syslog
sed -i 's/^\$RepeatedMsgReduction on/$RepeatedMsgReduction off/' /etc/rsyslog.conf || true
# imklog can't read /proc/kmsg in an unprivileged container; drop it so the
# rest of rsyslog still starts cleanly.
sed -i 's/^module(load="imklog".*/# imklog disabled in container/' /etc/rsyslog.conf || true
rsyslogd

# ---- Wazuh agent setup -------------------------------------------------
# Point the agent at the manager and make sure it reads auth.log.
sed -i 's|<address>.*</address>|<address>wazuh.manager</address>|' \
    /var/ossec/etc/ossec.conf || true

if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n</ossec_config>|' \
        /var/ossec/etc/ossec.conf
fi

/var/ossec/bin/wazuh-control start || true

# ---- sshd in the foreground -------------------------------------------
# No -e, so sshd logs via syslog (-> auth.log), not to stderr.
ssh-keygen -A
exec /usr/sbin/sshd -D
