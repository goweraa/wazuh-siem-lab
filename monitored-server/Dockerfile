# Monitored Linux server for the SIEM lab.
# Runs OpenSSH plus the Wazuh agent, which ships auth logs and file-integrity
# events to the Wazuh manager for detection. This is the "endpoint" a SOC
# analyst would be watching.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WAZUH_VERSION=4.14.8

RUN apt-get update && apt-get install -y \
        openssh-server \
        rsyslog \
        curl \
        gnupg2 \
        lsb-release \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Install the Wazuh agent from the official Wazuh apt repository.
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=${WAZUH_VERSION}-* \
    && rm -rf /var/lib/apt/lists/*

# Prepare SSH: create a normal, non-root demo user and the sshd runtime dir.
RUN mkdir -p /var/run/sshd \
    && useradd -m -s /bin/bash analyst \
    && echo 'analyst:Lab-Analyst-2026!' | chpasswd \
    && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
