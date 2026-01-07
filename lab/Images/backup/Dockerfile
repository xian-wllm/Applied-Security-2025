FROM kathara/base

# Base tools for backup nodes
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        borgbackup \
        cron \
        rsync \
        openssh-server \
        curl \
        jq \
        ca-certificates \
        default-mysql-client && \
    rm -rf /var/lib/apt/lists/*

# Wazuh agent
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gnupg \
        apt-transport-https && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="10.50.40.10" apt-get install -y --no-install-recommends wazuh-agent && \
    rm -rf /var/lib/apt/lists/*
