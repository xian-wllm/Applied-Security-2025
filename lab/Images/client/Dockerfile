FROM mrcolorrain/vnc-browser:debian
ENV DEBIAN_FRONTEND=noninteractive

# Networking tools + Wazuh agent
RUN set -eux; \
    apt-get update; \
    apt-get install -y \
      dnsmasq iproute2 wireshark nmap libnss3-tools iputils-ping net-tools \
      curl gnupg ca-certificates apt-transport-https; \
    \
    # Wazuh APT key
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import; \
    chmod 644 /usr/share/keyrings/wazuh.gpg; \
    \
    # Wazuh APT repo
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list; \
    \
    apt-get update; \
    WAZUH_MANAGER=10.50.40.10 WAZUH_AGENT_NAME=ext_client01 \
      apt-get install -y wazuh-agent; \
    \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

