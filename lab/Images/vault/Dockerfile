FROM hashicorp/vault AS vaultbin

# add necessary tools for kathara routing
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash iproute2 iptables ca-certificates curl jq 

RUN apt-get install gnupg openssh-server apt-transport-https -y
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN apt-get update

RUN WAZUH_MANAGER="10.50.40.10" apt-get install wazuh-agent -y

RUN rm -rf /var/lib/apt/lists/*

COPY --from=vaultbin /bin/vault /usr/local/bin/vault
COPY ./guac-login.sh /usr/local/bin/guac-login.sh
RUN chmod +x /usr/local/bin/guac-login.sh

SHELL ["/bin/bash", "-lc"]
