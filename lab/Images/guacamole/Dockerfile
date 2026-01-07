FROM guacamole/guacamole

USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
    iproute2 net-tools iptables ca-certificates iputils-ping lsb-release \
 && rm -rf /var/lib/apt/lists/*

RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN apt-get update

RUN WAZUH_MANAGER="10.50.40.10" apt-get install wazuh-agent -y

COPY ./user-mapping.xml /etc/guacamole/user-mapping.xml

SHELL ["/bin/bash", "-c"]