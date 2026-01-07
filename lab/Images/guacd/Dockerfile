FROM guacamole/guacd

USER root

RUN apk add --no-cache \
      bash \
      iproute2 \
      iptables \
      ca-certificates \
      openssh \
      lsb-release 

SHELL ["/bin/bash", "-c"]
