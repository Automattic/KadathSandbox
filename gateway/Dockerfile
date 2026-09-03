FROM mitmproxy/mitmproxy:12.2.3

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables dnsmasq tcpdump iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
RUN chmod 0755 /usr/local/bin/gateway-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]
