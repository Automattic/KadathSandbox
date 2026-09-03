FROM alpine:3.20
RUN apk add --no-cache iptables iproute2
COPY netguard.sh /netguard.sh
RUN chmod 0755 /netguard.sh
ENTRYPOINT ["/bin/sh", "/netguard.sh"]
