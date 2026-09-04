FROM alpine:3.20
RUN apk add --no-cache tcpdump iproute2 procps
COPY entrypoint.sh /netcap.sh
RUN chmod 0755 /netcap.sh
ENTRYPOINT ["/bin/sh", "/netcap.sh"]
