FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace bpftrace procps less \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/tracer
CMD ["bash"]
