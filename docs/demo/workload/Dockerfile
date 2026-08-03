FROM debian:bookworm-slim

# Tools the workload uses to exercise every field the monitor captures:
#   curl/wget/dnsutils/netcat/socat -> network (TCP/UDP/DNS/HTTP)
#   procps/findutils/grep/sed/gawk/coreutils/file -> varied execs + fs reads
#   python3 -> raw socket generator (netgen.py)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        dnsutils \
        netcat-openbsd \
        socat \
        iproute2 \
        procps \
        findutils \
        grep \
        sed \
        gawk \
        coreutils \
        file \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/workload
COPY workload.sh netgen.py ./
RUN chmod +x workload.sh netgen.py && mkdir -p /opt/workload/data

# base delay between rounds (seconds); set EXTERNAL_NET=0 to skip outbound net
ENV SLEEP_SECONDS=2 \
    EXTERNAL_NET=1

ENTRYPOINT ["/opt/workload/workload.sh"]
