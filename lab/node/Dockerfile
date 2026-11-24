# syntax=docker/dockerfile:1
# Image chung cho client, attacker, server. Vai trò chọn bằng biến môi trường ROLE.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping curl iperf3 hping3 netsniff-ng nginx-light procps tcpdump ethtool \
    && rm -rf /var/lib/apt/lists/*
COPY lab/node/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
