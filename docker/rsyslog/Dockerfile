FROM debian:bookworm-slim

# Debian rsyslog ma pełne moduły (omfwd.so, imudp, imtcp) — Alpine ma niekompletne pakiety
RUN apt-get update && \
    apt-get install -y --no-install-recommends rsyslog && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/spool/rsyslog && \
    chmod 700 /var/spool/rsyslog

# Konfiguracja montowana jako volume
# /etc/rsyslog.conf <- ./config/rsyslog/rsyslog.conf

EXPOSE 514/udp 514/tcp

CMD ["/usr/sbin/rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]
