#!/usr/bin/env bash
set -euo pipefail
# Kernel forwarding inside container
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Start FRR daemons
/usr/lib/frr/frrinit.sh start || true
# Optional NAT examples if you add a WAN later
# iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE || true
# iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE || true
# Keep container alive and show logs
tail -f /var/log/frr/* || tail -f /dev/null
