#!/bin/bash
set -euo pipefail

# Allow VNC only from lab network
iptables -A INPUT -p tcp --dport 5900:5910 -s 192.168.100.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 5900:5910 -j DROP

# Rate limit new connections
iptables -A INPUT -p tcp --dport 5900:5910 -m conntrack --ctstate NEW -m limit --limit 5/min -j ACCEPT
iptables -A INPUT -p tcp --dport 5900:5910 -m conntrack --ctstate NEW -j DROP

# Log attempts
iptables -A INPUT -p tcp --dport 5900:5910 -j LOG --log-prefix "VNC-ACCESS: " --log-level 6
