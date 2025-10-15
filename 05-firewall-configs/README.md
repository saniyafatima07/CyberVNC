# Firewall Configurations for VNC Security

This directory contains iptables and nftables firewall profiles designed to prevent VNC data exfiltration and enhance security.

## Firewall Profiles

### Basic Security Profile
- `basic-security.sh` - Basic VNC access control
- `basic-security.nft` - nftables equivalent

### Advanced Security Profile
- `advanced-security.sh` - Comprehensive VNC security
- `advanced-security.nft` - nftables equivalent

### Data Exfiltration Prevention
- `data-exfiltration-prevention.sh` - Block file transfers and clipboard
- `data-exfiltration-prevention.nft` - nftables equivalent

## Configuration Examples

### Basic VNC Security (iptables)
```bash
#!/bin/bash
# Basic VNC Security Rules

# Allow VNC connections only from specific networks
iptables -A INPUT -p tcp --dport 5900:5910 -s 192.168.100.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 5900:5910 -j DROP

# Rate limiting for VNC connections
iptables -A INPUT -p tcp --dport 5900:5910 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 5900:5910 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 -j DROP

# Log VNC connection attempts
iptables -A INPUT -p tcp --dport 5900:5910 -j LOG --log-prefix "VNC-ACCESS: "
```

### Data Exfiltration Prevention (nftables)
```nft
#!/usr/bin/nft -f
# Data Exfiltration Prevention Rules

table inet vnc_security {
    chain input {
        type filter hook input priority 0;
        
        # Allow VNC from trusted networks only
        tcp dport 5900-5910 ip saddr 192.168.100.0/24 accept
        tcp dport 5900-5910 drop
        
        # Rate limiting
        tcp dport 5900-5910 ct state new limit rate 5/minute accept
        tcp dport 5900-5910 ct state new drop
        
        # Log all VNC attempts
        tcp dport 5900-5910 log prefix "VNC-ACCESS: " drop
    }
    
    chain forward {
        type filter hook forward priority 0;
        
        # Block file transfer protocols
        tcp dport {21, 22, 80, 443, 8080} drop
        udp dport {53, 123, 161} drop
    }
}
```

### Advanced Security Features
```bash
#!/bin/bash
# Advanced VNC Security Rules

# Time-based access control
iptables -A INPUT -p tcp --dport 5900:5910 -m time --timestart 08:00 --timestop 18:00 -j ACCEPT
iptables -A INPUT -p tcp --dport 5900:5910 -j DROP

# Geographic blocking (using ipset)
ipset create geo_block hash:net
ipset add geo_block 0.0.0.0/0
iptables -A INPUT -p tcp --dport 5900:5910 -m set --match-set geo_block src -j DROP

# Connection state tracking
iptables -A INPUT -p tcp --dport 5900:5910 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 5900:5910 -m conntrack --ctstate NEW -m limit --limit 3/minute -j ACCEPT
```

## Deployment

### iptables Deployment
```bash
# Make scripts executable
chmod +x *.sh

# Apply basic security
sudo ./basic-security.sh

# Apply advanced security
sudo ./advanced-security.sh

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### nftables Deployment
```bash
# Apply nftables rules
sudo nft -f basic-security.nft

# Save rules
sudo nft list ruleset > /etc/nftables.conf
```

## Monitoring

### Log Analysis
Monitor firewall logs for:
- VNC connection attempts
- Blocked connections
- Rate limiting triggers
- Geographic blocks

### Performance Monitoring
- Connection tracking table size
- Rule hit counts
- CPU usage during high traffic

## Best Practices

1. **Principle of Least Privilege** - Only allow necessary VNC access
2. **Network Segmentation** - Isolate VNC servers from critical systems
3. **Time-based Access** - Restrict VNC access to business hours
4. **Geographic Restrictions** - Block access from high-risk countries
5. **Rate Limiting** - Prevent brute force attacks
6. **Logging** - Comprehensive logging for audit trails
7. **Regular Updates** - Keep firewall rules updated
8. **Testing** - Regular testing of firewall rules
