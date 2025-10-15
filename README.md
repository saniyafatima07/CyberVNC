# CyberVNC - VNC Data Exfiltration Detection and Prevention Testbed

## Project Overview

CyberVNC is a comprehensive testbed system designed to simulate and prevent data exfiltration attacks through TigerVNC and RealVNC servers. This project addresses the critical security vulnerabilities inherent in VNC implementations and provides detection, prevention, and hardening mechanisms.

## Background

Internet connectivity has enabled global LAN systems to span continents, making VNC (Virtual Network Computing) servers essential for remote access. However, VNC inherently provides weak security with no passwords or encryption by default. While TigerVNC and RealVNC offer TLS solutions, data exfiltration remains a significant concern for both insider threats and external attackers who gain VNC server access.

## Project Goals

- Simulate all possible data exfiltration scenarios via TigerVNC and RealVNC
- Develop comprehensive detection mechanisms using network monitoring tools
- Implement prevention strategies through firewall configurations and access controls
- Provide actionable hardening recommendations for production environments

## Repository Structure

```
CyberVNC/
├── 01-vm-images/                 # VM images and provisioning
├── 02-ansible-playbooks/         # Lab automation
├── 03-suricata-rules/           # IDS/IPS rules
├── 04-zeek-scripts/             # Network analysis scripts
├── 05-firewall-configs/         # iptables/nftables profiles
├── 06-test-harness/             # Attack simulation scripts
├── 07-elk-stack/                # Log analysis dashboards
├── 08-attack-scenarios/         # Data exfiltration techniques
├── 09-defense-mechanisms/       # Detection and prevention tools
├── 10-documentation/            # Reports and runbooks
└── scripts/                     # Utility scripts
```

## Deployment Guide

### Prerequisites
```bash
# System Requirements
- Ubuntu 22.04 LTS or CentOS 8
- 8GB RAM minimum
- 50GB disk space
- VirtualBox 6.0+ or VMware Workstation
- Vagrant 2.2+
- Ansible 2.9+
```

### Quick Start
```bash
# 1. Clone the repository
git clone <repository-url>
cd CyberVNC

# 2. Setup lab environment
cd 01-vm-images
vagrant up

# 3. Deploy defense mechanisms
cd ../09-defense-mechanisms
python3 defense-deployer.py --config defense-config.yaml

# 4. Run attack simulations
cd ../06-test-harness
python3 test-runner.py --config test-config.yaml
```

### Detailed Deployment

#### Step 1: Lab Environment Setup
```bash
# Navigate to VM images directory
cd 01-vm-images

# Review and customize Vagrantfile
vim Vagrantfile

# Start lab environment
vagrant up

# Verify lab setup
vagrant status
```

#### Step 2: VNC Server Configuration
```bash
# Navigate to Ansible playbooks
cd ../02-ansible-playbooks

# Review inventory
vim inventory/hosts.yml

# Configure VNC servers
ansible-playbook -i inventory/hosts.yml vnc-server-setup.yml

# Verify VNC configuration
ansible-playbook -i inventory/hosts.yml vnc-server-setup.yml --check
```

#### Step 3: Security Configuration
```bash
# Navigate to firewall configs
cd ../05-firewall-configs

# Apply basic security rules
sudo ./basic-security.sh

# Apply advanced security rules
sudo ./advanced-security.sh

# Verify firewall rules
sudo iptables -L
```

## Runbooks

### Incident Response Runbook
```markdown
# VNC Security Incident Response Runbook

## Initial Response (0-15 minutes)

### 1. Incident Detection
- [ ] Verify incident through monitoring systems
- [ ] Check ELK dashboards for alerts
- [ ] Review Suricata logs for attack signatures
- [ ] Analyze Zeek logs for anomalous behavior

### 2. Incident Classification
- [ ] Determine incident severity (Low/Medium/High/Critical)
- [ ] Identify affected systems and users
- [ ] Assess potential data exposure
- [ ] Document initial findings

### 3. Immediate Containment
- [ ] Block suspicious IP addresses
- [ ] Terminate compromised VNC sessions
- [ ] Isolate affected systems
- [ ] Preserve evidence

## Investigation (15-60 minutes)

### 4. Evidence Collection
- [ ] Collect network traffic captures
- [ ] Gather system logs
- [ ] Capture memory dumps
- [ ] Document timeline of events

### 5. Analysis
- [ ] Analyze attack vectors
- [ ] Determine data exfiltration scope
- [ ] Identify compromised accounts
- [ ] Assess system integrity

## Recovery (1-4 hours)

### 6. System Recovery
- [ ] Patch vulnerabilities
- [ ] Reset compromised credentials
- [ ] Restore from clean backups
- [ ] Implement additional security measures

### 7. Post-Incident
- [ ] Conduct lessons learned review
- [ ] Update security procedures
- [ ] Enhance monitoring rules
- [ ] Provide user training
```

### Maintenance Runbook
```markdown
# VNC Security Maintenance Runbook

## Daily Tasks
- [ ] Review security alerts
- [ ] Check system health
- [ ] Monitor performance metrics
- [ ] Update threat intelligence

## Weekly Tasks
- [ ] Review access logs
- [ ] Update security signatures
- [ ] Test backup systems
- [ ] Review user permissions

## Monthly Tasks
- [ ] Security patch management
- [ ] Vulnerability scanning
- [ ] Penetration testing
- [ ] Security training

## Quarterly Tasks
- [ ] Security policy review
- [ ] Disaster recovery testing
- [ ] Security architecture review
- [ ] Compliance assessment
```

## Configuration Guides

### VNC Server Hardening
```bash
# 1. Enable TLS encryption
sudo vncserver -localhost no -SecurityTypes VncAuth,TLSVnc

# 2. Configure strong authentication
sudo vncpasswd /etc/vncpasswd

# 3. Restrict access by IP
sudo iptables -A INPUT -p tcp --dport 5900 -s 192.168.100.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5900 -j DROP

# 4. Enable logging
sudo vncserver -log /var/log/vnc.log

# 5. Configure session timeouts
sudo vncserver -timeout 3600
```

### Network Security Configuration
```bash
# 1. Configure network segmentation
sudo ip route add 192.168.100.0/24 via 192.168.1.1

# 2. Enable traffic monitoring
sudo tcpdump -i eth0 -w vnc-traffic.pcap port 5900

# 3. Configure IDS/IPS
sudo suricata -c suricata.yaml -i eth0

# 4. Setup log forwarding
sudo rsyslog -f /etc/rsyslog.conf
```

## Troubleshooting Guide

### Common Issues

#### VNC Connection Issues
```bash
# Check VNC server status
sudo systemctl status vncserver

# Check firewall rules
sudo iptables -L | grep 5900

# Check network connectivity
telnet <vnc-server-ip> 5900

# Check VNC logs
sudo tail -f /var/log/vnc.log
```

#### Monitoring Issues
```bash
# Check ELK stack status
docker-compose ps

# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Check Logstash pipelines
curl http://localhost:9600/_node/pipelines

# Check Kibana status
curl http://localhost:5601/api/status
```

#### Security Alert Issues
```bash
# Check Suricata status
sudo systemctl status suricata

# Check Suricata logs
sudo tail -f /var/log/suricata/fast.log

# Check Zeek status
sudo zeekctl status

# Check Zeek logs
sudo tail -f /opt/zeek/logs/current/vnc.log
```

## Best Practices

### Security Best Practices
1. **Principle of Least Privilege** - Only grant necessary access
2. **Network Segmentation** - Isolate VNC servers from critical systems
3. **Encryption** - Always use TLS for VNC connections
4. **Monitoring** - Implement comprehensive monitoring
5. **Regular Updates** - Keep all systems updated
6. **Access Control** - Implement strong authentication
7. **Logging** - Enable comprehensive logging
8. **Incident Response** - Have clear response procedures

### Performance Best Practices
1. **Resource Monitoring** - Monitor CPU, memory, and network usage
2. **Load Balancing** - Distribute VNC connections across multiple servers
3. **Caching** - Implement caching for frequently accessed data
4. **Optimization** - Regularly optimize system performance
5. **Capacity Planning** - Plan for future growth

### Operational Best Practices
1. **Documentation** - Maintain up-to-date documentation
2. **Training** - Provide regular security training
3. **Testing** - Regular testing of security measures
4. **Backup** - Regular backups of critical data
5. **Recovery** - Test disaster recovery procedures
