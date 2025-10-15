# Ansible Playbooks for Lab Automation

This directory contains Ansible playbooks for automated lab provisioning and configuration.

## Playbooks

### Core Playbooks
- `lab-setup.yml` - Complete lab environment setup
- `vnc-server-setup.yml` - VNC server configuration
- `monitoring-setup.yml` - ELK stack and monitoring tools
- `attacker-setup.yml` - Attacker VM configuration

### Component Playbooks
- `tigervnc-install.yml` - TigerVNC installation and configuration
- `realvnc-install.yml` - RealVNC installation and configuration
- `suricata-setup.yml` - Suricata IDS/IPS setup
- `zeek-setup.yml` - Zeek network analysis setup
- `elk-stack-setup.yml` - Elasticsearch, Logstash, Kibana setup

## Inventory

The `inventory/` directory contains:
- `hosts.yml` - Lab host definitions
- `group_vars/` - Group-specific variables
- `host_vars/` - Host-specific variables

## Variables

Key variables in `group_vars/all.yml`:
```yaml
# VNC Configuration
vnc_password: "SecureVNC123!"
vnc_port: 5900
vnc_display: ":1"

# Network Configuration
lab_network: "192.168.100.0/24"
vnc_server_ip: "192.168.100.10"
attacker_ip: "192.168.100.20"
monitoring_ip: "192.168.100.30"

# Security Settings
enable_tls: true
enable_authentication: true
log_level: "info"
```

## Usage

```bash
# Complete lab setup
ansible-playbook -i inventory/hosts.yml lab-setup.yml

# Setup specific components
ansible-playbook -i inventory/hosts.yml vnc-server-setup.yml
ansible-playbook -i inventory/hosts.yml monitoring-setup.yml

# Run with specific tags
ansible-playbook -i inventory/hosts.yml lab-setup.yml --tags "vnc,monitoring"
```

## Roles

- `vnc-server` - VNC server installation and configuration
- `monitoring` - ELK stack and monitoring tools
- `attacker-tools` - Attack simulation tools
- `firewall` - Firewall configuration
- `logging` - Centralized logging setup
