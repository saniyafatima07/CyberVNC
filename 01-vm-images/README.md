# VM Images and Lab Provisioning

This directory contains VM images and Ansible playbooks for automated lab provisioning.

## Contents

- `vm-images/` - Pre-configured VM templates
- `ansible-playbooks/` - Automation scripts for lab setup
- `vagrant/` - Vagrant configuration files
- `docker/` - Containerized lab components

## VM Images

### Base Images
- **Ubuntu 22.04 LTS** - Primary lab environment
- **CentOS 8** - Alternative Linux distribution
- **Windows Server 2019** - Windows VNC server testing

### Pre-installed Software
- TigerVNC Server/Client
- RealVNC Server/Client
- Wireshark
- Suricata
- Zeek (Bro)
- ELK Stack components
- Python 3.8+
- Ansible

## Quick Setup

```bash
# Clone and setup
git clone <repository>
cd CyberVNC/01-vm-images

# Start lab environment
vagrant up

# Or use Ansible
ansible-playbook -i inventory lab-setup.yml
```

## Lab Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Attacker VM   │    │   VNC Server    │    │  Monitoring VM   │
│                 │    │                 │    │                 │
│ - Kali Linux    │◄──►│ - Ubuntu 22.04  │◄──►│ - ELK Stack     │
│ - Attack Tools  │    │ - TigerVNC      │    │ - Suricata      │
│ - Python Scripts│    │ - RealVNC       │    │ - Zeek          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Requirements

- VirtualBox 6.0+ or VMware Workstation
- Vagrant 2.2+
- Ansible 2.9+
- 8GB RAM minimum
- 50GB disk space
