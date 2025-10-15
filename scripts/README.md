# CyberVNC Project Structure

This directory contains utility scripts and configuration files for the CyberVNC project.

## Scripts

### Deployment Scripts
- `deploy-lab.sh` - Complete lab deployment script
- `deploy-monitoring.sh` - Monitoring stack deployment
- `deploy-security.sh` - Security tools deployment

### Testing Scripts
- `run-tests.sh` - Automated test execution
- `collect-logs.sh` - Log collection and analysis
- `generate-report.sh` - Report generation

### Maintenance Scripts
- `update-rules.sh` - Update security rules and signatures
- `backup-configs.sh` - Backup configuration files
- `health-check.sh` - System health monitoring

## Configuration Files

### Global Configuration
- `global-config.yaml` - Global project configuration
- `environment-config.yaml` - Environment-specific settings
- `security-config.yaml` - Security policy configuration

### Deployment Configuration
- `deployment-config.yaml` - Deployment settings
- `monitoring-config.yaml` - Monitoring configuration
- `testing-config.yaml` - Testing parameters

## Usage

### Quick Start
```bash
# Deploy complete lab environment
./scripts/deploy-lab.sh

# Run all tests
./scripts/run-tests.sh

# Generate final report
./scripts/generate-report.sh
```

### Custom Deployment
```bash
# Deploy specific components
./scripts/deploy-monitoring.sh
./scripts/deploy-security.sh

# Run specific tests
./scripts/run-tests.sh --component detection
./scripts/run-tests.sh --component prevention
```

## Configuration

### Global Configuration (global-config.yaml)
```yaml
# Global Configuration
project:
  name: "CyberVNC"
  version: "1.0.0"
  description: "VNC Data Exfiltration Detection and Prevention Testbed"

environment:
  lab_network: "192.168.100.0/24"
  vnc_server_ip: "192.168.100.10"
  attacker_ip: "192.168.100.20"
  monitoring_ip: "192.168.100.30"

security:
  enable_tls: true
  enable_authentication: true
  log_level: "INFO"
  alert_threshold: 0.8

monitoring:
  elk_stack:
    enabled: true
    elasticsearch_port: 9200
    kibana_port: 5601
    logstash_port: 5044
  
  suricata:
    enabled: true
    rules_path: "/etc/suricata/rules"
    
  zeek:
    enabled: true
    logs_path: "/opt/zeek/logs"
```

### Environment Configuration (environment-config.yaml)
```yaml
# Environment Configuration
development:
  vnc_password: "dev123"
  log_level: "DEBUG"
  enable_debug: true
  
staging:
  vnc_password: "staging123"
  log_level: "INFO"
  enable_debug: false
  
production:
  vnc_password: "prod123"
  log_level: "WARN"
  enable_debug: false
  enable_monitoring: true
```

## Scripts Documentation

### deploy-lab.sh
```bash
#!/bin/bash
# Complete lab deployment script

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    # Implementation for prerequisite checking
}

# Deploy VMs
deploy_vms() {
    echo "Deploying VMs..."
    cd 01-vm-images
    vagrant up
    cd ..
}

# Configure monitoring
configure_monitoring() {
    echo "Configuring monitoring..."
    cd 07-elk-stack
    docker-compose up -d
    cd ..
}

# Deploy security tools
deploy_security() {
    echo "Deploying security tools..."
    cd 09-defense-mechanisms
    python3 defense-deployer.py --config defense-config.yaml
    cd ..
}

# Main deployment
main() {
    check_prerequisites
    deploy_vms
    configure_monitoring
    deploy_security
    echo "Lab deployment completed!"
}

main "$@"
```

### run-tests.sh
```bash
#!/bin/bash
# Automated test execution script

# Run attack simulations
run_attack_tests() {
    echo "Running attack simulations..."
    cd 06-test-harness
    python3 test-runner.py --config test-config.yaml
    cd ..
}

# Run detection tests
run_detection_tests() {
    echo "Running detection tests..."
    cd 09-defense-mechanisms
    python3 detection-tester.py --config detection-config.yaml
    cd ..
}

# Collect results
collect_results() {
    echo "Collecting test results..."
    cd 06-test-harness
    python3 result-collector.py --output results/
    cd ..
}

# Main test execution
main() {
    run_attack_tests
    run_detection_tests
    collect_results
    echo "Test execution completed!"
}

main "$@"
```

## Maintenance

### Regular Maintenance Tasks
1. **Daily**
   - Check system health
   - Review security alerts
   - Update threat intelligence

2. **Weekly**
   - Update security rules
   - Review access logs
   - Test backup systems

3. **Monthly**
   - Security patch management
   - Vulnerability scanning
   - Performance optimization

### Backup Procedures
```bash
# Backup configurations
./scripts/backup-configs.sh

# Backup logs
./scripts/backup-logs.sh

# Backup evidence
./scripts/backup-evidence.sh
```

## Troubleshooting

### Common Issues
1. **VM Deployment Issues**
   - Check VirtualBox/VMware installation
   - Verify Vagrant configuration
   - Check system resources

2. **Monitoring Issues**
   - Check ELK stack status
   - Verify log forwarding
   - Check network connectivity

3. **Security Tool Issues**
   - Check Suricata configuration
   - Verify Zeek installation
   - Check firewall rules

### Debug Mode
```bash
# Enable debug mode
export DEBUG=true
./scripts/deploy-lab.sh

# Check logs
tail -f /var/log/cybervnc.log
```

## Support

### Documentation
- README files in each directory
- Configuration examples
- Troubleshooting guides

### Contact
- Project maintainer: [Your Name]
- Email: [Your Email]
- Issues: GitHub Issues
- Documentation: Project Wiki
