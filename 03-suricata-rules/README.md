# Suricata Ruleset for VNC Detection

This directory contains Suricata IDS/IPS rules specifically designed to detect VNC-related attacks and data exfiltration attempts.

## Rule Categories

### VNC Protocol Detection
- `vnc-protocol.rules` - Basic VNC protocol detection
- `vnc-handshake.rules` - VNC handshake and authentication monitoring
- `vnc-encryption.rules` - TLS/SSL VNC connection detection

### Data Exfiltration Detection
- `data-exfiltration.rules` - File transfer and clipboard monitoring
- `suspicious-traffic.rules` - Unusual VNC traffic patterns
- `insider-threat.rules` - Insider threat indicators

### Attack Detection
- `vnc-attacks.rules` - Known VNC attack patterns
- `brute-force.rules` - Password brute force attempts
- `session-hijacking.rules` - Session hijacking attempts

## Rule Examples

### VNC Protocol Detection
```suricata
alert tcp any any -> any 5900 (msg:"VNC Connection Attempt"; flow:to_server,established; content:"RFB"; depth:3; sid:1000001; rev:1;)

alert tcp any any -> any 5901 (msg:"VNC TLS Connection"; flow:to_server,established; tls.sni; sid:1000002; rev:1;)
```

### Data Exfiltration Detection
```suricata
alert tcp any 5900 -> any any (msg:"Potential VNC Data Exfiltration"; flow:from_server,established; content:"File Transfer"; sid:1000101; rev:1;)

alert tcp any 5900 -> any any (msg:"VNC Clipboard Access"; flow:from_server,established; content:"Clipboard"; sid:1000102; rev:1;)
```

### Brute Force Detection
```suricata
alert tcp any any -> any 5900 (msg:"VNC Brute Force Attempt"; flow:to_server,established; threshold:type both, track by_src, count 5, seconds 60; sid:1000201; rev:1;)
```

## Configuration

### Suricata Configuration
Key settings in `suricata.yaml`:
```yaml
# Rule files
rule-files:
  - vnc-protocol.rules
  - data-exfiltration.rules
  - vnc-attacks.rules

# Output configuration
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
```

### Log Analysis
Rules generate structured logs in JSON format for easy analysis with ELK stack.

## Deployment

```bash
# Copy rules to Suricata rules directory
sudo cp *.rules /etc/suricata/rules/

# Update Suricata configuration
sudo suricata-update

# Restart Suricata
sudo systemctl restart suricata
```

## Monitoring

Monitor Suricata logs for:
- VNC connection attempts
- Data exfiltration patterns
- Attack signatures
- Performance metrics
