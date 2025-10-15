# Zeek Scripts for VNC Network Analysis

This directory contains Zeek (Bro) scripts for comprehensive VNC network analysis and data exfiltration detection.

## Script Categories

### VNC Protocol Analysis
- `vnc-protocol.zeek` - VNC protocol parsing and analysis
- `vnc-sessions.zeek` - VNC session tracking and monitoring
- `vnc-authentication.zeek` - Authentication event logging

### Data Exfiltration Detection
- `data-exfiltration.zeek` - File transfer and clipboard monitoring
- `traffic-analysis.zeek` - Network traffic pattern analysis
- `behavioral-analysis.zeek` - User behavior analysis

### Security Monitoring
- `vnc-security.zeek` - Security event detection
- `anomaly-detection.zeek` - Anomalous activity detection
- `threat-intelligence.zeek` - Threat intelligence integration

## Script Examples

### VNC Protocol Analysis
```zeek
@load base/protocols/conn

module VNC;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        vnc_version: string &log;
        auth_method: string &log;
    };
}

event zeek_init() {
    Log::create_stream(VNC::LOG, [$columns=Info, $path="vnc"]);
}
```

### Data Exfiltration Detection
```zeek
module DataExfiltration;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        data_size: count &log;
        transfer_type: string &log;
        risk_score: double &log;
    };
}

event connection_state_remove(c: connection) {
    if (c$resp$size > 1000000) {  # Large data transfer
        local info: DataExfiltration::Info = [
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $data_size = c$resp$size,
            $transfer_type = "file_transfer",
            $risk_score = 0.8
        ];
        Log::write(DataExfiltration::LOG, info);
    }
}
```

## Configuration

### Zeek Configuration
Key settings in `local.zeek`:
```zeek
@load vnc-protocol
@load data-exfiltration
@load vnc-security

# Log configuration
redef Log::default_rotation_interval = 1hrs;
redef Log::default_mgmt_rotation_interval = 1hrs;

# Network configuration
redef Site::local_nets = {192.168.100.0/24};
```

### Log Output
Scripts generate structured logs in JSON format:
- `vnc.log` - VNC protocol events
- `data_exfiltration.log` - Data exfiltration events
- `vnc_security.log` - Security events

## Deployment

```bash
# Copy scripts to Zeek scripts directory
sudo cp *.zeek /opt/zeek/share/zeek/site/

# Update Zeek configuration
sudo zeekctl deploy

# Monitor logs
tail -f /opt/zeek/logs/current/vnc.log
```

## Analysis

### Key Metrics
- VNC connection frequency
- Data transfer volumes
- Authentication failures
- Session duration patterns

### Alerting
Scripts can trigger alerts for:
- Unusual data transfer patterns
- Failed authentication attempts
- Suspicious session behavior
- Protocol anomalies
