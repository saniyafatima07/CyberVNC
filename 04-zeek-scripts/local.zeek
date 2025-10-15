@load policy/tuning/json-logs
@load ./vnc-protocol.zeek
redef Log::default_rotation_interval = 1hr;
redef Site::local_nets += { 192.168.100.0/24 };
