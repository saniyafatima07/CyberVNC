@load base/protocols/conn
module VNC;

export {
  redef enum Log::ID += { LOG };
  type Info: record {
    ts: time &log;
    uid: string &log;
    id: conn_id &log;
    note: string &log;
  };
}

event zeek_init() {
  Log::create_stream(VNC::LOG, [$columns=Info, $path="vnc_events"]);
}

event new_connection(c: connection) {
  if ( c$id$resp_p >= 5900/tcp && c$id$resp_p <= 5910/tcp ) {
    local rec: VNC::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $note="VNC port activity"];
    Log::write(VNC::LOG, rec);
  }
}
