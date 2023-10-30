@load base/protocols/conn/removal-hooks

module ASN;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## Record type containing the column fields of the ASN log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# transport protocol
		proto: string &log &optional;

		success: bool &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into ASN logging.
	global log_asn: event(rec: Info);

	## ASN finalization hook.
	global finalize_asn: Conn::RemovalHook;
}

redef record connection += {
	asn_proto: string &optional;
	asn: Info &optional;
};

export {
    const asn1_ports_tcp: set[port] = { 12345/tcp } &redef;
    const asn1_ports_udp: set[port] = { 12345/udp } &redef;
}
redef likely_server_ports += { asn1_ports_tcp, asn1_ports_udp };

event zeek_init() &priority=5 {
	Analyzer::register_for_ports(Analyzer::ANALYZER_ASN1_TCP, asn1_ports_tcp);
	Analyzer::register_for_ports(Analyzer::ANALYZER_ASN1_UDP, asn1_ports_udp);

	Log::create_stream(ASN::LOG, [$columns=Info, $ev=log_asn, $path="asn1", $policy=log_policy]);
}

hook set_session(c: connection) {
	if ( c?$asn )
		return;

	c$asn = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_asn);
}

@if (Version::at_least("5.2.0"))
event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) {
  if ( atype == Analyzer::ANALYZER_ASN1_TCP ) {
    info$c$asn_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_ASN1_UDP ) {
    info$c$asn_proto = "udp";
  }
}
@else @if (Version::at_least("4.2.0"))
event analyzer_confirmation(c: connection, atype: AllAnalyzers::Tag, aid: count) {
@else
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) {
@endif

  if ( atype == Analyzer::ANALYZER_ASN1_TCP ) {
    c$asn_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_ASN1_UDP ) {
    c$asn_proto = "udp";
  }

}
@endif

function emit_log(c: connection) {
	if ( ! c?$asn )
		return;

	Log::write(ASN::LOG, c$asn);
	delete c$asn;
}

event ASN::message(c: connection, is_orig: bool, success: bool) {
	hook set_session(c);

	local info = c$asn;

	if (( ! info?$proto ) && c?$asn_proto)
	  info$proto = c$asn_proto;

	info$success = success;

	emit_log(c);
}


hook finalize_asn(c: connection) {
	;
}
