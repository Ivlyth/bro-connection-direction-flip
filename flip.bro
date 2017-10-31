event OS_version_found(c: connection, host: addr, OS: OS_version)
{
  print "################### OS_version_found start ##################";
  print fmt("in OS_version_found, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### OS_version_found end   ##################";
}

event bro_done()
{
  print "################### bro_done start ##################";
  print "################### bro_done end   ##################";
}

event bro_init()
{
  print "################### bro_init start ##################";
  print "################### bro_init end   ##################";
}

event conn_stats(c: connection, os: endpoint_stats, rs: endpoint_stats)
{
  print "################### conn_stats start ##################";
  print fmt("in conn_stats, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### conn_stats end   ##################";
}

event conn_weird(name: string, c: connection, addl: string)
{
  print "################### conn_weird start ##################";
  print fmt("in conn_weird, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### conn_weird end   ##################";
}

event connection_external(c: connection, tag: string)
{
  print "################### connection_external start ##################";
  print fmt("in connection_external, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_external end   ##################";
}

event connection_flow_label_changed(c: connection, is_orig: bool, old_label: count, new_label: count)
{
  print "################### connection_flow_label_changed start ##################";
  print fmt("in connection_flow_label_changed, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_flow_label_changed end   ##################";
}

event connection_reused(c: connection)
{
  print "################### connection_reused start ##################";
  print fmt("in connection_reused, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_reused end   ##################";
}

event connection_state_remove(c: connection)
{
  print "################### connection_state_remove start ##################";
  print fmt("in connection_state_remove, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_state_remove end   ##################";
}

event connection_status_update(c: connection)
{
  print "################### connection_status_update start ##################";
  print fmt("in connection_status_update, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_status_update end   ##################";
}

event connection_timeout(c: connection)
{
  print "################### connection_timeout start ##################";
  print fmt("in connection_timeout, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_timeout end   ##################";
}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
{
  print "################### content_gap start ##################";
  print fmt("in content_gap, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### content_gap end   ##################";
}

event dns_mapping_altered(dm: dns_mapping, old_addrs: addr_set, new_addrs: addr_set)
{
  print "################### dns_mapping_altered start ##################";
  print "################### dns_mapping_altered end   ##################";
}

event dns_mapping_lost_name(dm: dns_mapping)
{
  print "################### dns_mapping_lost_name start ##################";
  print "################### dns_mapping_lost_name end   ##################";
}

event dns_mapping_new_name(dm: dns_mapping)
{
  print "################### dns_mapping_new_name start ##################";
  print "################### dns_mapping_new_name end   ##################";
}

event dns_mapping_unverified(dm: dns_mapping)
{
  print "################### dns_mapping_unverified start ##################";
  print "################### dns_mapping_unverified end   ##################";
}

event dns_mapping_valid(dm: dns_mapping)
{
  print "################### dns_mapping_valid start ##################";
  print "################### dns_mapping_valid end   ##################";
}

event esp_packet(p: pkt_hdr)
{
  print "################### esp_packet start ##################";
  print "################### esp_packet end   ##################";
}

event file_gap(f: fa_file, offset: count, len: count)
{
  print "################### file_gap start ##################";
  print "################### file_gap end   ##################";
}

event file_new(f: fa_file)
{
  print "################### file_new start ##################";
  print "################### file_new end   ##################";
}

event file_opened(f: file)
{
  print "################### file_opened start ##################";
  print "################### file_opened end   ##################";
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
  print "################### file_over_new_connection start ##################";
  print fmt("in file_over_new_connection, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### file_over_new_connection end   ##################";
}

event file_reassembly_overflow(f: fa_file, offset: count, skipped: count)
{
  print "################### file_reassembly_overflow start ##################";
  print "################### file_reassembly_overflow end   ##################";
}

event file_sniff(f: fa_file, meta: fa_metadata)
{
  print "################### file_sniff start ##################";
  print "################### file_sniff end   ##################";
}

event file_state_remove(f: fa_file)
{
  print "################### file_state_remove start ##################";
  print "################### file_state_remove end   ##################";
}

event file_timeout(f: fa_file)
{
  print "################### file_timeout start ##################";
  print "################### file_timeout end   ##################";
}

event finished_send_state(p: event_peer)
{
  print "################### finished_send_state start ##################";
  print "################### finished_send_state end   ##################";
}

event flow_weird(name: string, src: addr, dst: addr)
{
  print "################### flow_weird start ##################";
  print "################### flow_weird end   ##################";
}

event get_file_handle(tag: Analyzer::Tag, c: connection, is_orig: bool)
{
  print "################### get_file_handle start ##################";
  print fmt("in get_file_handle, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### get_file_handle end   ##################";
}

event ipv6_ext_headers(c: connection, p: pkt_hdr)
{
  print "################### ipv6_ext_headers start ##################";
  print fmt("in ipv6_ext_headers, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ipv6_ext_headers end   ##################";
}

event load_sample(samples: load_sample_info, CPU: interval, dmem: int)
{
  print "################### load_sample start ##################";
  print "################### load_sample end   ##################";
}

event mobile_ipv6_message(p: pkt_hdr)
{
  print "################### mobile_ipv6_message start ##################";
  print "################### mobile_ipv6_message end   ##################";
}

event net_weird(name: string)
{
  print "################### net_weird start ##################";
  print "################### net_weird end   ##################";
}

event new_connection(c: connection)
{
  print "################### new_connection start ##################";
  print fmt("in new_connection, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### new_connection end   ##################";
}

event new_packet(c: connection, p: pkt_hdr)
{
  print "################### new_packet start ##################";
  print fmt("in new_packet, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### new_packet end   ##################";
}

event packet_contents(c: connection, contents: string)
{
  print "################### packet_contents start ##################";
  print fmt("in packet_contents, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### packet_contents end   ##################";
}

event profiling_update(f: file, expensive: bool)
{
  print "################### profiling_update start ##################";
  print "################### profiling_update end   ##################";
}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
{
  print "################### protocol_confirmation start ##################";
  print fmt("in protocol_confirmation, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### protocol_confirmation end   ##################";
}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string)
{
  print "################### protocol_violation start ##################";
  print fmt("in protocol_violation, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### protocol_violation end   ##################";
}

event raw_packet(p: raw_pkt_hdr)
{
  print "################### raw_packet start ##################";
  print "################### raw_packet end   ##################";
}

event remote_capture_filter(p: event_peer, filter: string)
{
  print "################### remote_capture_filter start ##################";
  print "################### remote_capture_filter end   ##################";
}

event remote_connection_closed(p: event_peer)
{
  print "################### remote_connection_closed start ##################";
  print "################### remote_connection_closed end   ##################";
}

event remote_connection_error(p: event_peer, reason: string)
{
  print "################### remote_connection_error start ##################";
  print "################### remote_connection_error end   ##################";
}

event remote_connection_established(p: event_peer)
{
  print "################### remote_connection_established start ##################";
  print "################### remote_connection_established end   ##################";
}

event remote_connection_handshake_done(p: event_peer)
{
  print "################### remote_connection_handshake_done start ##################";
  print "################### remote_connection_handshake_done end   ##################";
}

event remote_event_registered(p: event_peer, name: string)
{
  print "################### remote_event_registered start ##################";
  print "################### remote_event_registered end   ##################";
}

event remote_log(level: count, src: count, msg: string)
{
  print "################### remote_log start ##################";
  print "################### remote_log end   ##################";
}

event remote_log_peer(p: event_peer, level: count, src: count, msg: string)
{
  print "################### remote_log_peer start ##################";
  print "################### remote_log_peer end   ##################";
}

event remote_pong(p: event_peer, seq: count, d1: interval, d2: interval, d3: interval)
{
  print "################### remote_pong start ##################";
  print "################### remote_pong end   ##################";
}

event remote_state_access_performed(id: string, v: any)
{
  print "################### remote_state_access_performed start ##################";
  print "################### remote_state_access_performed end   ##################";
}

event remote_state_inconsistency(operation: string, id: string, expected_old: string, real_old: string)
{
  print "################### remote_state_inconsistency start ##################";
  print "################### remote_state_inconsistency end   ##################";
}

event reporter_error(t: time, msg: string, location: string)
{
  print "################### reporter_error start ##################";
  print "################### reporter_error end   ##################";
}

event reporter_info(t: time, msg: string, location: string)
{
  print "################### reporter_info start ##################";
  print "################### reporter_info end   ##################";
}

event reporter_warning(t: time, msg: string, location: string)
{
  print "################### reporter_warning start ##################";
  print "################### reporter_warning end   ##################";
}

event rexmit_inconsistency(c: connection, t1: string, t2: string, tcp_flags: string)
{
  print "################### rexmit_inconsistency start ##################";
  print fmt("in rexmit_inconsistency, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rexmit_inconsistency end   ##################";
}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag)
{
  print "################### scheduled_analyzer_applied start ##################";
  print fmt("in scheduled_analyzer_applied, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### scheduled_analyzer_applied end   ##################";
}

event signature_match(state: signature_state, msg: string, data: string)
{
  print "################### signature_match start ##################";
  print "################### signature_match end   ##################";
}

event software_parse_error(c: connection, host: addr, descr: string)
{
  print "################### software_parse_error start ##################";
  print fmt("in software_parse_error, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### software_parse_error end   ##################";
}

event software_unparsed_version_found(c: connection, host: addr, str: string)
{
  print "################### software_unparsed_version_found start ##################";
  print fmt("in software_unparsed_version_found, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### software_unparsed_version_found end   ##################";
}

event software_version_found(c: connection, host: addr, s: software, descr: string)
{
  print "################### software_version_found start ##################";
  print fmt("in software_version_found, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### software_version_found end   ##################";
}

event tunnel_changed(c: connection, e: EncapsulatingConnVector)
{
  print "################### tunnel_changed start ##################";
  print fmt("in tunnel_changed, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### tunnel_changed end   ##################";
}

event udp_session_done(u: connection)
{
  print "################### udp_session_done start ##################";
  print fmt("in udp_session_done, u$uid is %s, u$id is %s, u$history is %s", u$uid, u$id, u$history);
  print "################### udp_session_done end   ##################";
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
  print "################### arp_reply start ##################";
  print "################### arp_reply end   ##################";
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
  print "################### arp_request start ##################";
  print "################### arp_request end   ##################";
}

event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string)
{
  print "################### bad_arp start ##################";
  print "################### bad_arp end   ##################";
}

event bittorrent_peer_bitfield(c: connection, is_orig: bool, bitfield: string)
{
  print "################### bittorrent_peer_bitfield start ##################";
  print fmt("in bittorrent_peer_bitfield, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_bitfield end   ##################";
}

event bittorrent_peer_cancel(c: connection, is_orig: bool, index: count, begin: count, length: count)
{
  print "################### bittorrent_peer_cancel start ##################";
  print fmt("in bittorrent_peer_cancel, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_cancel end   ##################";
}

event bittorrent_peer_choke(c: connection, is_orig: bool)
{
  print "################### bittorrent_peer_choke start ##################";
  print fmt("in bittorrent_peer_choke, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_choke end   ##################";
}

event bittorrent_peer_handshake(c: connection, is_orig: bool, reserved: string, info_hash: string, peer_id: string)
{
  print "################### bittorrent_peer_handshake start ##################";
  print fmt("in bittorrent_peer_handshake, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_handshake end   ##################";
}

event bittorrent_peer_have(c: connection, is_orig: bool, piece_index: count)
{
  print "################### bittorrent_peer_have start ##################";
  print fmt("in bittorrent_peer_have, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_have end   ##################";
}

event bittorrent_peer_interested(c: connection, is_orig: bool)
{
  print "################### bittorrent_peer_interested start ##################";
  print fmt("in bittorrent_peer_interested, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_interested end   ##################";
}

event bittorrent_peer_keep_alive(c: connection, is_orig: bool)
{
  print "################### bittorrent_peer_keep_alive start ##################";
  print fmt("in bittorrent_peer_keep_alive, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_keep_alive end   ##################";
}

event bittorrent_peer_not_interested(c: connection, is_orig: bool)
{
  print "################### bittorrent_peer_not_interested start ##################";
  print fmt("in bittorrent_peer_not_interested, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_not_interested end   ##################";
}

event bittorrent_peer_piece(c: connection, is_orig: bool, index: count, begin: count, piece_length: count)
{
  print "################### bittorrent_peer_piece start ##################";
  print fmt("in bittorrent_peer_piece, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_piece end   ##################";
}

event bittorrent_peer_port(c: connection, is_orig: bool, listen_port: port)
{
  print "################### bittorrent_peer_port start ##################";
  print fmt("in bittorrent_peer_port, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_port end   ##################";
}

event bittorrent_peer_request(c: connection, is_orig: bool, index: count, begin: count, length: count)
{
  print "################### bittorrent_peer_request start ##################";
  print fmt("in bittorrent_peer_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_request end   ##################";
}

event bittorrent_peer_unchoke(c: connection, is_orig: bool)
{
  print "################### bittorrent_peer_unchoke start ##################";
  print fmt("in bittorrent_peer_unchoke, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_unchoke end   ##################";
}

event bittorrent_peer_unknown(c: connection, is_orig: bool, message_id: count, data: string)
{
  print "################### bittorrent_peer_unknown start ##################";
  print fmt("in bittorrent_peer_unknown, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_unknown end   ##################";
}

event bittorrent_peer_weird(c: connection, is_orig: bool, msg: string)
{
  print "################### bittorrent_peer_weird start ##################";
  print fmt("in bittorrent_peer_weird, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bittorrent_peer_weird end   ##################";
}

event bt_tracker_request(c: connection, uri: string, headers: bt_tracker_headers)
{
  print "################### bt_tracker_request start ##################";
  print fmt("in bt_tracker_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bt_tracker_request end   ##################";
}

event bt_tracker_response(c: connection, status: count, headers: bt_tracker_headers, peers: bittorrent_peer_set, benc: bittorrent_benc_dir)
{
  print "################### bt_tracker_response start ##################";
  print fmt("in bt_tracker_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bt_tracker_response end   ##################";
}

event bt_tracker_response_not_ok(c: connection, status: count, headers: bt_tracker_headers)
{
  print "################### bt_tracker_response_not_ok start ##################";
  print fmt("in bt_tracker_response_not_ok, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bt_tracker_response_not_ok end   ##################";
}

event bt_tracker_weird(c: connection, is_orig: bool, msg: string)
{
  print "################### bt_tracker_weird start ##################";
  print fmt("in bt_tracker_weird, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bt_tracker_weird end   ##################";
}

event conn_bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
{
  print "################### conn_bytes_threshold_crossed start ##################";
  print fmt("in conn_bytes_threshold_crossed, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### conn_bytes_threshold_crossed end   ##################";
}

event conn_packets_threshold_crossed(c: connection, threshold: count, is_orig: bool)
{
  print "################### conn_packets_threshold_crossed start ##################";
  print fmt("in conn_packets_threshold_crossed, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### conn_packets_threshold_crossed end   ##################";
}

event dce_rpc_bind(c: connection, fid: count, uuid: string, ver_major: count, ver_minor: count)
{
  print "################### dce_rpc_bind start ##################";
  print fmt("in dce_rpc_bind, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dce_rpc_bind end   ##################";
}

event dce_rpc_bind_ack(c: connection, fid: count, sec_addr: string)
{
  print "################### dce_rpc_bind_ack start ##################";
  print fmt("in dce_rpc_bind_ack, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dce_rpc_bind_ack end   ##################";
}

event dce_rpc_message(c: connection, is_orig: bool, fid: count, ptype_id: count, ptype: DCE_RPC::PType)
{
  print "################### dce_rpc_message start ##################";
  print fmt("in dce_rpc_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dce_rpc_message end   ##################";
}

event dce_rpc_request(c: connection, fid: count, opnum: count, stub_len: count)
{
  print "################### dce_rpc_request start ##################";
  print fmt("in dce_rpc_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dce_rpc_request end   ##################";
}

event dce_rpc_response(c: connection, fid: count, opnum: count, stub_len: count)
{
  print "################### dce_rpc_response start ##################";
  print fmt("in dce_rpc_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dce_rpc_response end   ##################";
}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
  print "################### dhcp_ack start ##################";
  print fmt("in dhcp_ack, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_ack end   ##################";
}

event dhcp_decline(c: connection, msg: dhcp_msg, host_name: string)
{
  print "################### dhcp_decline start ##################";
  print fmt("in dhcp_decline, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_decline end   ##################";
}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string)
{
  print "################### dhcp_discover start ##################";
  print fmt("in dhcp_discover, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_discover end   ##################";
}

event dhcp_inform(c: connection, msg: dhcp_msg, host_name: string)
{
  print "################### dhcp_inform start ##################";
  print fmt("in dhcp_inform, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_inform end   ##################";
}

event dhcp_nak(c: connection, msg: dhcp_msg, host_name: string)
{
  print "################### dhcp_nak start ##################";
  print fmt("in dhcp_nak, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_nak end   ##################";
}

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
  print "################### dhcp_offer start ##################";
  print fmt("in dhcp_offer, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_offer end   ##################";
}

event dhcp_release(c: connection, msg: dhcp_msg, host_name: string)
{
  print "################### dhcp_release start ##################";
  print fmt("in dhcp_release, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_release end   ##################";
}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string)
{
  print "################### dhcp_request start ##################";
  print fmt("in dhcp_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dhcp_request end   ##################";
}

event dnp3_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, value: count)
{
  print "################### dnp3_analog_input_16wFlag start ##################";
  print fmt("in dnp3_analog_input_16wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_16wFlag end   ##################";
}

event dnp3_analog_input_16woFlag(c: connection, is_orig: bool, value: count)
{
  print "################### dnp3_analog_input_16woFlag start ##################";
  print fmt("in dnp3_analog_input_16woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_16woFlag end   ##################";
}

event dnp3_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, value: count)
{
  print "################### dnp3_analog_input_32wFlag start ##################";
  print fmt("in dnp3_analog_input_32wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_32wFlag end   ##################";
}

event dnp3_analog_input_32woFlag(c: connection, is_orig: bool, value: count)
{
  print "################### dnp3_analog_input_32woFlag start ##################";
  print fmt("in dnp3_analog_input_32woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_32woFlag end   ##################";
}

event dnp3_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
{
  print "################### dnp3_analog_input_DPwFlag start ##################";
  print fmt("in dnp3_analog_input_DPwFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_DPwFlag end   ##################";
}

event dnp3_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, value: count)
{
  print "################### dnp3_analog_input_SPwFlag start ##################";
  print fmt("in dnp3_analog_input_SPwFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_SPwFlag end   ##################";
}

event dnp3_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
{
  print "################### dnp3_analog_input_event_16wTime start ##################";
  print fmt("in dnp3_analog_input_event_16wTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_16wTime end   ##################";
}

event dnp3_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, value: count)
{
  print "################### dnp3_analog_input_event_16woTime start ##################";
  print fmt("in dnp3_analog_input_event_16woTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_16woTime end   ##################";
}

event dnp3_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
{
  print "################### dnp3_analog_input_event_32wTime start ##################";
  print fmt("in dnp3_analog_input_event_32wTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_32wTime end   ##################";
}

event dnp3_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, value: count)
{
  print "################### dnp3_analog_input_event_32woTime start ##################";
  print fmt("in dnp3_analog_input_event_32woTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_32woTime end   ##################";
}

event dnp3_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: count)
{
  print "################### dnp3_analog_input_event_DPwTime start ##################";
  print fmt("in dnp3_analog_input_event_DPwTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_DPwTime end   ##################";
}

event dnp3_analog_input_event_DPwoTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
{
  print "################### dnp3_analog_input_event_DPwoTime start ##################";
  print fmt("in dnp3_analog_input_event_DPwoTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_DPwoTime end   ##################";
}

event dnp3_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
{
  print "################### dnp3_analog_input_event_SPwTime start ##################";
  print fmt("in dnp3_analog_input_event_SPwTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_SPwTime end   ##################";
}

event dnp3_analog_input_event_SPwoTime(c: connection, is_orig: bool, flag: count, value: count)
{
  print "################### dnp3_analog_input_event_SPwoTime start ##################";
  print fmt("in dnp3_analog_input_event_SPwoTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_analog_input_event_SPwoTime end   ##################";
}

event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)
{
  print "################### dnp3_application_request_header start ##################";
  print fmt("in dnp3_application_request_header, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_application_request_header end   ##################";
}

event dnp3_application_response_header(c: connection, is_orig: bool, application: count, fc: count, iin: count)
{
  print "################### dnp3_application_response_header start ##################";
  print fmt("in dnp3_application_response_header, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_application_response_header end   ##################";
}

event dnp3_attribute_common(c: connection, is_orig: bool, data_type_code: count, leng: count, attribute_obj: string)
{
  print "################### dnp3_attribute_common start ##################";
  print fmt("in dnp3_attribute_common, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_attribute_common end   ##################";
}

event dnp3_counter_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
  print "################### dnp3_counter_16wFlag start ##################";
  print fmt("in dnp3_counter_16wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_counter_16wFlag end   ##################";
}

event dnp3_counter_16woFlag(c: connection, is_orig: bool, count_value: count)
{
  print "################### dnp3_counter_16woFlag start ##################";
  print fmt("in dnp3_counter_16woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_counter_16woFlag end   ##################";
}

event dnp3_counter_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
  print "################### dnp3_counter_32wFlag start ##################";
  print fmt("in dnp3_counter_32wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_counter_32wFlag end   ##################";
}

event dnp3_counter_32woFlag(c: connection, is_orig: bool, count_value: count)
{
  print "################### dnp3_counter_32woFlag start ##################";
  print fmt("in dnp3_counter_32woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_counter_32woFlag end   ##################";
}

event dnp3_crob(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
{
  print "################### dnp3_crob start ##################";
  print fmt("in dnp3_crob, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_crob end   ##################";
}

event dnp3_debug_byte(c: connection, is_orig: bool, debug: string)
{
  print "################### dnp3_debug_byte start ##################";
  print fmt("in dnp3_debug_byte, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_debug_byte end   ##################";
}

event dnp3_file_transport(c: connection, is_orig: bool, file_handle: count, block_num: count, file_data: string)
{
  print "################### dnp3_file_transport start ##################";
  print fmt("in dnp3_file_transport, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_file_transport end   ##################";
}

event dnp3_frozen_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_16wFlag start ##################";
  print fmt("in dnp3_frozen_analog_input_16wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_16wFlag end   ##################";
}

event dnp3_frozen_analog_input_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
{
  print "################### dnp3_frozen_analog_input_16wTime start ##################";
  print fmt("in dnp3_frozen_analog_input_16wTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_16wTime end   ##################";
}

event dnp3_frozen_analog_input_16woFlag(c: connection, is_orig: bool, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_16woFlag start ##################";
  print fmt("in dnp3_frozen_analog_input_16woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_16woFlag end   ##################";
}

event dnp3_frozen_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_32wFlag start ##################";
  print fmt("in dnp3_frozen_analog_input_32wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_32wFlag end   ##################";
}

event dnp3_frozen_analog_input_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
{
  print "################### dnp3_frozen_analog_input_32wTime start ##################";
  print fmt("in dnp3_frozen_analog_input_32wTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_32wTime end   ##################";
}

event dnp3_frozen_analog_input_32woFlag(c: connection, is_orig: bool, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_32woFlag start ##################";
  print fmt("in dnp3_frozen_analog_input_32woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_32woFlag end   ##################";
}

event dnp3_frozen_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count)
{
  print "################### dnp3_frozen_analog_input_DPwFlag start ##################";
  print fmt("in dnp3_frozen_analog_input_DPwFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_DPwFlag end   ##################";
}

event dnp3_frozen_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_SPwFlag start ##################";
  print fmt("in dnp3_frozen_analog_input_SPwFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_SPwFlag end   ##################";
}

event dnp3_frozen_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
{
  print "################### dnp3_frozen_analog_input_event_16wTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_16wTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_16wTime end   ##################";
}

event dnp3_frozen_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_event_16woTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_16woTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_16woTime end   ##################";
}

event dnp3_frozen_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
{
  print "################### dnp3_frozen_analog_input_event_32wTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_32wTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_32wTime end   ##################";
}

event dnp3_frozen_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_event_32woTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_32woTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_32woTime end   ##################";
}

event dnp3_frozen_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count, time48: count)
{
  print "################### dnp3_frozen_analog_input_event_DPwTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_DPwTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_DPwTime end   ##################";
}

event dnp3_frozen_analog_input_event_DPwoTime(c: connection, is_orig: bool, flag: count, frozen_value_low: count, frozen_value_high: count)
{
  print "################### dnp3_frozen_analog_input_event_DPwoTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_DPwoTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_DPwoTime end   ##################";
}

event dnp3_frozen_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, frozen_value: count, time48: count)
{
  print "################### dnp3_frozen_analog_input_event_SPwTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_SPwTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_SPwTime end   ##################";
}

event dnp3_frozen_analog_input_event_SPwoTime(c: connection, is_orig: bool, flag: count, frozen_value: count)
{
  print "################### dnp3_frozen_analog_input_event_SPwoTime start ##################";
  print fmt("in dnp3_frozen_analog_input_event_SPwoTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_analog_input_event_SPwoTime end   ##################";
}

event dnp3_frozen_counter_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
  print "################### dnp3_frozen_counter_16wFlag start ##################";
  print fmt("in dnp3_frozen_counter_16wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_counter_16wFlag end   ##################";
}

event dnp3_frozen_counter_16wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: count)
{
  print "################### dnp3_frozen_counter_16wFlagTime start ##################";
  print fmt("in dnp3_frozen_counter_16wFlagTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_counter_16wFlagTime end   ##################";
}

event dnp3_frozen_counter_16woFlag(c: connection, is_orig: bool, count_value: count)
{
  print "################### dnp3_frozen_counter_16woFlag start ##################";
  print fmt("in dnp3_frozen_counter_16woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_counter_16woFlag end   ##################";
}

event dnp3_frozen_counter_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
  print "################### dnp3_frozen_counter_32wFlag start ##################";
  print fmt("in dnp3_frozen_counter_32wFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_counter_32wFlag end   ##################";
}

event dnp3_frozen_counter_32wFlagTime(c: connection, is_orig: bool, flag: count, count_value: count, time48: count)
{
  print "################### dnp3_frozen_counter_32wFlagTime start ##################";
  print fmt("in dnp3_frozen_counter_32wFlagTime, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_counter_32wFlagTime end   ##################";
}

event dnp3_frozen_counter_32woFlag(c: connection, is_orig: bool, count_value: count)
{
  print "################### dnp3_frozen_counter_32woFlag start ##################";
  print fmt("in dnp3_frozen_counter_32woFlag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_frozen_counter_32woFlag end   ##################";
}

event dnp3_header_block(c: connection, is_orig: bool, start: count, len: count, ctrl: count, dest_addr: count, src_addr: count)
{
  print "################### dnp3_header_block start ##################";
  print fmt("in dnp3_header_block, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_header_block end   ##################";
}

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
{
  print "################### dnp3_object_header start ##################";
  print fmt("in dnp3_object_header, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_object_header end   ##################";
}

event dnp3_object_prefix(c: connection, is_orig: bool, prefix_value: count)
{
  print "################### dnp3_object_prefix start ##################";
  print fmt("in dnp3_object_prefix, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_object_prefix end   ##################";
}

event dnp3_pcb(c: connection, is_orig: bool, control_code: count, count8: count, on_time: count, off_time: count, status_code: count)
{
  print "################### dnp3_pcb start ##################";
  print fmt("in dnp3_pcb, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_pcb end   ##################";
}

event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
{
  print "################### dnp3_response_data_object start ##################";
  print fmt("in dnp3_response_data_object, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dnp3_response_data_object end   ##################";
}

event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
  print "################### dns_A6_reply start ##################";
  print fmt("in dns_A6_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_A6_reply end   ##################";
}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
  print "################### dns_AAAA_reply start ##################";
  print fmt("in dns_AAAA_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_AAAA_reply end   ##################";
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
  print "################### dns_A_reply start ##################";
  print fmt("in dns_A_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_A_reply end   ##################";
}

event dns_CAA_reply(c: connection, msg: dns_msg, ans: dns_answer, flags: count, tag: string, value: string)
{
  print "################### dns_CAA_reply start ##################";
  print fmt("in dns_CAA_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_CAA_reply end   ##################";
}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
{
  print "################### dns_CNAME_reply start ##################";
  print fmt("in dns_CNAME_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_CNAME_reply end   ##################";
}

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
{
  print "################### dns_EDNS_addl start ##################";
  print fmt("in dns_EDNS_addl, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_EDNS_addl end   ##################";
}

event dns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer)
{
  print "################### dns_HINFO_reply start ##################";
  print fmt("in dns_HINFO_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_HINFO_reply end   ##################";
}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)
{
  print "################### dns_MX_reply start ##################";
  print fmt("in dns_MX_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_MX_reply end   ##################";
}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
{
  print "################### dns_NS_reply start ##################";
  print fmt("in dns_NS_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_NS_reply end   ##################";
}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
{
  print "################### dns_PTR_reply start ##################";
  print fmt("in dns_PTR_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_PTR_reply end   ##################";
}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
{
  print "################### dns_SOA_reply start ##################";
  print fmt("in dns_SOA_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_SOA_reply end   ##################";
}

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)
{
  print "################### dns_SRV_reply start ##################";
  print fmt("in dns_SRV_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_SRV_reply end   ##################";
}

event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
{
  print "################### dns_TSIG_addl start ##################";
  print fmt("in dns_TSIG_addl, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_TSIG_addl end   ##################";
}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
{
  print "################### dns_TXT_reply start ##################";
  print fmt("in dns_TXT_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_TXT_reply end   ##################";
}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
{
  print "################### dns_WKS_reply start ##################";
  print fmt("in dns_WKS_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_WKS_reply end   ##################";
}

event dns_end(c: connection, msg: dns_msg)
{
  print "################### dns_end start ##################";
  print fmt("in dns_end, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_end end   ##################";
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
  print "################### dns_message start ##################";
  print fmt("in dns_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_message end   ##################";
}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
  print "################### dns_query_reply start ##################";
  print fmt("in dns_query_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_query_reply end   ##################";
}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
  print "################### dns_rejected start ##################";
  print fmt("in dns_rejected, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_rejected end   ##################";
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
  print "################### dns_request start ##################";
  print fmt("in dns_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_request end   ##################";
}

event dns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer)
{
  print "################### dns_unknown_reply start ##################";
  print fmt("in dns_unknown_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### dns_unknown_reply end   ##################";
}

event file_transferred(c: connection, prefix: string, descr: string, mime_type: string)
{
  print "################### file_transferred start ##################";
  print fmt("in file_transferred, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### file_transferred end   ##################";
}

event finger_reply(c: connection, reply_line: string)
{
  print "################### finger_reply start ##################";
  print fmt("in finger_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### finger_reply end   ##################";
}

event finger_request(c: connection, full: bool, username: string, hostname: string)
{
  print "################### finger_request start ##################";
  print fmt("in finger_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### finger_request end   ##################";
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
{
  print "################### ftp_reply start ##################";
  print fmt("in ftp_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ftp_reply end   ##################";
}

event ftp_request(c: connection, command: string, arg: string)
{
  print "################### ftp_request start ##################";
  print fmt("in ftp_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ftp_request end   ##################";
}

event gnutella_binary_msg(c: connection, orig: bool, msg_type: count, ttl: count, hops: count, msg_len: count, payload: string, payload_len: count, trunc: bool, complete: bool)
{
  print "################### gnutella_binary_msg start ##################";
  print fmt("in gnutella_binary_msg, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gnutella_binary_msg end   ##################";
}

event gnutella_establish(c: connection)
{
  print "################### gnutella_establish start ##################";
  print fmt("in gnutella_establish, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gnutella_establish end   ##################";
}

event gnutella_http_notify(c: connection)
{
  print "################### gnutella_http_notify start ##################";
  print fmt("in gnutella_http_notify, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gnutella_http_notify end   ##################";
}

event gnutella_not_establish(c: connection)
{
  print "################### gnutella_not_establish start ##################";
  print fmt("in gnutella_not_establish, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gnutella_not_establish end   ##################";
}

event gnutella_partial_binary_msg(c: connection, orig: bool, msg: string, len: count)
{
  print "################### gnutella_partial_binary_msg start ##################";
  print fmt("in gnutella_partial_binary_msg, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gnutella_partial_binary_msg end   ##################";
}

event gnutella_text_msg(c: connection, orig: bool, headers: string)
{
  print "################### gnutella_text_msg start ##################";
  print fmt("in gnutella_text_msg, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gnutella_text_msg end   ##################";
}

event gssapi_neg_result(c: connection, state: count)
{
  print "################### gssapi_neg_result start ##################";
  print fmt("in gssapi_neg_result, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gssapi_neg_result end   ##################";
}

event gtpv1_create_pdp_ctx_request(c: connection, hdr: gtpv1_hdr, elements: gtp_create_pdp_ctx_request_elements)
{
  print "################### gtpv1_create_pdp_ctx_request start ##################";
  print fmt("in gtpv1_create_pdp_ctx_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_create_pdp_ctx_request end   ##################";
}

event gtpv1_create_pdp_ctx_response(c: connection, hdr: gtpv1_hdr, elements: gtp_create_pdp_ctx_response_elements)
{
  print "################### gtpv1_create_pdp_ctx_response start ##################";
  print fmt("in gtpv1_create_pdp_ctx_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_create_pdp_ctx_response end   ##################";
}

event gtpv1_delete_pdp_ctx_request(c: connection, hdr: gtpv1_hdr, elements: gtp_delete_pdp_ctx_request_elements)
{
  print "################### gtpv1_delete_pdp_ctx_request start ##################";
  print fmt("in gtpv1_delete_pdp_ctx_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_delete_pdp_ctx_request end   ##################";
}

event gtpv1_delete_pdp_ctx_response(c: connection, hdr: gtpv1_hdr, elements: gtp_delete_pdp_ctx_response_elements)
{
  print "################### gtpv1_delete_pdp_ctx_response start ##################";
  print fmt("in gtpv1_delete_pdp_ctx_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_delete_pdp_ctx_response end   ##################";
}

event gtpv1_g_pdu_packet(outer: connection, inner_gtp: gtpv1_hdr, inner_ip: pkt_hdr)
{
  print "################### gtpv1_g_pdu_packet start ##################";
  print fmt("in gtpv1_g_pdu_packet, outer$uid is %s, outer$id is %s, outer$history is %s", outer$uid, outer$id, outer$history);
  print "################### gtpv1_g_pdu_packet end   ##################";
}

event gtpv1_message(c: connection, hdr: gtpv1_hdr)
{
  print "################### gtpv1_message start ##################";
  print fmt("in gtpv1_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_message end   ##################";
}

event gtpv1_update_pdp_ctx_request(c: connection, hdr: gtpv1_hdr, elements: gtp_update_pdp_ctx_request_elements)
{
  print "################### gtpv1_update_pdp_ctx_request start ##################";
  print fmt("in gtpv1_update_pdp_ctx_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_update_pdp_ctx_request end   ##################";
}

event gtpv1_update_pdp_ctx_response(c: connection, hdr: gtpv1_hdr, elements: gtp_update_pdp_ctx_response_elements)
{
  print "################### gtpv1_update_pdp_ctx_response start ##################";
  print fmt("in gtpv1_update_pdp_ctx_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### gtpv1_update_pdp_ctx_response end   ##################";
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
  print "################### http_all_headers start ##################";
  print fmt("in http_all_headers, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_all_headers end   ##################";
}

event http_begin_entity(c: connection, is_orig: bool)
{
  print "################### http_begin_entity start ##################";
  print fmt("in http_begin_entity, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_begin_entity end   ##################";
}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string)
{
  print "################### http_content_type start ##################";
  print fmt("in http_content_type, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_content_type end   ##################";
}

event http_end_entity(c: connection, is_orig: bool)
{
  print "################### http_end_entity start ##################";
  print fmt("in http_end_entity, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_end_entity end   ##################";
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
  print "################### http_entity_data start ##################";
  print fmt("in http_entity_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_entity_data end   ##################";
}

event http_event(c: connection, event_type: string, detail: string)
{
  print "################### http_event start ##################";
  print fmt("in http_event, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_event end   ##################";
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
  print "################### http_header start ##################";
  print fmt("in http_header, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_header end   ##################";
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
  print "################### http_message_done start ##################";
  print fmt("in http_message_done, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_message_done end   ##################";
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
  print "################### http_reply start ##################";
  print fmt("in http_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_reply end   ##################";
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
  print "################### http_request start ##################";
  print fmt("in http_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_request end   ##################";
}

event http_stats(c: connection, stats: http_stats_rec)
{
  print "################### http_stats start ##################";
  print fmt("in http_stats, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### http_stats end   ##################";
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
  print "################### icmp_echo_reply start ##################";
  print fmt("in icmp_echo_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_echo_reply end   ##################";
}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
  print "################### icmp_echo_request start ##################";
  print fmt("in icmp_echo_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_echo_request end   ##################";
}

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
{
  print "################### icmp_error_message start ##################";
  print fmt("in icmp_error_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_error_message end   ##################";
}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
{
  print "################### icmp_neighbor_advertisement start ##################";
  print fmt("in icmp_neighbor_advertisement, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_neighbor_advertisement end   ##################";
}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options)
{
  print "################### icmp_neighbor_solicitation start ##################";
  print fmt("in icmp_neighbor_solicitation, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_neighbor_solicitation end   ##################";
}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
{
  print "################### icmp_packet_too_big start ##################";
  print fmt("in icmp_packet_too_big, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_packet_too_big end   ##################";
}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
{
  print "################### icmp_parameter_problem start ##################";
  print fmt("in icmp_parameter_problem, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_parameter_problem end   ##################";
}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options)
{
  print "################### icmp_redirect start ##################";
  print fmt("in icmp_redirect, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_redirect end   ##################";
}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options)
{
  print "################### icmp_router_advertisement start ##################";
  print fmt("in icmp_router_advertisement, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_router_advertisement end   ##################";
}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options)
{
  print "################### icmp_router_solicitation start ##################";
  print fmt("in icmp_router_solicitation, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_router_solicitation end   ##################";
}

event icmp_sent(c: connection, icmp: icmp_conn)
{
  print "################### icmp_sent start ##################";
  print fmt("in icmp_sent, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_sent end   ##################";
}

event icmp_sent_payload(c: connection, icmp: icmp_conn, payload: string)
{
  print "################### icmp_sent_payload start ##################";
  print fmt("in icmp_sent_payload, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_sent_payload end   ##################";
}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
{
  print "################### icmp_time_exceeded start ##################";
  print fmt("in icmp_time_exceeded, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_time_exceeded end   ##################";
}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
{
  print "################### icmp_unreachable start ##################";
  print fmt("in icmp_unreachable, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### icmp_unreachable end   ##################";
}

event ident_error(c: connection, lport: port, rport: port, line: string)
{
  print "################### ident_error start ##################";
  print fmt("in ident_error, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ident_error end   ##################";
}

event ident_reply(c: connection, lport: port, rport: port, user_id: string, system: string)
{
  print "################### ident_reply start ##################";
  print fmt("in ident_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ident_reply end   ##################";
}

event ident_request(c: connection, lport: port, rport: port)
{
  print "################### ident_request start ##################";
  print fmt("in ident_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ident_request end   ##################";
}

event imap_capabilities(c: connection, capabilities: string_vec)
{
  print "################### imap_capabilities start ##################";
  print fmt("in imap_capabilities, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### imap_capabilities end   ##################";
}

event imap_starttls(c: connection)
{
  print "################### imap_starttls start ##################";
  print fmt("in imap_starttls, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### imap_starttls end   ##################";
}

event irc_channel_info(c: connection, is_orig: bool, chans: count)
{
  print "################### irc_channel_info start ##################";
  print fmt("in irc_channel_info, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_channel_info end   ##################";
}

event irc_channel_topic(c: connection, is_orig: bool, channel: string, topic: string)
{
  print "################### irc_channel_topic start ##################";
  print fmt("in irc_channel_topic, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_channel_topic end   ##################";
}

event irc_dcc_message(c: connection, is_orig: bool, prefix: string, target: string, dcc_type: string, argument: string, address: addr, dest_port: count, size: count)
{
  print "################### irc_dcc_message start ##################";
  print fmt("in irc_dcc_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_dcc_message end   ##################";
}

event irc_error_message(c: connection, is_orig: bool, prefix: string, message: string)
{
  print "################### irc_error_message start ##################";
  print fmt("in irc_error_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_error_message end   ##################";
}

event irc_global_users(c: connection, is_orig: bool, prefix: string, msg: string)
{
  print "################### irc_global_users start ##################";
  print fmt("in irc_global_users, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_global_users end   ##################";
}

event irc_invalid_nick(c: connection, is_orig: bool)
{
  print "################### irc_invalid_nick start ##################";
  print fmt("in irc_invalid_nick, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_invalid_nick end   ##################";
}

event irc_invite_message(c: connection, is_orig: bool, prefix: string, nickname: string, channel: string)
{
  print "################### irc_invite_message start ##################";
  print fmt("in irc_invite_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_invite_message end   ##################";
}

event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list)
{
  print "################### irc_join_message start ##################";
  print fmt("in irc_join_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_join_message end   ##################";
}

event irc_kick_message(c: connection, is_orig: bool, prefix: string, chans: string, users: string, comment: string)
{
  print "################### irc_kick_message start ##################";
  print fmt("in irc_kick_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_kick_message end   ##################";
}

event irc_message(c: connection, is_orig: bool, prefix: string, command: string, message: string)
{
  print "################### irc_message start ##################";
  print fmt("in irc_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_message end   ##################";
}

event irc_mode_message(c: connection, is_orig: bool, prefix: string, params: string)
{
  print "################### irc_mode_message start ##################";
  print fmt("in irc_mode_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_mode_message end   ##################";
}

event irc_names_info(c: connection, is_orig: bool, c_type: string, channel: string, users: string_set)
{
  print "################### irc_names_info start ##################";
  print fmt("in irc_names_info, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_names_info end   ##################";
}

event irc_network_info(c: connection, is_orig: bool, users: count, services: count, servers: count)
{
  print "################### irc_network_info start ##################";
  print fmt("in irc_network_info, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_network_info end   ##################";
}

event irc_nick_message(c: connection, is_orig: bool, who: string, newnick: string)
{
  print "################### irc_nick_message start ##################";
  print fmt("in irc_nick_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_nick_message end   ##################";
}

event irc_notice_message(c: connection, is_orig: bool, source: string, target: string, message: string)
{
  print "################### irc_notice_message start ##################";
  print fmt("in irc_notice_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_notice_message end   ##################";
}

event irc_oper_message(c: connection, is_orig: bool, user: string, password: string)
{
  print "################### irc_oper_message start ##################";
  print fmt("in irc_oper_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_oper_message end   ##################";
}

event irc_oper_response(c: connection, is_orig: bool, got_oper: bool)
{
  print "################### irc_oper_response start ##################";
  print fmt("in irc_oper_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_oper_response end   ##################";
}

event irc_part_message(c: connection, is_orig: bool, nick: string, chans: string_set, message: string)
{
  print "################### irc_part_message start ##################";
  print fmt("in irc_part_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_part_message end   ##################";
}

event irc_password_message(c: connection, is_orig: bool, password: string)
{
  print "################### irc_password_message start ##################";
  print fmt("in irc_password_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_password_message end   ##################";
}

event irc_privmsg_message(c: connection, is_orig: bool, source: string, target: string, message: string)
{
  print "################### irc_privmsg_message start ##################";
  print fmt("in irc_privmsg_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_privmsg_message end   ##################";
}

event irc_quit_message(c: connection, is_orig: bool, nick: string, message: string)
{
  print "################### irc_quit_message start ##################";
  print fmt("in irc_quit_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_quit_message end   ##################";
}

event irc_reply(c: connection, is_orig: bool, prefix: string, code: count, params: string)
{
  print "################### irc_reply start ##################";
  print fmt("in irc_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_reply end   ##################";
}

event irc_request(c: connection, is_orig: bool, prefix: string, command: string, arguments: string)
{
  print "################### irc_request start ##################";
  print fmt("in irc_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_request end   ##################";
}

event irc_server_info(c: connection, is_orig: bool, users: count, services: count, servers: count)
{
  print "################### irc_server_info start ##################";
  print fmt("in irc_server_info, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_server_info end   ##################";
}

event irc_squery_message(c: connection, is_orig: bool, source: string, target: string, message: string)
{
  print "################### irc_squery_message start ##################";
  print fmt("in irc_squery_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_squery_message end   ##################";
}

event irc_squit_message(c: connection, is_orig: bool, prefix: string, server: string, message: string)
{
  print "################### irc_squit_message start ##################";
  print fmt("in irc_squit_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_squit_message end   ##################";
}

event irc_starttls(c: connection)
{
  print "################### irc_starttls start ##################";
  print fmt("in irc_starttls, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_starttls end   ##################";
}

event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string)
{
  print "################### irc_user_message start ##################";
  print fmt("in irc_user_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_user_message end   ##################";
}

event irc_who_line(c: connection, is_orig: bool, target_nick: string, channel: string, user: string, host: string, server: string, nick: string, params: string, hops: count, real_name: string)
{
  print "################### irc_who_line start ##################";
  print fmt("in irc_who_line, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_who_line end   ##################";
}

event irc_who_message(c: connection, is_orig: bool, mask: string, oper: bool)
{
  print "################### irc_who_message start ##################";
  print fmt("in irc_who_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_who_message end   ##################";
}

event irc_whois_channel_line(c: connection, is_orig: bool, nick: string, chans: string_set)
{
  print "################### irc_whois_channel_line start ##################";
  print fmt("in irc_whois_channel_line, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_whois_channel_line end   ##################";
}

event irc_whois_message(c: connection, is_orig: bool, server: string, users: string)
{
  print "################### irc_whois_message start ##################";
  print fmt("in irc_whois_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_whois_message end   ##################";
}

event irc_whois_operator_line(c: connection, is_orig: bool, nick: string)
{
  print "################### irc_whois_operator_line start ##################";
  print fmt("in irc_whois_operator_line, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_whois_operator_line end   ##################";
}

event irc_whois_user_line(c: connection, is_orig: bool, nick: string, user: string, host: string, real_name: string)
{
  print "################### irc_whois_user_line start ##################";
  print fmt("in irc_whois_user_line, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### irc_whois_user_line end   ##################";
}

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
{
  print "################### krb_ap_request start ##################";
  print fmt("in krb_ap_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_ap_request end   ##################";
}

event krb_ap_response(c: connection)
{
  print "################### krb_ap_response start ##################";
  print fmt("in krb_ap_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_ap_response end   ##################";
}

event krb_as_request(c: connection, msg: KRB::KDC_Request)
{
  print "################### krb_as_request start ##################";
  print fmt("in krb_as_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_as_request end   ##################";
}

event krb_as_response(c: connection, msg: KRB::KDC_Response)
{
  print "################### krb_as_response start ##################";
  print fmt("in krb_as_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_as_response end   ##################";
}

event krb_cred(c: connection, is_orig: bool, tickets: KRB::Ticket_Vector)
{
  print "################### krb_cred start ##################";
  print fmt("in krb_cred, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_cred end   ##################";
}

event krb_error(c: connection, msg: KRB::Error_Msg)
{
  print "################### krb_error start ##################";
  print fmt("in krb_error, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_error end   ##################";
}

event krb_priv(c: connection, is_orig: bool)
{
  print "################### krb_priv start ##################";
  print fmt("in krb_priv, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_priv end   ##################";
}

event krb_safe(c: connection, is_orig: bool, msg: KRB::SAFE_Msg)
{
  print "################### krb_safe start ##################";
  print fmt("in krb_safe, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_safe end   ##################";
}

event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
{
  print "################### krb_tgs_request start ##################";
  print fmt("in krb_tgs_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_tgs_request end   ##################";
}

event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
{
  print "################### krb_tgs_response start ##################";
  print fmt("in krb_tgs_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### krb_tgs_response end   ##################";
}

event activating_encryption(c: connection)
{
  print "################### activating_encryption start ##################";
  print fmt("in activating_encryption, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### activating_encryption end   ##################";
}

event authentication_accepted(name: string, c: connection)
{
  print "################### authentication_accepted start ##################";
  print fmt("in authentication_accepted, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### authentication_accepted end   ##################";
}

event authentication_rejected(name: string, c: connection)
{
  print "################### authentication_rejected start ##################";
  print fmt("in authentication_rejected, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### authentication_rejected end   ##################";
}

event authentication_skipped(c: connection)
{
  print "################### authentication_skipped start ##################";
  print fmt("in authentication_skipped, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### authentication_skipped end   ##################";
}

event bad_option(c: connection)
{
  print "################### bad_option start ##################";
  print fmt("in bad_option, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bad_option end   ##################";
}

event bad_option_termination(c: connection)
{
  print "################### bad_option_termination start ##################";
  print fmt("in bad_option_termination, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### bad_option_termination end   ##################";
}

event inconsistent_option(c: connection)
{
  print "################### inconsistent_option start ##################";
  print fmt("in inconsistent_option, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### inconsistent_option end   ##################";
}

event login_confused(c: connection, msg: string, line: string)
{
  print "################### login_confused start ##################";
  print fmt("in login_confused, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_confused end   ##################";
}

event login_confused_text(c: connection, line: string)
{
  print "################### login_confused_text start ##################";
  print fmt("in login_confused_text, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_confused_text end   ##################";
}

event login_display(c: connection, display: string)
{
  print "################### login_display start ##################";
  print fmt("in login_display, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_display end   ##################";
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string)
{
  print "################### login_failure start ##################";
  print fmt("in login_failure, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_failure end   ##################";
}

event login_input_line(c: connection, line: string)
{
  print "################### login_input_line start ##################";
  print fmt("in login_input_line, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_input_line end   ##################";
}

event login_output_line(c: connection, line: string)
{
  print "################### login_output_line start ##################";
  print fmt("in login_output_line, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_output_line end   ##################";
}

event login_prompt(c: connection, prompt: string)
{
  print "################### login_prompt start ##################";
  print fmt("in login_prompt, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_prompt end   ##################";
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
  print "################### login_success start ##################";
  print fmt("in login_success, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_success end   ##################";
}

event login_terminal(c: connection, terminal: string)
{
  print "################### login_terminal start ##################";
  print fmt("in login_terminal, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### login_terminal end   ##################";
}

event rsh_reply(c: connection, client_user: string, server_user: string, line: string)
{
  print "################### rsh_reply start ##################";
  print fmt("in rsh_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rsh_reply end   ##################";
}

event rsh_request(c: connection, client_user: string, server_user: string, line: string, new_session: bool)
{
  print "################### rsh_request start ##################";
  print fmt("in rsh_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rsh_request end   ##################";
}

event mime_all_data(c: connection, length: count, data: string)
{
  print "################### mime_all_data start ##################";
  print fmt("in mime_all_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_all_data end   ##################";
}

event mime_all_headers(c: connection, hlist: mime_header_list)
{
  print "################### mime_all_headers start ##################";
  print fmt("in mime_all_headers, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_all_headers end   ##################";
}

event mime_begin_entity(c: connection)
{
  print "################### mime_begin_entity start ##################";
  print fmt("in mime_begin_entity, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_begin_entity end   ##################";
}

event mime_content_hash(c: connection, content_len: count, hash_value: string)
{
  print "################### mime_content_hash start ##################";
  print fmt("in mime_content_hash, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_content_hash end   ##################";
}

event mime_end_entity(c: connection)
{
  print "################### mime_end_entity start ##################";
  print fmt("in mime_end_entity, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_end_entity end   ##################";
}

event mime_entity_data(c: connection, length: count, data: string)
{
  print "################### mime_entity_data start ##################";
  print fmt("in mime_entity_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_entity_data end   ##################";
}

event mime_event(c: connection, event_type: string, detail: string)
{
  print "################### mime_event start ##################";
  print fmt("in mime_event, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_event end   ##################";
}

event mime_one_header(c: connection, h: mime_header_rec)
{
  print "################### mime_one_header start ##################";
  print fmt("in mime_one_header, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_one_header end   ##################";
}

event mime_segment_data(c: connection, length: count, data: string)
{
  print "################### mime_segment_data start ##################";
  print fmt("in mime_segment_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mime_segment_data end   ##################";
}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
{
  print "################### modbus_exception start ##################";
  print fmt("in modbus_exception, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_exception end   ##################";
}

event modbus_mask_write_register_request(c: connection, headers: ModbusHeaders, address: count, and_mask: count, or_mask: count)
{
  print "################### modbus_mask_write_register_request start ##################";
  print fmt("in modbus_mask_write_register_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_mask_write_register_request end   ##################";
}

event modbus_mask_write_register_response(c: connection, headers: ModbusHeaders, address: count, and_mask: count, or_mask: count)
{
  print "################### modbus_mask_write_register_response start ##################";
  print fmt("in modbus_mask_write_register_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_mask_write_register_response end   ##################";
}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
  print "################### modbus_message start ##################";
  print fmt("in modbus_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_message end   ##################";
}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
  print "################### modbus_read_coils_request start ##################";
  print fmt("in modbus_read_coils_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_coils_request end   ##################";
}

event modbus_read_coils_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
  print "################### modbus_read_coils_response start ##################";
  print fmt("in modbus_read_coils_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_coils_response end   ##################";
}

event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
  print "################### modbus_read_discrete_inputs_request start ##################";
  print fmt("in modbus_read_discrete_inputs_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_discrete_inputs_request end   ##################";
}

event modbus_read_discrete_inputs_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
  print "################### modbus_read_discrete_inputs_response start ##################";
  print fmt("in modbus_read_discrete_inputs_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_discrete_inputs_response end   ##################";
}

event modbus_read_fifo_queue_request(c: connection, headers: ModbusHeaders, start_address: count)
{
  print "################### modbus_read_fifo_queue_request start ##################";
  print fmt("in modbus_read_fifo_queue_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_fifo_queue_request end   ##################";
}

event modbus_read_fifo_queue_response(c: connection, headers: ModbusHeaders, fifos: ModbusRegisters)
{
  print "################### modbus_read_fifo_queue_response start ##################";
  print fmt("in modbus_read_fifo_queue_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_fifo_queue_response end   ##################";
}

event modbus_read_file_record_request(c: connection, headers: ModbusHeaders)
{
  print "################### modbus_read_file_record_request start ##################";
  print fmt("in modbus_read_file_record_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_file_record_request end   ##################";
}

event modbus_read_file_record_response(c: connection, headers: ModbusHeaders)
{
  print "################### modbus_read_file_record_response start ##################";
  print fmt("in modbus_read_file_record_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_file_record_response end   ##################";
}

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
  print "################### modbus_read_holding_registers_request start ##################";
  print fmt("in modbus_read_holding_registers_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_holding_registers_request end   ##################";
}

event modbus_read_holding_registers_response(c: connection, headers: ModbusHeaders, registers: ModbusRegisters)
{
  print "################### modbus_read_holding_registers_response start ##################";
  print fmt("in modbus_read_holding_registers_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_holding_registers_response end   ##################";
}

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
  print "################### modbus_read_input_registers_request start ##################";
  print fmt("in modbus_read_input_registers_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_input_registers_request end   ##################";
}

event modbus_read_input_registers_response(c: connection, headers: ModbusHeaders, registers: ModbusRegisters)
{
  print "################### modbus_read_input_registers_response start ##################";
  print fmt("in modbus_read_input_registers_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_input_registers_response end   ##################";
}

event modbus_read_write_multiple_registers_request(c: connection, headers: ModbusHeaders, read_start_address: count, read_quantity: count, write_start_address: count, write_registers: ModbusRegisters)
{
  print "################### modbus_read_write_multiple_registers_request start ##################";
  print fmt("in modbus_read_write_multiple_registers_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_write_multiple_registers_request end   ##################";
}

event modbus_read_write_multiple_registers_response(c: connection, headers: ModbusHeaders, written_registers: ModbusRegisters)
{
  print "################### modbus_read_write_multiple_registers_response start ##################";
  print fmt("in modbus_read_write_multiple_registers_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_read_write_multiple_registers_response end   ##################";
}

event modbus_write_file_record_request(c: connection, headers: ModbusHeaders)
{
  print "################### modbus_write_file_record_request start ##################";
  print fmt("in modbus_write_file_record_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_file_record_request end   ##################";
}

event modbus_write_file_record_response(c: connection, headers: ModbusHeaders)
{
  print "################### modbus_write_file_record_response start ##################";
  print fmt("in modbus_write_file_record_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_file_record_response end   ##################";
}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders, start_address: count, coils: ModbusCoils)
{
  print "################### modbus_write_multiple_coils_request start ##################";
  print fmt("in modbus_write_multiple_coils_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_multiple_coils_request end   ##################";
}

event modbus_write_multiple_coils_response(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
  print "################### modbus_write_multiple_coils_response start ##################";
  print fmt("in modbus_write_multiple_coils_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_multiple_coils_response end   ##################";
}

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
{
  print "################### modbus_write_multiple_registers_request start ##################";
  print fmt("in modbus_write_multiple_registers_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_multiple_registers_request end   ##################";
}

event modbus_write_multiple_registers_response(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
  print "################### modbus_write_multiple_registers_response start ##################";
  print fmt("in modbus_write_multiple_registers_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_multiple_registers_response end   ##################";
}

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, address: count, value: bool)
{
  print "################### modbus_write_single_coil_request start ##################";
  print fmt("in modbus_write_single_coil_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_single_coil_request end   ##################";
}

event modbus_write_single_coil_response(c: connection, headers: ModbusHeaders, address: count, value: bool)
{
  print "################### modbus_write_single_coil_response start ##################";
  print fmt("in modbus_write_single_coil_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_single_coil_response end   ##################";
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count)
{
  print "################### modbus_write_single_register_request start ##################";
  print fmt("in modbus_write_single_register_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_single_register_request end   ##################";
}

event modbus_write_single_register_response(c: connection, headers: ModbusHeaders, address: count, value: count)
{
  print "################### modbus_write_single_register_response start ##################";
  print fmt("in modbus_write_single_register_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### modbus_write_single_register_response end   ##################";
}

event mysql_command_request(c: connection, command: count, arg: string)
{
  print "################### mysql_command_request start ##################";
  print fmt("in mysql_command_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mysql_command_request end   ##################";
}

event mysql_error(c: connection, code: count, msg: string)
{
  print "################### mysql_error start ##################";
  print fmt("in mysql_error, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mysql_error end   ##################";
}

event mysql_handshake(c: connection, username: string)
{
  print "################### mysql_handshake start ##################";
  print fmt("in mysql_handshake, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mysql_handshake end   ##################";
}

event mysql_ok(c: connection, affected_rows: count)
{
  print "################### mysql_ok start ##################";
  print fmt("in mysql_ok, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mysql_ok end   ##################";
}

event mysql_server_version(c: connection, ver: string)
{
  print "################### mysql_server_version start ##################";
  print fmt("in mysql_server_version, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### mysql_server_version end   ##################";
}

event ncp_reply(c: connection, frame_type: count, length: count, req_frame: count, req_func: count, completion_code: count)
{
  print "################### ncp_reply start ##################";
  print fmt("in ncp_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ncp_reply end   ##################";
}

event ncp_request(c: connection, frame_type: count, length: count, func: count)
{
  print "################### ncp_request start ##################";
  print fmt("in ncp_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ncp_request end   ##################";
}

event netbios_session_accepted(c: connection, msg: string)
{
  print "################### netbios_session_accepted start ##################";
  print fmt("in netbios_session_accepted, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_accepted end   ##################";
}

event netbios_session_keepalive(c: connection, msg: string)
{
  print "################### netbios_session_keepalive start ##################";
  print fmt("in netbios_session_keepalive, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_keepalive end   ##################";
}

event netbios_session_message(c: connection, is_orig: bool, msg_type: count, data_len: count)
{
  print "################### netbios_session_message start ##################";
  print fmt("in netbios_session_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_message end   ##################";
}

event netbios_session_raw_message(c: connection, is_orig: bool, msg: string)
{
  print "################### netbios_session_raw_message start ##################";
  print fmt("in netbios_session_raw_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_raw_message end   ##################";
}

event netbios_session_rejected(c: connection, msg: string)
{
  print "################### netbios_session_rejected start ##################";
  print fmt("in netbios_session_rejected, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_rejected end   ##################";
}

event netbios_session_request(c: connection, msg: string)
{
  print "################### netbios_session_request start ##################";
  print fmt("in netbios_session_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_request end   ##################";
}

event netbios_session_ret_arg_resp(c: connection, msg: string)
{
  print "################### netbios_session_ret_arg_resp start ##################";
  print fmt("in netbios_session_ret_arg_resp, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### netbios_session_ret_arg_resp end   ##################";
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
  print "################### ntlm_authenticate start ##################";
  print fmt("in ntlm_authenticate, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ntlm_authenticate end   ##################";
}

event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
{
  print "################### ntlm_challenge start ##################";
  print fmt("in ntlm_challenge, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ntlm_challenge end   ##################";
}

event ntlm_negotiate(c: connection, negotiate: NTLM::Negotiate)
{
  print "################### ntlm_negotiate start ##################";
  print fmt("in ntlm_negotiate, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ntlm_negotiate end   ##################";
}

event ntp_message(u: connection, msg: ntp_msg, excess: string)
{
  print "################### ntp_message start ##################";
  print fmt("in ntp_message, u$uid is %s, u$id is %s, u$history is %s", u$uid, u$id, u$history);
  print "################### ntp_message end   ##################";
}

event pop3_data(c: connection, is_orig: bool, data: string)
{
  print "################### pop3_data start ##################";
  print fmt("in pop3_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_data end   ##################";
}

event pop3_login_failure(c: connection, is_orig: bool, user: string, password: string)
{
  print "################### pop3_login_failure start ##################";
  print fmt("in pop3_login_failure, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_login_failure end   ##################";
}

event pop3_login_success(c: connection, is_orig: bool, user: string, password: string)
{
  print "################### pop3_login_success start ##################";
  print fmt("in pop3_login_success, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_login_success end   ##################";
}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
{
  print "################### pop3_reply start ##################";
  print fmt("in pop3_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_reply end   ##################";
}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
  print "################### pop3_request start ##################";
  print fmt("in pop3_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_request end   ##################";
}

event pop3_starttls(c: connection)
{
  print "################### pop3_starttls start ##################";
  print fmt("in pop3_starttls, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_starttls end   ##################";
}

event pop3_unexpected(c: connection, is_orig: bool, msg: string, detail: string)
{
  print "################### pop3_unexpected start ##################";
  print fmt("in pop3_unexpected, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### pop3_unexpected end   ##################";
}

event radius_attribute(c: connection, attr_type: count, value: string)
{
  print "################### radius_attribute start ##################";
  print fmt("in radius_attribute, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### radius_attribute end   ##################";
}

event radius_message(c: connection, result: RADIUS::Message)
{
  print "################### radius_message start ##################";
  print fmt("in radius_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### radius_message end   ##################";
}

event rdp_begin_encryption(c: connection, security_protocol: count)
{
  print "################### rdp_begin_encryption start ##################";
  print fmt("in rdp_begin_encryption, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_begin_encryption end   ##################";
}

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData)
{
  print "################### rdp_client_core_data start ##################";
  print fmt("in rdp_client_core_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_client_core_data end   ##################";
}

event rdp_connect_request(c: connection, cookie: string)
{
  print "################### rdp_connect_request start ##################";
  print fmt("in rdp_connect_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_connect_request end   ##################";
}

event rdp_gcc_server_create_response(c: connection, result: count)
{
  print "################### rdp_gcc_server_create_response start ##################";
  print fmt("in rdp_gcc_server_create_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_gcc_server_create_response end   ##################";
}

event rdp_negotiation_failure(c: connection, failure_code: count)
{
  print "################### rdp_negotiation_failure start ##################";
  print fmt("in rdp_negotiation_failure, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_negotiation_failure end   ##################";
}

event rdp_negotiation_response(c: connection, security_protocol: count)
{
  print "################### rdp_negotiation_response start ##################";
  print fmt("in rdp_negotiation_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_negotiation_response end   ##################";
}

event rdp_server_certificate(c: connection, cert_type: count, permanently_issued: bool)
{
  print "################### rdp_server_certificate start ##################";
  print fmt("in rdp_server_certificate, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_server_certificate end   ##################";
}

event rdp_server_security(c: connection, encryption_method: count, encryption_level: count)
{
  print "################### rdp_server_security start ##################";
  print fmt("in rdp_server_security, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rdp_server_security end   ##################";
}

event rfb_auth_result(c: connection, result: bool)
{
  print "################### rfb_auth_result start ##################";
  print fmt("in rfb_auth_result, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_auth_result end   ##################";
}

event rfb_authentication_type(c: connection, authtype: count)
{
  print "################### rfb_authentication_type start ##################";
  print fmt("in rfb_authentication_type, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_authentication_type end   ##################";
}

event rfb_client_version(c: connection, major_version: string, minor_version: string)
{
  print "################### rfb_client_version start ##################";
  print fmt("in rfb_client_version, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_client_version end   ##################";
}

event rfb_event(c: connection)
{
  print "################### rfb_event start ##################";
  print fmt("in rfb_event, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_event end   ##################";
}

event rfb_server_parameters(c: connection, name: string, width: count, height: count)
{
  print "################### rfb_server_parameters start ##################";
  print fmt("in rfb_server_parameters, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_server_parameters end   ##################";
}

event rfb_server_version(c: connection, major_version: string, minor_version: string)
{
  print "################### rfb_server_version start ##################";
  print fmt("in rfb_server_version, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_server_version end   ##################";
}

event rfb_share_flag(c: connection, flag: bool)
{
  print "################### rfb_share_flag start ##################";
  print fmt("in rfb_share_flag, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rfb_share_flag end   ##################";
}

event nfs_proc_create(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::newobj_reply_t)
{
  print "################### nfs_proc_create start ##################";
  print fmt("in nfs_proc_create, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_create end   ##################";
}

event nfs_proc_getattr(c: connection, info: NFS3::info_t, fh: string, attrs: NFS3::fattr_t)
{
  print "################### nfs_proc_getattr start ##################";
  print fmt("in nfs_proc_getattr, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_getattr end   ##################";
}

event nfs_proc_lookup(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::lookup_reply_t)
{
  print "################### nfs_proc_lookup start ##################";
  print fmt("in nfs_proc_lookup, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_lookup end   ##################";
}

event nfs_proc_mkdir(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::newobj_reply_t)
{
  print "################### nfs_proc_mkdir start ##################";
  print fmt("in nfs_proc_mkdir, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_mkdir end   ##################";
}

event nfs_proc_not_implemented(c: connection, info: NFS3::info_t, proc: NFS3::proc_t)
{
  print "################### nfs_proc_not_implemented start ##################";
  print fmt("in nfs_proc_not_implemented, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_not_implemented end   ##################";
}

event nfs_proc_null(c: connection, info: NFS3::info_t)
{
  print "################### nfs_proc_null start ##################";
  print fmt("in nfs_proc_null, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_null end   ##################";
}

event nfs_proc_read(c: connection, info: NFS3::info_t, req: NFS3::readargs_t, rep: NFS3::read_reply_t)
{
  print "################### nfs_proc_read start ##################";
  print fmt("in nfs_proc_read, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_read end   ##################";
}

event nfs_proc_readdir(c: connection, info: NFS3::info_t, req: NFS3::readdirargs_t, rep: NFS3::readdir_reply_t)
{
  print "################### nfs_proc_readdir start ##################";
  print fmt("in nfs_proc_readdir, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_readdir end   ##################";
}

event nfs_proc_readlink(c: connection, info: NFS3::info_t, fh: string, rep: NFS3::readlink_reply_t)
{
  print "################### nfs_proc_readlink start ##################";
  print fmt("in nfs_proc_readlink, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_readlink end   ##################";
}

event nfs_proc_remove(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::delobj_reply_t)
{
  print "################### nfs_proc_remove start ##################";
  print fmt("in nfs_proc_remove, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_remove end   ##################";
}

event nfs_proc_rmdir(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::delobj_reply_t)
{
  print "################### nfs_proc_rmdir start ##################";
  print fmt("in nfs_proc_rmdir, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_rmdir end   ##################";
}

event nfs_proc_write(c: connection, info: NFS3::info_t, req: NFS3::writeargs_t, rep: NFS3::write_reply_t)
{
  print "################### nfs_proc_write start ##################";
  print fmt("in nfs_proc_write, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### nfs_proc_write end   ##################";
}

event nfs_reply_status(n: connection, info: NFS3::info_t)
{
  print "################### nfs_reply_status start ##################";
  print fmt("in nfs_reply_status, n$uid is %s, n$id is %s, n$history is %s", n$uid, n$id, n$history);
  print "################### nfs_reply_status end   ##################";
}

event pm_attempt_callit(r: connection, status: rpc_status, call: pm_callit_request)
{
  print "################### pm_attempt_callit start ##################";
  print fmt("in pm_attempt_callit, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_attempt_callit end   ##################";
}

event pm_attempt_dump(r: connection, status: rpc_status)
{
  print "################### pm_attempt_dump start ##################";
  print fmt("in pm_attempt_dump, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_attempt_dump end   ##################";
}

event pm_attempt_getport(r: connection, status: rpc_status, pr: pm_port_request)
{
  print "################### pm_attempt_getport start ##################";
  print fmt("in pm_attempt_getport, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_attempt_getport end   ##################";
}

event pm_attempt_null(r: connection, status: rpc_status)
{
  print "################### pm_attempt_null start ##################";
  print fmt("in pm_attempt_null, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_attempt_null end   ##################";
}

event pm_attempt_set(r: connection, status: rpc_status, m: pm_mapping)
{
  print "################### pm_attempt_set start ##################";
  print fmt("in pm_attempt_set, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_attempt_set end   ##################";
}

event pm_attempt_unset(r: connection, status: rpc_status, m: pm_mapping)
{
  print "################### pm_attempt_unset start ##################";
  print fmt("in pm_attempt_unset, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_attempt_unset end   ##################";
}

event pm_bad_port(r: connection, bad_p: count)
{
  print "################### pm_bad_port start ##################";
  print fmt("in pm_bad_port, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_bad_port end   ##################";
}

event pm_request_callit(r: connection, call: pm_callit_request, p: port)
{
  print "################### pm_request_callit start ##################";
  print fmt("in pm_request_callit, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_request_callit end   ##################";
}

event pm_request_dump(r: connection, m: pm_mappings)
{
  print "################### pm_request_dump start ##################";
  print fmt("in pm_request_dump, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_request_dump end   ##################";
}

event pm_request_getport(r: connection, pr: pm_port_request, p: port)
{
  print "################### pm_request_getport start ##################";
  print fmt("in pm_request_getport, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_request_getport end   ##################";
}

event pm_request_null(r: connection)
{
  print "################### pm_request_null start ##################";
  print fmt("in pm_request_null, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_request_null end   ##################";
}

event pm_request_set(r: connection, m: pm_mapping, success: bool)
{
  print "################### pm_request_set start ##################";
  print fmt("in pm_request_set, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_request_set end   ##################";
}

event pm_request_unset(r: connection, m: pm_mapping, success: bool)
{
  print "################### pm_request_unset start ##################";
  print fmt("in pm_request_unset, r$uid is %s, r$id is %s, r$history is %s", r$uid, r$id, r$history);
  print "################### pm_request_unset end   ##################";
}

event rpc_call(c: connection, xid: count, prog: count, ver: count, proc: count, call_len: count)
{
  print "################### rpc_call start ##################";
  print fmt("in rpc_call, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rpc_call end   ##################";
}

event rpc_dialogue(c: connection, prog: count, ver: count, proc: count, status: rpc_status, start_time: time, call_len: count, reply_len: count)
{
  print "################### rpc_dialogue start ##################";
  print fmt("in rpc_dialogue, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rpc_dialogue end   ##################";
}

event rpc_reply(c: connection, xid: count, status: rpc_status, reply_len: count)
{
  print "################### rpc_reply start ##################";
  print fmt("in rpc_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### rpc_reply end   ##################";
}

event sip_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
  print "################### sip_all_headers start ##################";
  print fmt("in sip_all_headers, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### sip_all_headers end   ##################";
}

event sip_begin_entity(c: connection, is_orig: bool)
{
  print "################### sip_begin_entity start ##################";
  print fmt("in sip_begin_entity, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### sip_begin_entity end   ##################";
}

event sip_end_entity(c: connection, is_orig: bool)
{
  print "################### sip_end_entity start ##################";
  print fmt("in sip_end_entity, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### sip_end_entity end   ##################";
}

event sip_header(c: connection, is_orig: bool, name: string, value: string)
{
  print "################### sip_header start ##################";
  print fmt("in sip_header, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### sip_header end   ##################";
}

event sip_reply(c: connection, version: string, code: count, reason: string)
{
  print "################### sip_reply start ##################";
  print fmt("in sip_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### sip_reply end   ##################";
}

event sip_request(c: connection, method: string, original_URI: string, version: string)
{
  print "################### sip_request start ##################";
  print fmt("in sip_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### sip_request end   ##################";
}

event snmp_encrypted_pdu(c: connection, is_orig: bool, header: SNMP::Header)
{
  print "################### snmp_encrypted_pdu start ##################";
  print fmt("in snmp_encrypted_pdu, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_encrypted_pdu end   ##################";
}

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU)
{
  print "################### snmp_get_bulk_request start ##################";
  print fmt("in snmp_get_bulk_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_get_bulk_request end   ##################";
}

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_get_next_request start ##################";
  print fmt("in snmp_get_next_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_get_next_request end   ##################";
}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_get_request start ##################";
  print fmt("in snmp_get_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_get_request end   ##################";
}

event snmp_inform_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_inform_request start ##################";
  print fmt("in snmp_inform_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_inform_request end   ##################";
}

event snmp_report(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_report start ##################";
  print fmt("in snmp_report, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_report end   ##################";
}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_response start ##################";
  print fmt("in snmp_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_response end   ##################";
}

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_set_request start ##################";
  print fmt("in snmp_set_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_set_request end   ##################";
}

event snmp_trap(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::TrapPDU)
{
  print "################### snmp_trap start ##################";
  print fmt("in snmp_trap, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_trap end   ##################";
}

event snmp_trapV2(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
  print "################### snmp_trapV2 start ##################";
  print fmt("in snmp_trapV2, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_trapV2 end   ##################";
}

event snmp_unknown_header_version(c: connection, is_orig: bool, version: count)
{
  print "################### snmp_unknown_header_version start ##################";
  print fmt("in snmp_unknown_header_version, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_unknown_header_version end   ##################";
}

event snmp_unknown_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count)
{
  print "################### snmp_unknown_pdu start ##################";
  print fmt("in snmp_unknown_pdu, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_unknown_pdu end   ##################";
}

event snmp_unknown_scoped_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count)
{
  print "################### snmp_unknown_scoped_pdu start ##################";
  print fmt("in snmp_unknown_scoped_pdu, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### snmp_unknown_scoped_pdu end   ##################";
}

event smb1_empty_response(c: connection, hdr: SMB1::Header)
{
  print "################### smb1_empty_response start ##################";
  print fmt("in smb1_empty_response, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smb1_empty_response end   ##################";
}

event smb1_error(c: connection, hdr: SMB1::Header, is_orig: bool)
{
  print "################### smb1_error start ##################";
  print fmt("in smb1_error, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smb1_error end   ##################";
}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
{
  print "################### smb1_message start ##################";
  print fmt("in smb1_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smb1_message end   ##################";
}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
{
  print "################### smb2_message start ##################";
  print fmt("in smb2_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smb2_message end   ##################";
}

event smb_pipe_connect_heuristic(c: connection)
{
  print "################### smb_pipe_connect_heuristic start ##################";
  print fmt("in smb_pipe_connect_heuristic, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smb_pipe_connect_heuristic end   ##################";
}

event smtp_data(c: connection, is_orig: bool, data: string)
{
  print "################### smtp_data start ##################";
  print fmt("in smtp_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smtp_data end   ##################";
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
  print "################### smtp_reply start ##################";
  print fmt("in smtp_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smtp_reply end   ##################";
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
  print "################### smtp_request start ##################";
  print fmt("in smtp_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smtp_request end   ##################";
}

event smtp_starttls(c: connection)
{
  print "################### smtp_starttls start ##################";
  print fmt("in smtp_starttls, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smtp_starttls end   ##################";
}

event smtp_unexpected(c: connection, is_orig: bool, msg: string, detail: string)
{
  print "################### smtp_unexpected start ##################";
  print fmt("in smtp_unexpected, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### smtp_unexpected end   ##################";
}

event socks_login_userpass_reply(c: connection, code: count)
{
  print "################### socks_login_userpass_reply start ##################";
  print fmt("in socks_login_userpass_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### socks_login_userpass_reply end   ##################";
}

event socks_login_userpass_request(c: connection, user: string, password: string)
{
  print "################### socks_login_userpass_request start ##################";
  print fmt("in socks_login_userpass_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### socks_login_userpass_request end   ##################";
}

event socks_reply(c: connection, version: count, reply: count, sa: SOCKS::Address, p: port)
{
  print "################### socks_reply start ##################";
  print fmt("in socks_reply, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### socks_reply end   ##################";
}

event socks_request(c: connection, version: count, request_type: count, sa: SOCKS::Address, p: port, user: string)
{
  print "################### socks_request start ##################";
  print fmt("in socks_request, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### socks_request end   ##################";
}

event ssh1_server_host_key(c: connection, p: string, e: string)
{
  print "################### ssh1_server_host_key start ##################";
  print fmt("in ssh1_server_host_key, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh1_server_host_key end   ##################";
}

event ssh2_dh_server_params(c: connection, p: string, q: string)
{
  print "################### ssh2_dh_server_params start ##################";
  print fmt("in ssh2_dh_server_params, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh2_dh_server_params end   ##################";
}

event ssh2_ecc_key(c: connection, is_orig: bool, q: string)
{
  print "################### ssh2_ecc_key start ##################";
  print fmt("in ssh2_ecc_key, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh2_ecc_key end   ##################";
}

event ssh2_gss_error(c: connection, major_status: count, minor_status: count, err_msg: string)
{
  print "################### ssh2_gss_error start ##################";
  print fmt("in ssh2_gss_error, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh2_gss_error end   ##################";
}

event ssh2_server_host_key(c: connection, key: string)
{
  print "################### ssh2_server_host_key start ##################";
  print fmt("in ssh2_server_host_key, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh2_server_host_key end   ##################";
}

event ssh_auth_attempted(c: connection, authenticated: bool)
{
  print "################### ssh_auth_attempted start ##################";
  print fmt("in ssh_auth_attempted, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh_auth_attempted end   ##################";
}

event ssh_auth_successful(c: connection, auth_method_none: bool)
{
  print "################### ssh_auth_successful start ##################";
  print fmt("in ssh_auth_successful, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh_auth_successful end   ##################";
}

event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities)
{
  print "################### ssh_capabilities start ##################";
  print fmt("in ssh_capabilities, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh_capabilities end   ##################";
}

event ssh_client_version(c: connection, version: string)
{
  print "################### ssh_client_version start ##################";
  print fmt("in ssh_client_version, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh_client_version end   ##################";
}

event ssh_encrypted_packet(c: connection, orig: bool, len: count)
{
  print "################### ssh_encrypted_packet start ##################";
  print fmt("in ssh_encrypted_packet, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh_encrypted_packet end   ##################";
}

event ssh_server_version(c: connection, version: string)
{
  print "################### ssh_server_version start ##################";
  print fmt("in ssh_server_version, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssh_server_version end   ##################";
}

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
{
  print "################### ssl_alert start ##################";
  print fmt("in ssl_alert, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_alert end   ##################";
}

event ssl_application_data(c: connection, is_orig: bool, length: count)
{
  print "################### ssl_application_data start ##################";
  print fmt("in ssl_application_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_application_data end   ##################";
}

event ssl_change_cipher_spec(c: connection, is_orig: bool)
{
  print "################### ssl_change_cipher_spec start ##################";
  print fmt("in ssl_change_cipher_spec, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_change_cipher_spec end   ##################";
}

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
{
  print "################### ssl_client_hello start ##################";
  print fmt("in ssl_client_hello, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_client_hello end   ##################";
}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string)
{
  print "################### ssl_dh_server_params start ##################";
  print fmt("in ssl_dh_server_params, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_dh_server_params end   ##################";
}

event ssl_encrypted_data(c: connection, is_orig: bool, content_type: count, length: count)
{
  print "################### ssl_encrypted_data start ##################";
  print fmt("in ssl_encrypted_data, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_encrypted_data end   ##################";
}

event ssl_established(c: connection)
{
  print "################### ssl_established start ##################";
  print fmt("in ssl_established, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_established end   ##################";
}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
  print "################### ssl_extension start ##################";
  print fmt("in ssl_extension, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension end   ##################";
}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_orig: bool, protocols: string_vec)
{
  print "################### ssl_extension_application_layer_protocol_negotiation start ##################";
  print fmt("in ssl_extension_application_layer_protocol_negotiation, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_application_layer_protocol_negotiation end   ##################";
}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
{
  print "################### ssl_extension_ec_point_formats start ##################";
  print fmt("in ssl_extension_ec_point_formats, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_ec_point_formats end   ##################";
}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
{
  print "################### ssl_extension_elliptic_curves start ##################";
  print fmt("in ssl_extension_elliptic_curves, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_elliptic_curves end   ##################";
}

event ssl_extension_key_share(c: connection, is_orig: bool, curves: index_vec)
{
  print "################### ssl_extension_key_share start ##################";
  print fmt("in ssl_extension_key_share, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_key_share end   ##################";
}

event ssl_extension_psk_key_exchange_modes(c: connection, is_orig: bool, modes: index_vec)
{
  print "################### ssl_extension_psk_key_exchange_modes start ##################";
  print fmt("in ssl_extension_psk_key_exchange_modes, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_psk_key_exchange_modes end   ##################";
}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
{
  print "################### ssl_extension_server_name start ##################";
  print fmt("in ssl_extension_server_name, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_server_name end   ##################";
}

event ssl_extension_signature_algorithm(c: connection, is_orig: bool, signature_algorithms: signature_and_hashalgorithm_vec)
{
  print "################### ssl_extension_signature_algorithm start ##################";
  print fmt("in ssl_extension_signature_algorithm, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_signature_algorithm end   ##################";
}

event ssl_extension_supported_versions(c: connection, is_orig: bool, versions: index_vec)
{
  print "################### ssl_extension_supported_versions start ##################";
  print fmt("in ssl_extension_supported_versions, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_extension_supported_versions end   ##################";
}

event ssl_handshake_message(c: connection, is_orig: bool, msg_type: count, length: count)
{
  print "################### ssl_handshake_message start ##################";
  print fmt("in ssl_handshake_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_handshake_message end   ##################";
}

event ssl_heartbeat(c: connection, is_orig: bool, length: count, heartbeat_type: count, payload_length: count, payload: string)
{
  print "################### ssl_heartbeat start ##################";
  print fmt("in ssl_heartbeat, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_heartbeat end   ##################";
}

event ssl_server_curve(c: connection, curve: count)
{
  print "################### ssl_server_curve start ##################";
  print fmt("in ssl_server_curve, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_server_curve end   ##################";
}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
{
  print "################### ssl_server_hello start ##################";
  print fmt("in ssl_server_hello, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_server_hello end   ##################";
}

event ssl_session_ticket_handshake(c: connection, ticket_lifetime_hint: count, ticket: string)
{
  print "################### ssl_session_ticket_handshake start ##################";
  print fmt("in ssl_session_ticket_handshake, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_session_ticket_handshake end   ##################";
}

event ssl_stapled_ocsp(c: connection, is_orig: bool, response: string)
{
  print "################### ssl_stapled_ocsp start ##################";
  print fmt("in ssl_stapled_ocsp, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### ssl_stapled_ocsp end   ##################";
}

event stp_correlate_pair(e1: int, e2: int)
{
  print "################### stp_correlate_pair start ##################";
  print "################### stp_correlate_pair end   ##################";
}

event stp_remove_endp(e: int)
{
  print "################### stp_remove_endp start ##################";
  print "################### stp_remove_endp end   ##################";
}

event stp_remove_pair(e1: int, e2: int)
{
  print "################### stp_remove_pair start ##################";
  print "################### stp_remove_pair end   ##################";
}

event stp_resume_endp(e: int)
{
  print "################### stp_resume_endp start ##################";
  print "################### stp_resume_endp end   ##################";
}

event syslog_message(c: connection, facility: count, severity: count, msg: string)
{
  print "################### syslog_message start ##################";
  print fmt("in syslog_message, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### syslog_message end   ##################";
}

event connection_EOF(c: connection, is_orig: bool)
{
  print "################### connection_EOF start ##################";
  print fmt("in connection_EOF, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_EOF end   ##################";
}

event connection_SYN_packet(c: connection, pkt: SYN_packet)
{
  print "################### connection_SYN_packet start ##################";
  print fmt("in connection_SYN_packet, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_SYN_packet end   ##################";
}

event connection_attempt(c: connection)
{
  print "################### connection_attempt start ##################";
  print fmt("in connection_attempt, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_attempt end   ##################";
}

event connection_established(c: connection)
{
  print "################### connection_established start ##################";
  print fmt("in connection_established, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_established end   ##################";
}

event connection_finished(c: connection)
{
  print "################### connection_finished start ##################";
  print fmt("in connection_finished, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_finished end   ##################";
}

event connection_first_ACK(c: connection)
{
  print "################### connection_first_ACK start ##################";
  print fmt("in connection_first_ACK, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_first_ACK end   ##################";
}

event connection_half_finished(c: connection)
{
  print "################### connection_half_finished start ##################";
  print fmt("in connection_half_finished, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_half_finished end   ##################";
}

event connection_partial_close(c: connection)
{
  print "################### connection_partial_close start ##################";
  print fmt("in connection_partial_close, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_partial_close end   ##################";
}

event connection_pending(c: connection)
{
  print "################### connection_pending start ##################";
  print fmt("in connection_pending, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_pending end   ##################";
}

event connection_rejected(c: connection)
{
  print "################### connection_rejected start ##################";
  print fmt("in connection_rejected, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_rejected end   ##################";
}

event connection_reset(c: connection)
{
  print "################### connection_reset start ##################";
  print fmt("in connection_reset, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### connection_reset end   ##################";
}

event contents_file_write_failure(c: connection, is_orig: bool, msg: string)
{
  print "################### contents_file_write_failure start ##################";
  print fmt("in contents_file_write_failure, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### contents_file_write_failure end   ##################";
}

event new_connection_contents(c: connection)
{
  print "################### new_connection_contents start ##################";
  print fmt("in new_connection_contents, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### new_connection_contents end   ##################";
}

event partial_connection(c: connection)
{
  print "################### partial_connection start ##################";
  print fmt("in partial_connection, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### partial_connection end   ##################";
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
{
  print "################### tcp_contents start ##################";
  print fmt("in tcp_contents, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### tcp_contents end   ##################";
}

event tcp_option(c: connection, is_orig: bool, opt: count, optlen: count)
{
  print "################### tcp_option start ##################";
  print fmt("in tcp_option, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### tcp_option end   ##################";
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
  print "################### tcp_packet start ##################";
  print fmt("in tcp_packet, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### tcp_packet end   ##################";
}

event tcp_rexmit(c: connection, is_orig: bool, seq: count, len: count, data_in_flight: count, window: count)
{
  print "################### tcp_rexmit start ##################";
  print fmt("in tcp_rexmit, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### tcp_rexmit end   ##################";
}

event teredo_authentication(outer: connection, inner: teredo_hdr)
{
  print "################### teredo_authentication start ##################";
  print fmt("in teredo_authentication, outer$uid is %s, outer$id is %s, outer$history is %s", outer$uid, outer$id, outer$history);
  print "################### teredo_authentication end   ##################";
}

event teredo_bubble(outer: connection, inner: teredo_hdr)
{
  print "################### teredo_bubble start ##################";
  print fmt("in teredo_bubble, outer$uid is %s, outer$id is %s, outer$history is %s", outer$uid, outer$id, outer$history);
  print "################### teredo_bubble end   ##################";
}

event teredo_origin_indication(outer: connection, inner: teredo_hdr)
{
  print "################### teredo_origin_indication start ##################";
  print fmt("in teredo_origin_indication, outer$uid is %s, outer$id is %s, outer$history is %s", outer$uid, outer$id, outer$history);
  print "################### teredo_origin_indication end   ##################";
}

event teredo_packet(outer: connection, inner: teredo_hdr)
{
  print "################### teredo_packet start ##################";
  print fmt("in teredo_packet, outer$uid is %s, outer$id is %s, outer$history is %s", outer$uid, outer$id, outer$history);
  print "################### teredo_packet end   ##################";
}

event udp_contents(u: connection, is_orig: bool, contents: string)
{
  print "################### udp_contents start ##################";
  print fmt("in udp_contents, u$uid is %s, u$id is %s, u$history is %s", u$uid, u$id, u$history);
  print "################### udp_contents end   ##################";
}

event udp_reply(u: connection)
{
  print "################### udp_reply start ##################";
  print fmt("in udp_reply, u$uid is %s, u$id is %s, u$history is %s", u$uid, u$id, u$history);
  print "################### udp_reply end   ##################";
}

event udp_request(u: connection)
{
  print "################### udp_request start ##################";
  print fmt("in udp_request, u$uid is %s, u$id is %s, u$history is %s", u$uid, u$id, u$history);
  print "################### udp_request end   ##################";
}

event xmpp_starttls(c: connection)
{
  print "################### xmpp_starttls start ##################";
  print fmt("in xmpp_starttls, c$uid is %s, c$id is %s, c$history is %s", c$uid, c$id, c$history);
  print "################### xmpp_starttls end   ##################";
}

event file_entropy(f: fa_file, ent: entropy_test_result)
{
  print "################### file_entropy start ##################";
  print "################### file_entropy end   ##################";
}

event file_extraction_limit(f: fa_file, args: Files::AnalyzerArgs, limit: count, len: count)
{
  print "################### file_extraction_limit start ##################";
  print "################### file_extraction_limit end   ##################";
}

event file_hash(f: fa_file, kind: string, hash: string)
{
  print "################### file_hash start ##################";
  print "################### file_hash end   ##################";
}

event pe_dos_code(f: fa_file, code: string)
{
  print "################### pe_dos_code start ##################";
  print "################### pe_dos_code end   ##################";
}

event pe_dos_header(f: fa_file, h: PE::DOSHeader)
{
  print "################### pe_dos_header start ##################";
  print "################### pe_dos_header end   ##################";
}

event pe_file_header(f: fa_file, h: PE::FileHeader)
{
  print "################### pe_file_header start ##################";
  print "################### pe_file_header end   ##################";
}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader)
{
  print "################### pe_optional_header start ##################";
  print "################### pe_optional_header end   ##################";
}

event pe_section_header(f: fa_file, h: PE::SectionHeader)
{
  print "################### pe_section_header start ##################";
  print "################### pe_section_header end   ##################";
}

event unified2_event(f: fa_file, ev: Unified2::IDSEvent)
{
  print "################### unified2_event start ##################";
  print "################### unified2_event end   ##################";
}

event unified2_packet(f: fa_file, pkt: Unified2::Packet)
{
  print "################### unified2_packet start ##################";
  print "################### unified2_packet end   ##################";
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
{
  print "################### x509_certificate start ##################";
  print "################### x509_certificate end   ##################";
}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints)
{
  print "################### x509_ext_basic_constraints start ##################";
  print "################### x509_ext_basic_constraints end   ##################";
}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName)
{
  print "################### x509_ext_subject_alternative_name start ##################";
  print "################### x509_ext_subject_alternative_name end   ##################";
}

event x509_extension(f: fa_file, ext: X509::Extension)
{
  print "################### x509_extension start ##################";
  print "################### x509_extension end   ##################";
}

