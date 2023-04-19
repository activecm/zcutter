#!/usr/bin/env python3
"""A library of routines for working with Zeek logs."""


def register_header_block(hb: list):
	"""Load in a header block from a TSV format zeek log."""

	h_list = hb.split('\n')

	pared_h_list = []

	file_type = ''
	field_list = []
	type_list = []
	for one_line in h_list:
		if one_line.startswith('#path'):
			file_type = one_line.split('\t')[1]
			#print("==== " + file_type)
		elif one_line.startswith('#fields'):
			field_list = one_line.split('\t')[1:]
		elif one_line.startswith('#types'):
			type_list = one_line.split('\t')[1:]

		if not one_line.startswith(('#open', '#close')):
			pared_h_list.append(one_line)

	assert len(field_list) == len(type_list)
	field_name_lists[file_type] = field_list
	field_type_lists[file_type] = type_list

	#if field_list and type_list:
	#	if file_type not in master_types:
	#		master_types[file_type] = {}
	#	types_of = dict(zip(field_list, type_list))
	#	for field_name, field_type in types_of.items():
	#		master_types[file_type][field_name] = field_type
	#else:
	#	print(file_type + " is missing one or both of field and type lines.")

	if file_type:
		header_lines[file_type] = pared_h_list

	#print(str(h_list))




header_lines = {}		#Keys are file_type, values are lists of header strings
field_name_lists = {}		#Keys are file_type, values are lists of field names
field_type_lists = {}		#Keys are file_type, values are lists of field types
#master_types = {}		#keys are file_type, values are dictionaries of field->type.






register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	capture_loss
#open	2023-04-18-00-12-38
#fields	ts	ts_delta	peer	gaps	acks	percent_lost
#types	time	interval	string	count	count	double
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2023-04-18-00-00-00
#fields	_node_name	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	string	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2023-04-18-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dpd
#open	2023-04-18-00-11-24
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	analyzer	failure_reason
#types	time	string	addr	port	addr	port	enum	string	string
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2023-04-18-00-11-23
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2023-04-18-00-11-23
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	known_services
#open	2023-04-18-02-15-27
#fields	ts	host	port_num	port_proto	service
#types	time	addr	port	enum	set[string]
#close	2023-04-18-03-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2023-04-18-00-12-38
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ntp
#open	2023-04-18-00-15-39
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	mode	stratum	poll	precision	root_delay	root_disp	ref_id	ref_time	org_time	rec_time	xmt_time	num_exts
#types	time	string	addr	port	addr	port	count	count	count	interval	interval	interval	interval	string	time	time	time	time	count
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ocsp
#open	2023-04-18-03-20-16
#fields	ts	id	hashAlgorithm	issuerNameHash	issuerKeyHash	serialNumber	certStatus	revoketime	revokereason	thisUpdate	nextUpdate
#types	time	string	string	string	string	string	string	time	string	time	time
#close	2023-04-18-04-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	open_conn
#open	2023-04-18-02-20-11
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
#close	2023-04-18-03-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	sip
#open	2023-04-18-00-03-55
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	uri	date	request_from	request_to	response_from	response_to	reply_to	call_id	seq	subject	request_path	response_path	user_agent	status_code	status_msg	warning	request_body_len	response_body_len	content_type
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	string	string	string	string	vector[string]	vector[string]	string	count	string	string	count	count	string
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	snmp
#open	2023-04-18-01-44-52
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	duration	version	community	get_requests	get_bulk_requests	get_responses	set_requests	display_string	up_since
#types	time	string	addr	port	addr	port	interval	string	string	count	count	count	count	string	time
#close	2023-04-18-02-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	software
#open	2023-04-18-18-33-13
#fields	ts	host	host_p	software_type	name	version.major	version.minor	version.minor2	version.minor3	version.addl	unparsed_version
#types	time	addr	port	enum	string	count	count	count	count	string	string
#close	2023-04-18-19-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2023-04-18-00-00-10
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#open	2023-04-18-00-11-24
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	ssl_history	cert_chain_fps	client_cert_chain_fps	sni_matches_cert	validation_status	ja3	ja3s
#types	time	string	addr	port	addr	port	string	string	string	string	bool	string	string	bool	string	vector[string]	vector[string]	bool	string	string	string
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	stats
#open	2023-04-18-00-01-43
#fields	ts	peer	mem	pkts_proc	bytes_recv	pkts_dropped	pkts_link	pkt_lag	events_proc	events_queued	active_tcp_conns	active_udp_conns	active_icmp_conns	tcp_conns	udp_conns	icmp_conns	timers	active_timers	files	active_files	dns_requests	active_dns_requests	reassem_tcp_size	reassem_file_size	reassem_frag_size	reassem_unknown_size
#types	time	string	count	count	count	count	count	interval	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	weird
#open	2023-04-18-00-02-47
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	name	addl	notice	peer	source
#types	time	string	addr	port	addr	port	string	string	bool	string	string
#close	2023-04-18-01-00-00""")

register_header_block(r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	x509
#open	2023-04-18-06-32-13
#fields	ts	fingerprint	certificate.version	certificate.serial	certificate.subject	certificate.issuer	certificate.not_valid_before	certificate.not_valid_after	certificate.key_alg	certificate.sig_alg	certificate.key_type	certificate.key_length	certificate.exponent	certificate.curve	san.dns	san.uri	san.email	san.ip	basic_constraints.ca	basic_constraints.path_len	host_cert	client_cert
#types	time	string	count	string	string	string	time	time	string	string	string	count	string	string	vector[string]	vector[string]	vector[string]	vector[addr]	bool	count	bool	bool
#close	2023-04-18-07-00-00""")


#print(str(header_lines))
#print()
#print(str(field_name_lists))
#print()
#print(str(field_type_lists))
#print()

#print(str(master_types))

