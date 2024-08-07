#!/usr/bin/env python3
"""Python replacement for zeek-cut.  Handles tsv and json input and output files."""			# pylint: disable=too-many-lines

#Copyright 2023 William Stearns <william.l.stearns@gmail.com>
#Released under the GPL

#Dedicated to my colleague and friend, Chris Brenton.  Many thanks for all you have shared about understanding networks.

__version__ = '1.0.14'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2023, William Stearns'
__credits__ = ['William Stearns', 'Naomi Goddard']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Production'		#Prototype, Development or Production


#======== External libraries
import os				#File access
import sys				#Used for reading from stdin/writing to stdout
import tempfile				#Creating temporary files for working with stdin or compressed files
import bz2				#Opening bzip2 compressed files
import datetime				#Date formatting
import gzip				#Opening gzip compressed files
import json				#Reading json formatted files
import errno				#For exceptions
import zlib
import shutil				#For file copies
from typing import Dict, List, Union, TextIO, Tuple


#======== Constants
raw_header_blocks = [
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	app_stats
#open	0000-00-00-00-00-00
#fields	ts	ts_delta	app	uniq_hosts	hits	bytes
#types	time	interval	string	count	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	broker
#open	0000-00-00-00-00-00
#fields	ts	ty	ev	peer.address	peer.bound_port	message
#types	time	enum	string	string	port	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	capture_loss
#open	0000-00-00-00-00-00
#fields	ts	ts_delta	peer	gaps	acks	percent_lost
#types	time	interval	string	count	count	double
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	cluster
#open	0000-00-00-00-00-00
#fields	ts	node	message
#types	time	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	communication
#open	0000-00-00-00-00-00
#fields	ts	peer	src_name	connected_peer_desc	connected_peer_addr	connected_peer_port	level	message
#types	time	string	string	string	addr	port	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	0000-00-00-00-00-00
#fields	_node_name	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	string	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn_red
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	orig_cc	resp_cc	orig_l2_addr	resp_l2_addr	vlan	inner_vlan	community_id
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]	string	string	string	string	int	int	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	corelight_burst
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	orig_size	resp_size	mbps	age_of_conn
#types	time	string	addr	port	addr	port	enum	count	count	double	interval
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	corelight_overall_capture_loss
#open	0000-00-00-00-00-00
#fields	ts	gaps	acks	percent_lost
#types	time	double	double	double
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	datared
#open	0000-00-00-00-00-00
#fields	ts	conn_red	conn_total	dns_red	dns_total	dns_coal_miss	files_red	files_total	files_coal_miss	http_red	http_total	ssl_red	ssl_total	ssl_coal_miss	weird_red	weird_total	x509_red	x509_total	x509_coal_miss
#types	time	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dce_rpc
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	rtt	named_pipe	endpoint	operation
#types	time	string	addr	port	addr	port	interval	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dhcp
#open	0000-00-00-00-00-00
#fields	ts	uids	client_addr	server_addr	mac	host_name	client_fqdn	domain	requested_addr	assigned_addr	lease_time	client_message	server_message	msg_types	duration
#types	time	set[string]	addr	addr	string	string	string	string	addr	addr	interval	string	string	vector[string]	interval
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dnp3
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fc_request	fc_reply	iin
#types	time	string	addr	port	addr	port	string	string	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns_red
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	query	qtype_name	rcode	answers	num
#types	time	string	addr	port	addr	port	string	string	count	vector[string]	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dpd
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	analyzer	failure_reason
#types	time	string	addr	port	addr	port	enum	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	etc_viz
#open	0000-00-00-00-00-00
#fields	uid	server_a	server_p	service	viz_stat	c2s_viz.size	c2s_viz.enc_dev	c2s_viz.enc_frac	c2s_viz.pdu1_enc	c2s_viz.clr_frac	c2s_viz.clr_ex	s2c_viz.size	s2c_viz.enc_dev	s2c_viz.enc_frac	s2c_viz.pdu1_enc	s2c_viz.clr_frac	s2c_viz.clr_ex
#types	string	addr	port	set[string]	string	count	double	double	bool	double	string	count	double	double	bool	double	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	0000-00-00-00-00-00
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files_red
#open	0000-00-00-00-00-00
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	extracted	extracted_cutoff	extracted_size	md5	sha1	sha256	num
#types	vector[time]	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	bool	bool	count	count	count	count	bool	string	set[string]	bool	count	string	string	string	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ftp
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	user	password	command	arg	mime_type	file_size	reply_code	reply_msg	data_channel.passive	data_channel.orig_h	data_channel.resp_h	data_channel.resp_p	fuid
#types	time	string	addr	port	addr	port	string	string	string	string	string	count	count	string	bool	addr	addr	port	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http_red
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types	post_body
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	intel
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	seen.indicator	seen.indicator_type	seen.where	matched	sources	fuid	file_mime_type	file_desc
#types	time	string	addr	port	addr	port	string	enum	enum	set[enum]	set[string]	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	irc
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	nick	user	command	value	addl	dcc_file_name	dcc_file_size	dcc_mime_type	fuid
#types	time	string	addr	port	addr	port	string	string	string	string	string	string	count	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	kerberos
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	request_type	client	service	success	error_msg	from	till	cipher	forwardable	renewable	client_cert_subject	client_cert_fuid	server_cert_subject	server_cert_fuid
#types	time	string	addr	port	addr	port	string	string	string	bool	string	time	time	string	bool	bool	string	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	known_certs
#open	0000-00-00-00-00-00
#fields	ts	host	port_num	subject	issuer_subject	serial
#types	time	addr	port	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	known_hosts
#open	0000-00-00-00-00-00
#fields	ts	host
#types	time	addr
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	known_services
#open	0000-00-00-00-00-00
#fields	ts	host	port_num	port_proto	service
#types	time	addr	port	enum	set[string]
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	modbus
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	func	exception
#types	time	string	addr	port	addr	port	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	mqtt_connect
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto_name	proto_version	client_id	connect_status	will_topic	will_payload
#types	time	string	addr	port	addr	port	string	string	string	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	mqtt_publish
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	from_client	retain	qos	status	topic	payload	payload_len
#types	time	string	addr	port	addr	port	bool	bool	string	string	string	string	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	mqtt_subscribe
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	action	topics	qos_levels	granted_qos_level	ack
#types	time	string	addr	port	addr	port	enum	vector[string]	vector[count]	count	bool
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	mysql
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	cmd	arg	success	rows	response
#types	time	string	addr	port	addr	port	string	string	bool	count	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	namecache
#open	0000-00-00-00-00-00
#fields	ts	lookups	hit_rate_conn	hit_rate_conn_orig_h	hit_rate_conn_resp_h	hit_rate_conn_prod	hit_rate_conn_prod_orig_h	hit_rate_conn_prod_resp_h	hit_rate_conn_int_h	hit_rate_conn_ext_h	src_dns_a	src_dns_aaaa	src_dns_a6	src_dns_ptr	src_unknown	cache_entries	cache_add_tx_ev	cache_add_tx_mpg	cache_add_rx_ev	cache_add_rx_mpg	cache_add_rx_new	cache_del_mpg
#types	time	count	double	double	double	double	double	double	double	double	count	count	count	count	count	count	count	count	count	count	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ntlm
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	username	hostname	domainname	server_nb_computer_name	server_dns_computer_name	server_tree_name	success
#types	time	string	addr	port	addr	port	string	string	string	string	string	string	bool
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ntp
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	mode	stratum	poll	precision	root_delay	root_disp	ref_id	ref_time	org_time	rec_time	xmt_time	num_exts
#types	time	string	addr	port	addr	port	count	count	count	interval	interval	interval	interval	string	time	time	time	time	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ocsp
#open	0000-00-00-00-00-00
#fields	ts	id	hashAlgorithm	issuerNameHash	issuerKeyHash	serialNumber	certStatus	revoketime	revokereason	thisUpdate	nextUpdate
#types	time	string	string	string	string	string	string	time	string	time	time
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	open_conn
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	packet_filter
#open	0000-00-00-00-00-00
#fields	ts	node	filter	init	success
#types	time	string	string	bool	bool
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	pe
#open	0000-00-00-00-00-00
#fields	ts	id	machine	compile_ts	os	subsystem	is_exe	is_64bit	uses_aslr	uses_dep	uses_code_integrity	uses_seh	has_import_table	has_export_table	has_cert_table	has_debug_data	section_names
#types	time	string	string	time	string	string	bool	bool	bool	bool	bool	bool	bool	bool	bool	bool	vector[string]
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	radius
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	username	mac	framed_addr	remote_ip	connect_info	reply_msg	result	ttl
#types	time	string	addr	port	addr	port	string	string	addr	addr	string	string	string	interval
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	rdp
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	cookie	result	security_protocol	keyboard_layout	client_build	client_name	client_dig_product_id	desktop_width	desktop_height	requested_color_depth	cert_type	cert_count	cert_permanent	encryption_level	encryption_method
#types	time	string	addr	port	addr	port	string	string	string	string	string	string	string	count	count	string	string	count	bool	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	reporter
#open	0000-00-00-00-00-00
#fields	ts	level	message	location
#types	time	enum	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	rfb
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	client_major_version	client_minor_version	server_major_version	server_minor_version	authentication_method	auth	share_flag	desktop_name	width	height
#types	time	string	addr	port	addr	port	string	string	string	string	string	bool	bool	string	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	signatures
#open	0000-00-00-00-00-00
#fields	ts	uid	src_addr	src_port	dst_addr	dst_port	note	sig_id	event_msg	sub_msg	sig_count	host_count
#types	time	string	addr	port	addr	port	enum	string	string	string	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	sip
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	uri	date	request_from	request_to	response_from	response_to	reply_to	call_id	seq	subject	request_path	response_path	user_agent	status_code	status_msg	warning	request_body_len	response_body_len	content_type
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	string	string	string	string	vector[string]	vector[string]	string	count	string	string	count	count	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	smb_files
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	action	path	name	size	prev_name	times.modified	times.accessed	times.created	times.changed	data_offset_req	data_len_req	data_len_rsp
#types	time	string	addr	port	addr	port	string	enum	string	string	count	string	time	time	time	time	count	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	smb_mapping
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	path	service	native_file_system	share_type
#types	time	string	addr	port	addr	port	string	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	smtp
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	helo	mailfrom	rcptto	date	from	to	cc	reply_to	msg_id	in_reply_to	subject	x_originating_ip	first_received	second_received	last_reply	path	user_agent	tls	fuids	is_webmail
#types	time	string	addr	port	addr	port	count	string	string	set[string]	string	string	set[string]	set[string]	string	string	string	string	addr	string	string	string	vector[addr]	string	bool	vector[string]	bool
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	snmp
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	duration	version	community	get_requests	get_bulk_requests	get_responses	set_requests	display_string	up_since
#types	time	string	addr	port	addr	port	interval	string	string	count	count	count	count	string	time
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	socks
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	user	password	status	request.host	request.name	request_p	bound.host	bound.name	bound_p
#types	time	string	addr	port	addr	port	count	string	string	string	addr	string	port	addr	string	port
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	software
#open	0000-00-00-00-00-00
#fields	ts	host	host_p	software_type	name	version.major	version.minor	version.minor2	version.minor3	version.addl	unparsed_version
#types	time	addr	port	enum	string	count	count	count	count	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	ssl_history	cert_chain_fps	client_cert_chain_fps	sni_matches_cert	validation_status	ja3	ja3s
#types	time	string	addr	port	addr	port	string	string	string	string	bool	string	string	bool	string	vector[string]	vector[string]	bool	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssl_red
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	cert_chain_fuids	client_cert_chain_fuids	subject	issuer	client_subject	client_issuer	validation_status	ja3	ja3s
#types	time	string	addr	port	addr	port	string	string	string	string	bool	string	string	bool	vector[string]	vector[string]	string	string	string	string	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	stats
#open	0000-00-00-00-00-00
#fields	ts	peer	mem	pkts_proc	bytes_recv	pkts_dropped	pkts_link	pkt_lag	events_proc	events_queued	active_tcp_conns	active_udp_conns	active_icmp_conns	tcp_conns	udp_conns	icmp_conns	timers	active_timers	files	active_files	dns_requests	active_dns_requests	reassem_tcp_size	reassem_file_size	reassem_frag_size	reassem_unknown_size
#types	time	string	count	count	count	count	count	interval	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count	count
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	syslog
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	facility	severity	message
#types	time	string	addr	port	addr	port	enum	string	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	traceroute
#open	0000-00-00-00-00-00
#fields	ts	src	dst	proto
#types	time	addr	addr	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	tunnel
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	tunnel_type	action
#types	time	string	addr	port	addr	port	enum	enum
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	weird
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	name	addl	notice	peer	source
#types	time	string	addr	port	addr	port	string	string	bool	string	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	weird_red
#open	0000-00-00-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	name	addl	notice	peer
#types	time	string	addr	port	addr	port	string	string	bool	string
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	x509
#open	0000-00-00-00-00-00
#fields	ts	fingerprint	certificate.version	certificate.serial	certificate.subject	certificate.issuer	certificate.not_valid_before	certificate.not_valid_after	certificate.key_alg	certificate.sig_alg	certificate.key_type	certificate.key_length	certificate.exponent	certificate.curve	san.dns	san.uri	san.email	san.ip	basic_constraints.ca	basic_constraints.path_len	host_cert	client_cert
#types	time	string	count	string	string	string	time	time	string	string	string	count	string	string	vector[string]	vector[string]	vector[string]	vector[addr]	bool	count	bool	bool
#close	9999-12-31-23-59-59""",
r"""#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	x509_red
#open	0000-00-00-00-00-00
#fields	ts	id	certificate.version	certificate.serial	certificate.subject	certificate.issuer	certificate.not_valid_before	certificate.not_valid_after	certificate.key_alg	certificate.sig_alg	certificate.key_type	certificate.key_length	certificate.exponent	certificate.curve	san.dns	san.uri	san.email	san.ip	basic_constraints.ca	basic_constraints.path_len
#types	time	string	count	string	string	string	time	time	string	string	string	count	string	string	vector[string]	vector[string]	vector[string]	vector[addr]	bool	count
#close	9999-12-31-23-59-59"""
]


#Originally this was supposed to be key=fieldname, value=fieldtype (like 'ts_delta': 'interval' below.
#Unfortunately these are not fixed.  For example, 'version' is a 'string' in 5 headers (called 'paths')
#but 'count' in 3 others.  For that reason, some of these are key=(fieldname, path), value=fieldtype , so
#you have to check for both fieldname and (fieldname. path) as keys when accessing this; see top of correct_var_format
static_field_types: dict = {('ts', 'app_stats'): 'time', 'ts_delta': 'interval', 'app': 'string', 'uniq_hosts': 'count', 'hits': 'count', 'bytes': 'count', ('ts', 'broker'): 'time', 'ty': 'enum', 'ev': 'string', 'peer.address': 'string', 'peer.bound_port': 'port', 'message': 'string', ('ts', 'capture_loss'): 'time', 'peer': 'string', ('gaps', 'capture_loss'): 'count', ('acks', 'capture_loss'): 'count', 'percent_lost': 'double', ('ts', 'cluster'): 'time', 'node': 'string', ('ts', 'communication'): 'time', 'src_name': 'string', 'connected_peer_desc': 'string', 'connected_peer_addr': 'addr', 'connected_peer_port': 'port', ('level', 'communication'): 'string', '_node_name': 'string', ('ts', 'conn'): 'time', 'uid': 'string', 'id.orig_h': 'addr', 'id.orig_p': 'port', 'id.resp_h': 'addr', 'id.resp_p': 'port', ('proto', 'conn'): 'enum', ('service', 'conn'): 'string', 'duration': 'interval', 'orig_bytes': 'count', 'resp_bytes': 'count', 'conn_state': 'string', 'local_orig': 'bool', 'local_resp': 'bool', 'missed_bytes': 'count', 'history': 'string', 'orig_pkts': 'count', 'orig_ip_bytes': 'count', 'resp_pkts': 'count', 'resp_ip_bytes': 'count', 'tunnel_parents': 'set[string]', ('ts', 'conn_red'): 'time', ('proto', 'conn_red'): 'enum', ('service', 'conn_red'): 'string', 'orig_cc': 'string', 'resp_cc': 'string', 'orig_l2_addr': 'string', 'resp_l2_addr': 'string', 'vlan': 'int', 'inner_vlan': 'int', 'community_id': 'string', ('ts', 'corelight_burst'): 'time', ('proto', 'corelight_burst'): 'enum', 'orig_size': 'count', 'resp_size': 'count', 'mbps': 'double', 'age_of_conn': 'interval', ('ts', 'corelight_overall_capture_loss'): 'time', ('gaps', 'corelight_overall_capture_loss'): 'double', ('acks', 'corelight_overall_capture_loss'): 'double', ('ts', 'datared'): 'time', 'conn_red': 'count', 'conn_total': 'count', 'dns_red': 'count', 'dns_total': 'count', 'dns_coal_miss': 'count', 'files_red': 'count', 'files_total': 'count', 'files_coal_miss': 'count', 'http_red': 'count', 'http_total': 'count', 'ssl_red': 'count', 'ssl_total': 'count', 'ssl_coal_miss': 'count', 'weird_red': 'count', 'weird_total': 'count', 'x509_red': 'count', 'x509_total': 'count', 'x509_coal_miss': 'count', ('ts', 'dce_rpc'): 'time', 'rtt': 'interval', 'named_pipe': 'string', 'endpoint': 'string', 'operation': 'string', ('ts', 'dhcp'): 'time', 'uids': 'set[string]', 'client_addr': 'addr', 'server_addr': 'addr', 'mac': 'string', 'host_name': 'string', 'client_fqdn': 'string', 'domain': 'string', 'requested_addr': 'addr', 'assigned_addr': 'addr', 'lease_time': 'interval', 'client_message': 'string', 'server_message': 'string', 'msg_types': 'vector[string]', ('ts', 'dnp3'): 'time', 'fc_request': 'string', 'fc_reply': 'string', 'iin': 'count', ('ts', 'dns'): 'time', ('proto', 'dns'): 'enum', 'trans_id': 'count', 'query': 'string', 'qclass': 'count', 'qclass_name': 'string', 'qtype': 'count', 'qtype_name': 'string', 'rcode': 'count', 'rcode_name': 'string', 'AA': 'bool', 'TC': 'bool', 'RD': 'bool', 'RA': 'bool', 'Z': 'count', 'answers': 'vector[string]', 'TTLs': 'vector[interval]', 'rejected': 'bool', ('ts', 'dns_red'): 'time', 'num': 'count', ('ts', 'dpd'): 'time', ('proto', 'dpd'): 'enum', 'analyzer': 'string', 'failure_reason': 'string', 'server_a': 'addr', 'server_p': 'port', ('service', 'etc_viz'): 'set[string]', 'viz_stat': 'string', 'c2s_viz.size': 'count', 'c2s_viz.enc_dev': 'double', 'c2s_viz.enc_frac': 'double', 'c2s_viz.pdu1_enc': 'bool', 'c2s_viz.clr_frac': 'double', 'c2s_viz.clr_ex': 'string', 's2c_viz.size': 'count', 's2c_viz.enc_dev': 'double', 's2c_viz.enc_frac': 'double', 's2c_viz.pdu1_enc': 'bool', 's2c_viz.clr_frac': 'double', 's2c_viz.clr_ex': 'string', ('ts', 'files'): 'time', 'fuid': 'string', 'tx_hosts': 'set[addr]', 'rx_hosts': 'set[addr]', 'conn_uids': 'set[string]', 'source': 'string', 'depth': 'count', 'analyzers': 'set[string]', 'mime_type': 'string', 'filename': 'string', 'is_orig': 'bool', 'seen_bytes': 'count', 'total_bytes': 'count', 'missing_bytes': 'count', 'overflow_bytes': 'count', 'timedout': 'bool', 'parent_fuid': 'string', 'md5': 'string', 'sha1': 'string', 'sha256': 'string', ('extracted', 'files'): 'string', 'extracted_cutoff': 'bool', 'extracted_size': 'count', ('ts', 'files_red'): 'vector[time]', ('extracted', 'files_red'): 'set[string]', ('ts', 'ftp'): 'time', 'user': 'string', 'password': 'string', 'command': 'string', 'arg': 'string', 'file_size': 'count', 'reply_code': 'count', 'reply_msg': 'string', 'data_channel.passive': 'bool', 'data_channel.orig_h': 'addr', 'data_channel.resp_h': 'addr', 'data_channel.resp_p': 'port', ('ts', 'http'): 'time', 'trans_depth': 'count', 'method': 'string', ('host', 'http'): 'string', 'uri': 'string', 'referrer': 'string', ('version', 'http'): 'string', 'user_agent': 'string', 'origin': 'string', 'request_body_len': 'count', 'response_body_len': 'count', 'status_code': 'count', 'status_msg': 'string', 'info_code': 'count', 'info_msg': 'string', 'tags': 'set[enum]', 'username': 'string', 'proxied': 'set[string]', 'orig_fuids': 'vector[string]', 'orig_filenames': 'vector[string]', 'orig_mime_types': 'vector[string]', 'resp_fuids': 'vector[string]', 'resp_filenames': 'vector[string]', 'resp_mime_types': 'vector[string]', ('ts', 'http_red'): 'time', ('host', 'http_red'): 'string', ('version', 'http_red'): 'string', 'post_body': 'string', ('ts', 'intel'): 'time', 'seen.indicator': 'string', 'seen.indicator_type': 'enum', 'seen.where': 'enum', 'matched': 'set[enum]', 'sources': 'set[string]', 'file_mime_type': 'string', 'file_desc': 'string', ('ts', 'irc'): 'time', 'nick': 'string', 'value': 'string', 'addl': 'string', 'dcc_file_name': 'string', 'dcc_file_size': 'count', 'dcc_mime_type': 'string', ('ts', 'kerberos'): 'time', 'request_type': 'string', 'client': 'string', ('service', 'kerberos'): 'string', 'success': 'bool', 'error_msg': 'string', ('from', 'kerberos'): 'time', 'till': 'time', 'cipher': 'string', 'forwardable': 'bool', 'renewable': 'bool', 'client_cert_subject': 'string', 'client_cert_fuid': 'string', 'server_cert_subject': 'string', 'server_cert_fuid': 'string', ('ts', 'known_certs'): 'time', ('host', 'known_certs'): 'addr', 'port_num': 'port', 'subject': 'string', 'issuer_subject': 'string', 'serial': 'string', ('ts', 'known_hosts'): 'time', ('host', 'known_hosts'): 'addr', ('ts', 'known_services'): 'time', ('host', 'known_services'): 'addr', 'port_proto': 'enum', ('service', 'known_services'): 'set[string]', ('ts', 'modbus'): 'time', 'func': 'string', 'exception': 'string', ('ts', 'mqtt_connect'): 'time', 'proto_name': 'string', 'proto_version': 'string', 'client_id': 'string', 'connect_status': 'string', 'will_topic': 'string', 'will_payload': 'string', ('ts', 'mqtt_publish'): 'time', 'from_client': 'bool', 'retain': 'bool', 'qos': 'string', 'status': 'string', 'topic': 'string', 'payload': 'string', 'payload_len': 'count', ('ts', 'mqtt_subscribe'): 'time', 'action': 'enum', 'topics': 'vector[string]', 'qos_levels': 'vector[count]', 'granted_qos_level': 'count', 'ack': 'bool', ('ts', 'mysql'): 'time', 'cmd': 'string', 'rows': 'count', 'response': 'string', ('ts', 'namecache'): 'time', 'lookups': 'count', 'hit_rate_conn': 'double', 'hit_rate_conn_orig_h': 'double', 'hit_rate_conn_resp_h': 'double', 'hit_rate_conn_prod': 'double', 'hit_rate_conn_prod_orig_h': 'double', 'hit_rate_conn_prod_resp_h': 'double', 'hit_rate_conn_int_h': 'double', 'hit_rate_conn_ext_h': 'double', 'src_dns_a': 'count', 'src_dns_aaaa': 'count', 'src_dns_a6': 'count', 'src_dns_ptr': 'count', 'src_unknown': 'count', 'cache_entries': 'count', 'cache_add_tx_ev': 'count', 'cache_add_tx_mpg': 'count', 'cache_add_rx_ev': 'count', 'cache_add_rx_mpg': 'count', 'cache_add_rx_new': 'count', 'cache_del_mpg': 'count', ('ts', 'notice'): 'time', ('proto', 'notice'): 'enum', 'note': 'enum', 'msg': 'string', 'sub': 'string', 'src': 'addr', 'dst': 'addr', 'p': 'port', 'n': 'count', 'peer_descr': 'string', 'actions': 'set[enum]', 'email_dest': 'set[string]', 'suppress_for': 'interval', 'remote_location.country_code': 'string', 'remote_location.region': 'string', 'remote_location.city': 'string', 'remote_location.latitude': 'double', 'remote_location.longitude': 'double', ('ts', 'ntlm'): 'time', 'hostname': 'string', 'domainname': 'string', 'server_nb_computer_name': 'string', 'server_dns_computer_name': 'string', 'server_tree_name': 'string', ('ts', 'ntp'): 'time', ('version', 'ntp'): 'count', 'mode': 'count', 'stratum': 'count', 'poll': 'interval', 'precision': 'interval', 'root_delay': 'interval', 'root_disp': 'interval', 'ref_id': 'string', 'ref_time': 'time', 'org_time': 'time', 'rec_time': 'time', 'xmt_time': 'time', 'num_exts': 'count', ('ts', 'ocsp'): 'time', 'id': 'string', 'hashAlgorithm': 'string', 'issuerNameHash': 'string', 'issuerKeyHash': 'string', 'serialNumber': 'string', 'certStatus': 'string', 'revoketime': 'time', 'revokereason': 'string', 'thisUpdate': 'time', 'nextUpdate': 'time', ('ts', 'open_conn'): 'time', ('proto', 'open_conn'): 'enum', ('service', 'open_conn'): 'string', ('ts', 'packet_filter'): 'time', 'filter': 'string', 'init': 'bool', ('ts', 'pe'): 'time', 'machine': 'string', 'compile_ts': 'time', 'os': 'string', 'subsystem': 'string', 'is_exe': 'bool', 'is_64bit': 'bool', 'uses_aslr': 'bool', 'uses_dep': 'bool', 'uses_code_integrity': 'bool', 'uses_seh': 'bool', 'has_import_table': 'bool', 'has_export_table': 'bool', 'has_cert_table': 'bool', 'has_debug_data': 'bool', 'section_names': 'vector[string]', ('ts', 'radius'): 'time', 'framed_addr': 'addr', 'remote_ip': 'addr', 'connect_info': 'string', 'result': 'string', 'ttl': 'interval', ('ts', 'rdp'): 'time', 'cookie': 'string', 'security_protocol': 'string', 'keyboard_layout': 'string', 'client_build': 'string', 'client_name': 'string', 'client_dig_product_id': 'string', 'desktop_width': 'count', 'desktop_height': 'count', 'requested_color_depth': 'string', 'cert_type': 'string', 'cert_count': 'count', 'cert_permanent': 'bool', 'encryption_level': 'string', 'encryption_method': 'string', ('ts', 'reporter'): 'time', ('level', 'reporter'): 'enum', 'location': 'string', ('ts', 'rfb'): 'time', 'client_major_version': 'string', 'client_minor_version': 'string', 'server_major_version': 'string', 'server_minor_version': 'string', 'authentication_method': 'string', 'auth': 'bool', 'share_flag': 'bool', 'desktop_name': 'string', 'width': 'count', 'height': 'count', ('ts', 'signatures'): 'time', 'src_addr': 'addr', 'src_port': 'port', 'dst_addr': 'addr', 'dst_port': 'port', 'sig_id': 'string', 'event_msg': 'string', 'sub_msg': 'string', 'sig_count': 'count', 'host_count': 'count', ('ts', 'sip'): 'time', 'date': 'string', 'request_from': 'string', 'request_to': 'string', 'response_from': 'string', 'response_to': 'string', 'reply_to': 'string', 'call_id': 'string', 'seq': 'string', 'request_path': 'vector[string]', 'response_path': 'vector[string]', 'warning': 'string', 'content_type': 'string', ('ts', 'smb_files'): 'time', ('path', 'smb_files'): 'string', 'name': 'string', 'size': 'count', 'prev_name': 'string', 'times.modified': 'time', 'times.accessed': 'time', 'times.created': 'time', 'times.changed': 'time', 'data_offset_req': 'count', 'data_len_req': 'count', 'data_len_rsp': 'count', ('ts', 'smb_mapping'): 'time', ('path', 'smb_mapping'): 'string', ('service', 'smb_mapping'): 'string', 'native_file_system': 'string', 'share_type': 'string', ('ts', 'smtp'): 'time', 'helo': 'string', 'mailfrom': 'string', 'rcptto': 'set[string]', ('from', 'smtp'): 'string', 'to': 'set[string]', 'cc': 'set[string]', 'msg_id': 'string', 'in_reply_to': 'string', 'x_originating_ip': 'addr', 'first_received': 'string', 'second_received': 'string', 'last_reply': 'string', ('path', 'smtp'): 'vector[addr]', 'tls': 'bool', 'fuids': 'vector[string]', 'is_webmail': 'bool', ('ts', 'snmp'): 'time', ('version', 'snmp'): 'string', 'community': 'string', 'get_requests': 'count', 'get_bulk_requests': 'count', 'get_responses': 'count', 'set_requests': 'count', 'display_string': 'string', 'up_since': 'time', ('ts', 'socks'): 'time', ('version', 'socks'): 'count', 'request.host': 'addr', 'request.name': 'string', 'request_p': 'port', 'bound.host': 'addr', 'bound.name': 'string', 'bound_p': 'port', ('ts', 'software'): 'time', ('host', 'software'): 'addr', 'host_p': 'port', 'software_type': 'enum', 'version.major': 'count', 'version.minor': 'count', 'version.minor2': 'count', 'version.minor3': 'count', 'version.addl': 'string', 'unparsed_version': 'string', ('ts', 'ssh'): 'time', ('version', 'ssh'): 'count', 'auth_success': 'bool', 'auth_attempts': 'count', 'direction': 'enum', 'server': 'string', 'cipher_alg': 'string', 'mac_alg': 'string', 'compression_alg': 'string', 'kex_alg': 'string', 'host_key_alg': 'string', 'host_key': 'string', ('ts', 'ssl'): 'time', ('version', 'ssl'): 'string', 'curve': 'string', 'server_name': 'string', 'resumed': 'bool', 'last_alert': 'string', 'next_protocol': 'string', 'established': 'bool', 'ssl_history': 'string', 'cert_chain_fps': 'vector[string]', 'client_cert_chain_fps': 'vector[string]', 'sni_matches_cert': 'bool', 'validation_status': 'string', 'ja3': 'string', 'ja3s': 'string', ('ts', 'ssl_red'): 'time', ('version', 'ssl_red'): 'string', 'cert_chain_fuids': 'vector[string]', 'client_cert_chain_fuids': 'vector[string]', 'issuer': 'string', 'client_subject': 'string', 'client_issuer': 'string', ('ts', 'stats'): 'time', 'mem': 'count', 'pkts_proc': 'count', 'bytes_recv': 'count', 'pkts_dropped': 'count', 'pkts_link': 'count', 'pkt_lag': 'interval', 'events_proc': 'count', 'events_queued': 'count', 'active_tcp_conns': 'count', 'active_udp_conns': 'count', 'active_icmp_conns': 'count', 'tcp_conns': 'count', 'udp_conns': 'count', 'icmp_conns': 'count', 'timers': 'count', 'active_timers': 'count', 'files': 'count', 'active_files': 'count', 'dns_requests': 'count', 'active_dns_requests': 'count', 'reassem_tcp_size': 'count', 'reassem_file_size': 'count', 'reassem_frag_size': 'count', 'reassem_unknown_size': 'count', ('ts', 'syslog'): 'time', ('proto', 'syslog'): 'enum', 'facility': 'string', 'severity': 'string', ('ts', 'traceroute'): 'time', ('proto', 'traceroute'): 'string', ('ts', 'tunnel'): 'time', 'tunnel_type': 'enum', ('ts', 'weird'): 'time', 'notice': 'bool', ('ts', 'weird_red'): 'time', ('ts', 'x509'): 'time', 'fingerprint': 'string', 'certificate.version': 'count', 'certificate.serial': 'string', 'certificate.subject': 'string', 'certificate.issuer': 'string', 'certificate.not_valid_before': 'time', 'certificate.not_valid_after': 'time', 'certificate.key_alg': 'string', 'certificate.sig_alg': 'string', 'certificate.key_type': 'string', 'certificate.key_length': 'count', 'certificate.exponent': 'string', 'certificate.curve': 'string', 'san.dns': 'vector[string]', 'san.uri': 'vector[string]', 'san.email': 'vector[string]', 'san.ip': 'vector[addr]', 'basic_constraints.ca': 'bool', 'basic_constraints.path_len': 'count', 'host_cert': 'bool', 'client_cert': 'bool', ('ts', 'x509_red'): 'time'}


skip_log_prefix = ('LICENSE', 'README', '.capture_loss.', '.capture_loss_', '.conn.', '.conn_', '.dns.', '.dns_', '.env_vars', '.http.', '.http_', '.known_certs.', '.known_certs_', '.notice.', '.notice_', '.ntlm.', '.ntlm_', '.rotated.', '.ssl.', '.ssl_', '.stats.', '.stats_', '.x509.', '.x509_', '.startup', '.cmdline', '.pid', 'conn-summary', 'stderr', 'stdout')		#Note, the following are actual zeek logs: capture_loss, files, loaded_scripts, notice, packet_filter, stats, weird
skip_log_suffix = ('.pcap', '.tar.gz', '.tar', '.zip', '.zng', '.zng.gz')				#.log.gz is TSV, .zson.gz is json, .ndjson.gz is NL-delimited json, and .zng is a zed special format


#======== Functions
def create_simulated_headers() -> Tuple[Dict, Dict, Dict]:
	"""Create dictionaries with simulated header blocks, "#fields" lines, and "#types" lines for each file type."""

	local_header_lines = {}										#Keys are file_path, values are lists of header strings
	local_field_name_lists = {}									#Keys are file_path, values are lists of field names
	local_field_type_lists = {}									#Keys are file_path, values are lists of field types
	#master_types = {}										#Keys are file_path, values are dictionaries of field->type.

	for hb in raw_header_blocks:

		h_list = hb.split('\n')

		pared_h_list = []

		file_path = ''
		field_list = []
		type_list = []
		for one_line in h_list:
			if one_line.startswith('#path'):
				file_path = one_line.split('\t')[1]
			elif one_line.startswith('#fields'):
				field_list = one_line.split('\t')[1:]
			elif one_line.startswith('#types'):
				type_list = one_line.split('\t')[1:]

			#if not one_line.startswith(('#open', '#close')):
			pared_h_list.append(one_line)

		assert len(field_list) == len(type_list)

		#if field_list and type_list:
		#	if file_path not in master_types:
		#		master_types[file_path] = {}
		#	types_of = dict(zip(field_list, type_list))
		#	for field_name, field_type in types_of.items():
		#		master_types[file_path][field_name] = field_type
		#else:
		#	print(file_path + " is missing one or both of field and type lines.")

		if file_path:
			if file_path in local_header_lines:
				sys.stderr.write(file_path + " being added twice in zcutter.py .\n")
				sys.stderr.flush()
			local_header_lines[file_path] = pared_h_list
			local_field_name_lists[file_path] = field_list
			local_field_type_lists[file_path] = type_list
		else:
			sys.stderr.write("No #path line or missing #path value in zcutter.py .\n")
			sys.stderr.flush()

	return (local_header_lines, local_field_name_lists, local_field_type_lists)


def Debug(DebugStr: str) -> None:
	"""Prints a note to stderr."""

	if args['verbose']:
		sys.stderr.write(DebugStr + '\n')
		sys.stderr.flush()


def fail(fail_message: str) -> None:
	"""Print a failure notice and exit."""

	sys.stderr.write(str(fail_message) + ', exiting.\n')
	sys.stderr.flush()
	sys.exit(1)


def print_line(output_line: str, out_h: Union[TextIO, None]) -> None:
	"""Print or log the output line.  If out_h is set, use that as a handle to which to write the line, otherwise print to stdout."""

	try:
		if out_h:
			out_h.write(output_line + '\n')
		else:
			print(output_line)
	except (BrokenPipeError, KeyboardInterrupt):
		sys.stderr.close()									#To avoid printing the BrokenPipeError warning
		sys.exit(0)


def mkdir_p(path: str) -> None:
	"""Create an entire directory branch.  Will not complain if the directory already exists."""

	if not os.path.isdir(path):
		try:
			os.makedirs(path)
		except OSError as exc:
			if exc.errno == errno.EEXIST and os.path.isdir(path):
				pass
			elif exc.errno == errno.EEXIST:
				sys.stderr.write(path + ' exists, so we cannot create it as a directory.  Exiting.\n')
				sys.stderr.flush()
				sys.exit(1)
			else:
				raise


def open_bzip2_file_to_tmp_file(bzip2_filename: str) -> str:
	"""Open up a bzip2 file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, bz2.BZ2File(bzip2_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding bzip2 file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def open_gzip_file_to_tmp_file(gzip_filename: str) -> str:
	"""Open up a gzip file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, gzip.GzipFile(gzip_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
	except zlib.error:
		sys.stderr.write(str(gzip_filename) + " could not be decompressed with zlib, skipping.\n")
		if os.path.exists(tmp_path):
			os.remove(tmp_path)
		tmp_path = ''
	except gzip.BadGzipFile:
		sys.stderr.write(str(gzip_filename) + " is not a gzip file, skipping.\n")
		if os.path.exists(tmp_path):
			os.remove(tmp_path)
		tmp_path = ''
	except EOFError:
		sys.stderr.write(str(gzip_filename) + " appears to be truncated, skipping.\n")
		if os.path.exists(tmp_path):
			os.remove(tmp_path)
		tmp_path = ''
	except:												# pylint: disable=bare-except
		sys.stderr.write("While expanding gzip file, unable to write to " + str(tmp_path) + ', skipping.\n')
		if os.path.exists(tmp_path):
			os.remove(tmp_path)
		tmp_path = ''
		#raise

	return tmp_path


def data_line_of(field_name_list: List[str], field_value_list: List, input_type: str, cl_args: Dict, zeek_file_path: str) -> str:
	"""Provide a formatted output line from the raw data fields."""

	if not zeek_file_path:
		Debug('Missing zeek_file_path in data_line_of')

	output_line: str = ''
	no_empty_out_dict: Dict = {}

	if cl_args['tsv']:
		output_line = cl_args['fieldseparator'].join(field_value_list)
	elif cl_args['json']:
		out_dict = dict(zip(field_name_list, field_value_list))
		if '_path' not in out_dict:
			out_dict['_path'] = zeek_file_path
		no_empty_out_dict = {k: v for k, v in out_dict.items() if v != ''}
		output_line = json.dumps(no_empty_out_dict)
	elif input_type == 'tsv':
		output_line = cl_args['fieldseparator'].join(field_value_list)
	elif input_type == 'json':
		out_dict = dict(zip(field_name_list, field_value_list))
		if '_path' not in out_dict:
			out_dict['_path'] = zeek_file_path
		no_empty_out_dict = {k: v for k, v in out_dict.items() if v != ''}
		output_line = json.dumps(no_empty_out_dict)

	return output_line


def print_sim_tsv_header(line_dict: Dict, requested_fields: List, cl_args: Dict, output_h: Union[TextIO, None]) -> None:
	"""Generate a simulated TSV header for the case where we input json and output in TSV."""

	if "_path" in line_dict:
		file_path = line_dict['_path']
		type_of = dict(zip(field_name_lists[file_path], field_type_lists[file_path]))
		limited_types = []
		for one_field in requested_fields:
			limited_types.append(type_of[one_field])
		for one_line in header_lines[file_path]:
			if one_line.startswith('#fields'):
				if cl_args['_min_hdr']:
					print_line(cl_args['fieldseparator'].join(requested_fields), output_h)
				else:
					print_line('#fields' + cl_args['fieldseparator'] + cl_args['fieldseparator'].join(requested_fields), output_h)
			elif not cl_args['_min_hdr']:
				if one_line.startswith('#types'):
					print_line('#types' + cl_args['fieldseparator'] + cl_args['fieldseparator'].join(limited_types), output_h)
				#No  special handling needed for the "#path" line as the templates already have a correct #path line.
				else:
					print_line(one_line, output_h)
	else:
		fail("_path missing from first json record.")


def correct_var_format(field_str_value: str, this_field_name: str, this_file_path: str, correct_field_types: Dict, cl_args: Dict) -> Union[str, int, float, bool, list]:
	"""Json requires numbers (ints and floats) and boolean values to be
	presented as such, rather than values inside strings.  This function
	takes a specific field and returns it as the correct python type so
	it can be correctly formatted as json."""

	typed_field: Union[str, int, float, bool, list] = ''

	#Check for both this_field_name and (this_field_name, this_file_path) as keys
	mytype = correct_field_types.get(this_field_name, correct_field_types.get((this_field_name, this_file_path), ''))
	if field_str_value == '':
		typed_field = ''
	elif field_str_value == '-' and mytype in ('port', 'count', 'int', 'time', 'interval', 'double'):
		typed_field = ''
	elif field_str_value == '(empty)' and mytype.startswith(('vector[', 'set[')):
		typed_field = []
	elif this_field_name == 'ts' and cl_args['readabledate']:
		typed_field = datetime.datetime.fromtimestamp(float(field_str_value)).strftime(cl_args['dateformat'])
	elif mytype in ('port', 'count', 'int'):
		typed_field = int(field_str_value)
	elif mytype in ('time', 'interval', 'double'):
		typed_field = float(field_str_value)
	elif mytype == 'bool':
		if field_str_value in ('t', 'T', 'true', True,):
			typed_field = True
		elif field_str_value in ('f', 'F', 'false', False,):
			typed_field = False
		else:
			typed_field = bool(field_str_value)
	elif mytype.startswith(('vector[', 'set[')):
		if len(field_str_value) > 0:
			#This may need tweaking if the upcoming conversion to str (for TSV output) or json.dumps (for json output) don't correctly format the values inside the list.
			typed_field = field_str_value.split(',')
		else:
			typed_field = ''
	else:
		typed_field = str(field_str_value)

	return typed_field


def process_log_lines(log_file: str, original_filename: str, requested_fields: List[str], cl_args: Dict) -> None:
	"""Will process all the lines in an uncompressed log file."""

	if 'data_line_seen' not in process_log_lines.__dict__:
		process_log_lines.data_line_seen = False						# type: ignore

	tsv_headers_printed: bool = False

	in_file_format: str = ''
	field_line_fields: List = []
	type_line_fields: List = []
	field_types: Dict = {}										#Dictionary whose keys are ALL field names and whose values are the corresponding field types.  This has all the field names, even when we limit the output to only certain fields.

	field_location: Dict[str, int] = {}								#Remembers in which column we can find a given field name.

	Debug("Processing: " + log_file)
	log_h: Union[TextIO, None] = None
	with open(log_file, 'r', encoding='utf8') as log_h:
		output_h: Union[TextIO, None] = None
		if cl_args['outputdir'] and original_filename not in ('-', '', None):			#If original_filename is one of these it's from stdin, so we don't create a handle and the output continues to go to stdout.
			output_filename = os.path.join(cl_args['outputdir'], original_filename.replace('.gz', '').replace('.bz2', ''))		#We're writing out uncompressed no matter what the input format was.
			if output_filename:
				if os.path.exists(output_filename):					# pylint: disable=no-else-return
					Debug(output_filename + " exists, late skipping.")
					log_h.close()
					return
				else:
					mkdir_p(os.path.dirname(os.path.join(cl_args['outputdir'], original_filename)))
					output_h = open(output_filename, "a+", encoding="utf8")		# pylint: disable=consider-using-with

		limited_fields: List = []
		file_path = ''										#The zeek record type, like "dns", "http".  In TSV, found on #path line, in json, in key "_path"
		for _, raw_line in enumerate(log_h):							#_ is the line count
			raw_line = raw_line.rstrip()
			if not in_file_format:
				#FIXME - handle case where stdin gets both TSV and json input lines
				if raw_line == r'#separator \x09':					#Use raw string so python won't turn \x09 into an actual tab
					in_file_format = 'tsv'
				#elif raw_line == '':							#conn-summary files start with a blank line, but we've skipped these already.
				#	pass
				elif raw_line.startswith('{'):
					in_file_format = 'json'
					field_dict_1 = json.loads(raw_line)
					if "_path" in field_dict_1:
						file_path = field_dict_1["_path"]
						del field_dict_1["_path"]
					if "_write_ts" in field_dict_1:
						del field_dict_1["_write_ts"]
					if requested_fields == []:
						limited_fields = list(field_dict_1.keys())
					elif cl_args['negate']:
						for one_field in field_dict_1.keys():
							if one_field not in requested_fields:
								limited_fields.append(one_field)
					else:
						for one_field in requested_fields:
							if one_field in field_dict_1.keys():
								limited_fields.append(one_field)
				elif raw_line.startswith('#separator'):
					sys.stderr.write('Unrecognized separator in ' + log_file + ' , skipping.\n')
					return
				else:
					sys.stderr.write('Unrecognized starting line in ' + log_file + ' , skipping.\n')
					return

			if (cl_args['allheaders'] or cl_args['allminheaders'] or (cl_args['_one_hdr'] and process_log_lines.data_line_seen is False)) and (cl_args['tsv'] and in_file_format == 'json' and tsv_headers_printed is False):		# type: ignore # pylint: disable=too-many-boolean-expressions
				#We're inputting json and forcing TSV output.  Now we have to print simulated TSV headers.
				print_sim_tsv_header(json.loads(raw_line), limited_fields, cl_args, output_h)
				tsv_headers_printed = True

			out_line = ''
			if raw_line.startswith('#'):
				#Process header lines
				if raw_line.startswith('#fields'):
					#read fields into dictionary (fieldname->adjusted column number)
					field_location = {}
					field_line_fields = raw_line.split('\t')[1:]			#List of the fields in the #fields line.  We have to use [1:] to skip over '#fields'
					for field_num, one_field in enumerate(field_line_fields):
						field_location[one_field] = field_num
					limited_fields = []
					if requested_fields == []:
						limited_fields = field_line_fields.copy()
					elif cl_args['negate']:
						for one_field in field_location:
							if one_field not in requested_fields:
								limited_fields.append(one_field)
					else:
						for one_field in requested_fields:
							if one_field in field_location:
								limited_fields.append(one_field)
					out_line = cl_args['fieldseparator'].join(limited_fields)
					if not cl_args['_min_hdr']:					#Prepend "#fields" unless we're doing minimal headers
						out_line = '#fields' + cl_args['fieldseparator'] + out_line

				elif raw_line.startswith('#types'):
					type_list = ['#types', ]
					type_line_fields = raw_line.split('\t')[1:]			#List of the fields in the #types line.  We have to use [1:] to skip over '#types'
					if requested_fields == []:
						type_list = raw_line.split('\t')			#Grab everything, including the leading "#types"
					elif not field_location:
						#Fail case where #types shows up before #fields
						fail('field_location is not set when attempting to process #types line: is there a chance #types showed up before #fields?')
					elif cl_args['negate']:
						for line_index, one_type in enumerate(type_line_fields):
							if line_index not in field_location.values():
								type_list.append(one_type)
					else:
						for one_label in requested_fields:
							field_index = field_location.get(one_label)
							if field_index is not None:
								type_list.append(type_line_fields[field_index])
					if not cl_args['_min_hdr']:
						out_line = cl_args['fieldseparator'].join(type_list)
				elif raw_line.startswith('#path'):
					file_path = raw_line.split('\t')[1]
					if not cl_args['_min_hdr']:
						out_line = raw_line
				else:
					if not cl_args['_min_hdr']:
						out_line = raw_line

				if field_line_fields and type_line_fields and not field_types:
					#Build the field_types dictionary
					field_types = dict(zip(field_line_fields, type_line_fields))

				if not (cl_args['allheaders'] or cl_args['allminheaders'] or (cl_args['_one_hdr'] and process_log_lines.data_line_seen is False)):		# type: ignore
					out_line = ''
				if cl_args['json']:
					out_line = ''
			else:
				process_log_lines.data_line_seen = True					# type: ignore
				#Process non-header lines
				if in_file_format == 'tsv':
					if not field_location:
						fail("Warning, field_location is not set as we enter live data lines")
					#process tsv line
					data_fields = raw_line.split('\t')
					out_fields = []
					#FIXME - handle case where no fields were requested.
					for one_field in limited_fields:
						try:
							field_in_string_format = data_fields[field_location[one_field]]
						except IndexError:
							field_in_string_format = ''

						#We _should_ have already built a field_types dictionary from the header fields.  If not, we fall back on the static one at the top of this program.
						if cl_args['json']:
							out_fields.append(correct_var_format(field_in_string_format, one_field, file_path, field_types or static_field_types, cl_args))
						else:
							if one_field == 'ts' and cl_args['readabledate']:
								out_fields.append(datetime.datetime.fromtimestamp(float(field_in_string_format)).strftime(cl_args['dateformat']))
							else:
								out_fields.append(field_in_string_format)
					out_line = data_line_of(limited_fields, out_fields, in_file_format, cl_args, file_path)
				elif in_file_format == 'json':
					#Process json line
					try:
						field_dict_3 = json.loads(raw_line)
						out_fields = []
						for one_field in limited_fields:
							if requested_fields == [] or (one_field in field_dict_3) or (cl_args['negate'] and one_field not in field_dict_3):
								#We _should_ have already built a field_types dictionary from the header fields.  If not, we fall back on the static one at the top of this program.
								if cl_args['tsv']:
									if one_field == 'ts' and cl_args['readabledate']:
										out_fields.append(datetime.datetime.fromtimestamp(float(field_dict_3.get(one_field, 0.0))).strftime(cl_args['dateformat']))
									else:
										out_fields.append(str(field_dict_3.get(one_field, '')))
								else:
									out_fields.append(correct_var_format(str(field_dict_3.get(one_field, '')), one_field, file_path, field_types or static_field_types, cl_args))
							else:
								out_fields.append('')

						out_line = data_line_of(limited_fields, out_fields, in_file_format, cl_args, file_path)
					except json.decoder.JSONDecodeError:
						out_line = ''
				else:
					fail('Unrecognized file format: ' + in_file_format)

			if out_line:
				print_line(out_line, output_h)

		if output_h:
			output_h.close()
			relative_touch(original_filename, os.path.join(cl_args['outputdir'], original_filename.replace('.gz', '').replace('.bz2', '')))

	sys.stderr.flush()


def relative_touch(old_file: str, new_file_to_change: str) -> None:
	"""Make the modification time and atime of new_file_to_change to be equal to those of old_file."""

	os.utime(new_file_to_change, ns=(os.stat(old_file).st_atime_ns, os.stat(old_file).st_mtime_ns))


def link_or_copy(source_dirname: str, source_basename: str, destdir: str, dest_relative_file: str) -> None:
	"""Create a hardlink from source to destdir (which may not yet exist.)"""

	complete_source = os.path.join(source_dirname, source_basename)

	if not os.path.isdir(destdir):
		try:
			mkdir_p(destdir)
		except:											# pylint: disable=bare-except
			Debug("Unable to create " + destdir + " , skipping " + complete_source)
			return

	if os.path.isdir(destdir) and os.access(destdir, os.W_OK):
		complete_dest = os.path.join(destdir, dest_relative_file)
		if os.path.exists(complete_dest):
			Debug('Skipping copy of ' + complete_source + ' as it already exists in ' + destdir)
		else:
			try:
				os.link(complete_source, complete_dest, follow_symlinks=False)		#Don't follow symlinks as these may point to sensitive files outside the log tree.
				#No need to adjust timestamp as hardlinks share the underlying timestamps
			except OSError:
				#Debug('Unable to hardlink, so we will do a file copy instead')
				try:
					shutil.copy2(complete_source, complete_dest, follow_symlinks=False)		#Copy the file, preserving metadata if possible
					relative_touch(complete_source, complete_dest)
				except:									# pylint: disable=bare-except
					Debug('Unable to link or copy ' + complete_source + ' to ' + destdir + ' , skipping.')


def process_log(log_source: str, fields: List[str], cl_args: Dict) -> None:
	"""Process a single source file or stdin."""

	source_file = ''
	close_temp = False
	delete_temp = False

	try:
		full_source_path, source_basename = os.path.split(log_source)
	except:												# pylint: disable=bare-except
		full_source_path = ''
		source_basename = ''

	if log_source not in ('-', '', None) and cl_args['outputdir']:
		output_filename = os.path.join(cl_args['outputdir'], log_source.replace('.gz', '').replace('.bz2', ''))		#We're writing out uncompressed no matter what the input format was.
		if output_filename and os.path.exists(output_filename):
			Debug(output_filename + " exists, skipping.")
			return

	#Read from stdin
	if log_source in ('-', '', None):
		Debug('Reading log lines from stdin.')
		tmp_log = tempfile.NamedTemporaryFile(delete=True)					# pylint: disable=consider-using-with
		tmp_log.write(sys.stdin.buffer.read())
		tmp_log.flush()
		source_file = tmp_log.name
		close_temp = True
	elif not os.path.exists(log_source):
		Debug('Skipping nonexistent file ' + log_source)
	#Set up source log file; next 2 sections check for and handle compressed file extensions first, then final "else" treats the source as an uncompressed log file
	elif source_basename.startswith(skip_log_prefix) or source_basename.endswith(skip_log_suffix):		#Log files that are not TSV/json formatted log files
		Debug("Linking or copying non-TSV/json file " + log_source)
		if cl_args['outputdir']:
			#Make a hardlink to the file if possible (or copy if not) in the output directory
			link_or_copy(full_source_path, source_basename, os.path.realpath(cl_args['outputdir']), log_source)
		else:
			#We're sending content to stdout - do not process the file at all to match zeek-cut.
			pass
		return
	elif log_source.endswith('.bz2'):
		Debug('Reading bzip2 compressed logs from file ' + log_source)
		source_file = open_bzip2_file_to_tmp_file(log_source)
		delete_temp = True
	elif log_source.endswith('.gz'):
		Debug('Reading gzip compressed logs from file ' + log_source)
		source_file = open_gzip_file_to_tmp_file(log_source)
		delete_temp = True
	else:
		Debug('Reading logs from file ' + log_source)
		source_file = log_source

	#Try to process file first
	if source_file:
		if os.path.exists(source_file) and os.access(source_file, os.R_OK):
			try:
				process_log_lines(source_file, log_source, fields, cl_args)
			except (FileNotFoundError, IOError):
				sys.stderr.write("Unable to open file " + str(log_source) + ', exiting.\n')
				raise
		else:
			sys.stderr.write("Unable to open file " + str(source_file) + ', skipping.\n')

	if close_temp:
		tmp_log.close()

	if delete_temp and source_file != log_source and os.path.exists(source_file):
		os.remove(source_file)


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='zcutter.py version ' + str(__version__) + ': returns fields from zeek log files.')
	parser.add_argument('fields', help='fields to display', default=[], nargs='*')
	parser.add_argument('-n', '--negate', help='Negate test; show all columns EXCEPT those specified.', required=False, default=False, action='store_true')
	parser.add_argument('-c', '--firstheaders', help='Include first format header blocks in the output.', required=False, default=False, action='store_true')
	parser.add_argument('-C', '--allheaders', help='Include all format header blocks in the output.', required=False, default=False, action='store_true')
	parser.add_argument('-m', '--firstminheaders', help='Include first format header blocks in the output in minimal view.', required=False, default=False, action='store_true')
	parser.add_argument('-M', '--allminheaders', help='Include all format header blocks in the output in minimal view.', required=False, default=False, action='store_true')
	parser.add_argument('-F', '--fieldseparator', help='character that separates output fields.', required=False, default='\t')
	parser.add_argument('-d', '--readabledate', help='Convert ts to readable format.', required=False, default=False, action='store_true')
	parser.add_argument('-D', '--dateformat', help='Format to use for date output.', required=False, default='%FT%T+0000')		#Should be using %z , but it comes up empty.  need to force +0000  https://docs.python.org/3/library/datetime.html
	parser.add_argument('-t', '--tsv', help='Force TSV output', required=False, default=False, action='store_true')
	parser.add_argument('-j', '--json', help='Force json output', required=False, default=False, action='store_true')
	parser.add_argument('-v', '--verbose', help='Be verbose', required=False, default=False, action='store_true')
	parser.add_argument('-o', '--outputdir', help='Directory in which to place corresponding (uncompressed) output files', required=False, default='')
	parser.add_argument('-r', '--read', help='Log file(s) from which to read logs (place this option last)', required=False, default=[], nargs='*')
	#May need to manually transfer params misplaced as files into the fields array.  Perhaps by extension?
	args = vars(parser.parse_args())

	if args['tsv'] and args['json']:
		fail("Cannot force both tsv and json output at the same time.")

	if (int(args['firstheaders']) + int(args['allheaders']) + int(args['firstminheaders']) + int(args['allminheaders'])) > 1:
		fail('Please pick just one header format type')

	if args['outputdir'] and (not os.path.isdir(args['outputdir'])):
		fail(str(args['outputdir']) + " is not a directory")
	if args['outputdir'] and (not os.access(args['outputdir'], os.W_OK)):
		fail(str(args['outputdir']) + " is not writeable")

	if args['dateformat'] != '%FT%T+0000':
		args['readabledate'] = True

	args['_hdr'] = args['allheaders'] or args['allminheaders'] or args['firstheaders'] or args['firstminheaders']
	args['_min_hdr'] = args['allminheaders'] or args['firstminheaders']
	args['_one_hdr'] = args['firstheaders'] or args['firstminheaders']

	if args['tsv'] and args['_hdr']:								#We only need the simulated header blocks if the output is forced to TSV and the user wants headers
		header_lines, field_name_lists, field_type_lists = create_simulated_headers()
	else:
		header_lines = {}
		field_name_lists = {}
		field_type_lists = {}

	requested_field_list: list = args['fields']
	Debug('Requesting these columns: ' + str(requested_field_list))

	if not args['read']:										#If no files specified, force reading from stdin
		args['read'].append('')

	for one_file in args['read']:
		process_log(one_file, requested_field_list, args)
