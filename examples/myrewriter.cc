/*
 * iprewriter.{cc,hh} -- rewrites packet source and destination
 * Max Poletto, Eddie Kohler
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2008-2010 Meraki, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "myrewriter.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/timer.hh>
#include <click/router.hh>
CLICK_DECLS

MyIPRewriter::MyIPRewriter()
    : _udp_map(0)
{
}

MyIPRewriter::~MyIPRewriter()
{
}

void *
MyIPRewriter::cast(const char *n)
{
    if (strcmp(n, "IPRewriterBase") == 0)
	return (IPRewriterBase *)this;
    else if (strcmp(n, "TCPRewriter") == 0)
	return (TCPRewriter *)this;
    else if (strcmp(n, "MyIPRewriter") == 0)
	return this;
    else
	return 0;
}

int
MyIPRewriter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool has_udp_streaming_timeout = false;
    _udp_timeouts[0] = 60 * 5;	// 5 minutes
    _udp_timeouts[1] = 5;	// 5 seconds

    if (Args(this, errh).bind(conf)
	.read("UDP_TIMEOUT", SecondsArg(), _udp_timeouts[0])
	.read("UDP_STREAMING_TIMEOUT", SecondsArg(), _udp_streaming_timeout).read_status(has_udp_streaming_timeout)
	.read("UDP_GUARANTEE", SecondsArg(), _udp_timeouts[1])
	.consume() < 0)
	return -1;

    if (!has_udp_streaming_timeout)
	_udp_streaming_timeout = _udp_timeouts[0];
    _udp_timeouts[0] *= CLICK_HZ; // change timeouts to jiffies
    _udp_timeouts[1] *= CLICK_HZ;
    _udp_streaming_timeout *= CLICK_HZ; // IPRewriterBase handles the others
    int ret = TCPRewriter::configure(conf, errh);

    _my_input_specs.clear();
    for (auto i = 0; i < _input_specs.size(); i++) {
        const auto &is = _input_specs[i];
        MyInputSpec my_is;
        my_is.kind = is.kind;
        my_is.foutput = is.foutput;
        if (is.kind == IPRewriterInput::i_pattern) {
            IPFlowID id(*(IPFlowID *)is.u.pattern);
            MyRewriterPattern pattern;
            pattern._saddr = id.saddr();
            pattern._daddr = id.daddr();
            pattern._sport = id.sport();
            pattern._dport = id.dport();
            my_is.pattern = pattern;
        }
        _my_input_specs.push_back(my_is);
    }

    for (auto i = 0; i < _my_input_specs.size(); i++) {
        auto &is = _my_input_specs[i];
        printf("input_spec: %d %d %d\n", i, is.kind, is.foutput);
        if (is.kind == IPRewriterInput::i_pattern) {
            dump_memory_hex(&is.pattern, sizeof(MyRewriterPattern));
        }
        printf("======\n");
    }

    return ret;
}

inline IPRewriterEntry *
MyIPRewriter::get_entry(int ip_p, const IPFlowID &flowid, int input)
{
    if (ip_p == IP_PROTO_TCP)
	return TCPRewriter::get_entry(ip_p, flowid, input);
    if (ip_p != IP_PROTO_UDP)
	return 0;
    IPRewriterEntry *m = _udp_map.get(flowid);
    if (!m && (unsigned) input < (unsigned) _input_specs.size()) {
	IPRewriterInput &is = _input_specs[input];
	IPFlowID rewritten_flowid = IPFlowID::uninitialized_t();
	if (is.rewrite_flowid(flowid, rewritten_flowid, 0, IPRewriterInput::mapid_iprewriter_udp) == rw_addmap)
	    m = MyIPRewriter::add_flow(0, flowid, rewritten_flowid, _my_input_specs[input]);
    }
    return m;
}

IPRewriterEntry *
MyIPRewriter::add_flow(int ip_p, const IPFlowID &flowid,
		     const IPFlowID &rewritten_flowid, MyInputSpec &is)
{
    HashMap<IPFlowID, MyIPRewriterEntry> *map = (ip_p == IP_PROTO_TCP ? &_map_tcp : &_map_udp);
    MyIPRewriterEntry entry;
    entry.orig_flow = flowid;
    entry.changed_flow = rewritten_flowid;
    entry.port = is.foutput;

    map->insert(flowid, entry);
    return NULL;
}

void
MyIPRewriter::tcp_flow_apply(const MyIPRewriterEntry &e, WritablePacket *p) {
    assert(p->has_network_header());
    click_ip *iph = p->ip_header();

    iph->ip_src = e.changed_flow.saddr();
    iph->ip_dst = e.changed_flow.daddr();

    click_tcp *tcph = p->tcp_header();
    tcph->th_sport = e.changed_flow.sport();
    tcph->th_dport = e.changed_flow.dport();
}

void
MyIPRewriter::udp_flow_apply(const MyIPRewriterEntry &e, WritablePacket *p) {
    assert(p->has_network_header());
    click_ip *iph = p->ip_header();

    // IP header
    iph->ip_src = e.changed_flow.saddr();
    iph->ip_dst = e.changed_flow.daddr();

    // end if not first fragment
    if (!IP_FIRSTFRAG(iph))
	return;

    // TCP/UDP header
    click_udp *udph = p->udp_header();
    udph->uh_sport = e.changed_flow.sport(); // TCP ports in the same place
    udph->uh_dport = e.changed_flow.dport();
}

void
MyIPRewriter::push(int port, Packet *p_in)
{
    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();

    MyInputSpec &is = _my_input_specs[port];
    // handle non-first fragments
    if ((iph->ip_p != IP_PROTO_TCP && iph->ip_p != IP_PROTO_UDP)
        || !IP_FIRSTFRAG(iph)
        || p->transport_length() < 8) {
        if (is.kind == IPRewriterInput::i_nochange)
            checked_output_push(is.foutput, p);
	else
	    p->kill();
	return;
    }
    IPFlowID flowid(p);
    
    HashMap<IPFlowID, MyIPRewriterEntry> *map = (iph->ip_p == IP_PROTO_TCP ? &_map_tcp : &_map_udp);
    MyIPRewriterEntry *m = map->findp(flowid);

    if (!m) {			// create new mapping
        IPFlowID rewritten_flowid = IPFlowID::uninitialized_t();
        int result = is.rewrite_flowid(flowid, rewritten_flowid, p, map);
        if (result == rw_addmap) {
            MyIPRewriter::add_flow(iph->ip_p, flowid, rewritten_flowid, is);
        }
        checked_output_push(is.foutput, p);
        return;
    }

    if (iph->ip_p == IP_PROTO_TCP) {
        tcp_flow_apply(*m, p);
    } else {
        udp_flow_apply(*m, p);
    }

    checked_output_push(is.foutput, p);
}

String
MyIPRewriter::udp_mappings_handler(Element *e, void *)
{
    MyIPRewriter *rw = (MyIPRewriter *)e;
    click_jiffies_t now = click_jiffies();
    StringAccum sa;
    for (Map::iterator iter = rw->_udp_map.begin(); iter.live(); ++iter) {
	iter->flow()->unparse(sa, iter->direction(), now);
	sa << '\n';
    }
    return sa.take_string();
}

void
MyIPRewriter::add_handlers()
{
    add_read_handler("tcp_table", tcp_mappings_handler);
    add_read_handler("udp_table", udp_mappings_handler);
    add_read_handler("tcp_mappings", tcp_mappings_handler, 0, Handler::h_deprecated);
    add_read_handler("udp_mappings", udp_mappings_handler, 0, Handler::h_deprecated);
    set_handler("tcp_lookup", Handler::OP_READ | Handler::READ_PARAM, tcp_lookup_handler, 0);
    add_rewriter_handlers(true);
}

int MyInputSpec::rewrite_flowid(const IPFlowID &flowid,
                                IPFlowID &rewritten_flowid,
                                WritablePacket *p, HashMap<IPFlowID, MyIPRewriterEntry> *map) {
    pattern._sport++;
    rewritten_flowid.set_saddr(0xdeadbeef);
    rewritten_flowid.set_sport(pattern._sport);
    rewritten_flowid.set_daddr(flowid.daddr());
    rewritten_flowid.set_dport(flowid.dport());

    click_ip *iph = p->ip_header();

    iph->ip_src = rewritten_flowid.saddr();
    iph->ip_dst = rewritten_flowid.daddr();

    click_tcp *tcph = p->tcp_header();
    tcph->th_sport = rewritten_flowid.sport();
    tcph->th_dport = rewritten_flowid.dport();

    return MyIPRewriter::rw_addmap;
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(TCPRewriter UDPRewriter)
EXPORT_ELEMENT(MyIPRewriter)
