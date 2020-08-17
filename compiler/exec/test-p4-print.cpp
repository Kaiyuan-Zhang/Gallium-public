#include "p4-ir.hpp"

using namespace P4IR;
int main(int argc, char* argv[]) {
    std::vector<std::string> hdrs;
    std::unordered_map<std::string, size_t> vmap;
    for (auto& kv : CommonHdr::default_layout.headers) {
        vmap[kv.first] = hdrs.size();
        hdrs.push_back(kv.first);
    }

    AdjacencyList<PktParser::ParsingEdge> edges(hdrs.size());
    edges.set_edge(vmap["ether"], vmap["ipv4"], PktParser::ParsingEdge{"ether", "ethertype", 0x0800});
    edges.set_edge(vmap["ipv4"], vmap["udp"], PktParser::ParsingEdge{"ipv4", "protocol", 0x11});
    edges.set_edge(vmap["ipv4"], vmap["tcp"], PktParser::ParsingEdge{"ipv4", "protocol", 6});
    Graph<std::string, PktParser::ParsingEdge, AdjacencyList<PktParser::ParsingEdge>>
        parse_graph(std::move(hdrs), std::move(edges));

    auto parser = std::make_shared<PktParser>(CommonHdr::default_layout, parse_graph);
    parser->layout = CommonHdr::default_layout;

    auto meta = std::make_shared<Metadata>();

    meta->fields = {
        {"__always_1", 1},
        {"test_field", 32},
        {"should_drop", 1},
    };

// action do_tcp_snat(srcAddr, srcPort) {
//     modify_field(ipv4.srcAddr, srcAddr);
//     modify_field(tcp.src, srcPort);
// }
// 
// action do_udp_snat(srcAddr, srcPort) {
//     modify_field(ipv4.srcAddr, srcAddr);
//     modify_field(udp.src, srcPort);
//     modify_field(udp.check, 0);
// }
// 
// action do_tcp_dnat(dstAddr, dstPort) {
//     modify_field(ipv4.dstAddr, dstAddr);
//     modify_field(tcp.dst, dstPort);
// }
// 
// action do_udp_dnat(dstAddr, dstPort) {
//     modify_field(ipv4.dstAddr, dstAddr);
//     modify_field(udp.dst, dstPort);
//     modify_field(udp.check, 0);
// }

    std::vector<HeaderRef> args;
    HeaderRef d{"ipv4", "saddr"};

	auto do_tcp_snat_act = std::make_shared<Action>("do_tcp_snat");
    do_tcp_snat_act->args = {"srcAddr", "srcPort"};
    d = {"ipv4", "saddr"};
    args = {HeaderRef::Arg("srcAddr")};
    do_tcp_snat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_tcp_snat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));

	auto do_udp_snat_act = std::make_shared<Action>("do_udp_snat");
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_udp_snat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_udp_snat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_udp_snat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    
	auto do_tcp_dnat_act = std::make_shared<Action>("do_tcp_dnat");
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_tcp_dnat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_tcp_dnat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));

	auto do_udp_dnat_act = std::make_shared<Action>("do_udp_dnat");
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_udp_dnat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_udp_dnat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));
    d = {"tcp", "source"};
    args = {HeaderRef::Arg("srcPort")};
    do_udp_dnat_act->ops.emplace_back(
            std::make_shared<Operation>(d, args));


    P4IR::Program prog;
    prog.parser = parser;
    prog.meta = meta;
    prog.add_action(do_tcp_dnat_act);
    prog.add_action(do_tcp_snat_act);
    prog.add_action(do_udp_dnat_act);
    prog.add_action(do_udp_snat_act);

    auto s = std::make_shared<Stage>();
    s->type = Stage::T::TABLE;
    s->name = "in_port_tab";
    s->table_info.keys.emplace_back(HeaderRef{"ig_intr_md", "ingress_port"});
    s->table_info.actions.emplace_back("do_tcp_dnat");
    s->act = "drop";

    prog.add_stage(s);
    prog.init_stage = s->name;

    P4IR::print_p4_prog_tofino(prog, std::cout);
    return 0;
}
