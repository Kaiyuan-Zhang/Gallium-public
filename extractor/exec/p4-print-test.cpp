#include "target-p4.hpp"
#include <memory>

namespace P4 = Target::P4;

std::vector<std::tuple<std::string, int>> ethernet_fields = {
    {"dstAddr",   48},
    {"srcAddr",   48},
    {"etherType", 16},
};

std::vector<std::tuple<std::string, int>> ipv4_fields = {
    {"version"        , 4},
    {"ihl"            , 4},
    {"diffserv"       , 8},
    {"totalLen"       , 16},
    {"identification" , 16},
    {"flags"          , 3},
    {"fragOffset"     , 13},
    {"ttl"            , 8},
    {"protocol"       , 8},
    {"hdrChecksum"    , 16},
    {"srcAddr"        , 32},
    {"dstAddr"        , 32},
};

std::vector<std::tuple<std::string, int>> ports_fields = {
    {"srcPort", 16},
    {"dstPort", 16},
};

std::vector<std::tuple<std::string, int>> udp_fields = {
    {"len",   16},
    {"check", 16},
};

std::vector<std::tuple<std::string, int>> tcp_fields = {
    {"seq_no"  ,   32},
    {"ack_no"  ,   32},
    {"doff"    ,   4},
    {"resv"    ,   3},
    {"ns"      ,   1},
    {"cwr"     ,   1},
    {"ece"     ,   1},
    {"urg"     ,   1},
    {"ack"     ,   1},
    {"psh"     ,   1},
    {"rst"     ,   1},
    {"syn"     ,   1},
    {"fin"     ,   1},
    {"window"  ,   16},
    {"check"   ,   16},
    {"urg_ptr" ,   16},
};

int main(int argc, char *argv[]) {
    P4::HeaderDef ether_hdr("ethernet_t", ethernet_fields);
    P4::HeaderDef ipv4_hdr("ipv4_t", ipv4_fields);
    P4::HeaderDef ports_hdr("ports_t", ports_fields);
    P4::HeaderDef udp_hdr("udp_t", udp_fields);
    P4::HeaderDef tcp_hdr("tcp_t", tcp_fields);

    auto parse_ethernet = std::make_shared<P4::ParserStage>("parse_ethernet",
                                                            std::vector<std::string>{"ethernet"});
    auto parse_ipv4 = std::make_shared<P4::ParserStage>("parse_ipv4",
                                                        std::vector<std::string>{"ipv4"});
    auto parse_ports = std::make_shared<P4::ParserStage>("parse_ports",
                                                         std::vector<std::string>{"ports"});
    auto parse_udp = std::make_shared<P4::ParserStage>("parse_udp",
                                                       std::vector<std::string>{"udp"});
    auto parse_tcp = std::make_shared<P4::ParserStage>("parse_tcp",
                                                       std::vector<std::string>{"tcp"});

    parse_ethernet->match_field = std::make_shared<P4::HeaderRef>("ethernet", "etherType");
    parse_ethernet->add_match_rule("0x0800", parse_ipv4);
    
    parse_ipv4->match_field = std::make_shared<P4::HeaderRef>("ipv4", "protocol");
    parse_ethernet->add_match_rule("0x06", parse_ports);
    parse_ethernet->add_match_rule("0x11", parse_ports);

    parse_ports->match_field = std::make_shared<P4::HeaderRef>("ipv4", "protocol");
    parse_ports->add_match_rule("0x06", parse_tcp);
    parse_ports->add_match_rule("0x11", parse_udp);

    P4::Parser parser({parse_ethernet, parse_ipv4, parse_ports, parse_udp, parse_tcp});

    P4::Prog prog({ether_hdr, ipv4_hdr, ports_hdr, udp_hdr, tcp_hdr},
                  parser);

    prog.header_decls = {
        {"ethernet_t", "ethernet"},
        {"ipv4_t", "ipv4"},
        {"ports_t", "ports"},
        {"udp_t", "udp"},
        {"tcp_t", "tcp"},
    };

    P4::PrintConf conf;
    conf.metadata_name = "ig_intr_md_for_tm";

    std::vector<P4::Table::ReadEntry> reads = {
        {std::make_shared<P4::HeaderRef>(conf.metadata_name, "ingress_port"), P4::Table::MatchType::EXACT},
    };

    std::vector<std::shared_ptr<P4::Value>> args = {
        std::make_shared<P4::HeaderRef>("ipv4", "srcAddr"),
        std::make_shared<P4::HeaderRef>("ipv4", "dstAddr"),
    };

    std::vector<std::shared_ptr<P4::Stmt>> stmts = {
        std::make_shared<P4::PrimitiveStmt>("modify_field", args),
        std::make_shared<P4::PrimitiveStmt>("test2", args),
    };

    auto act = std::make_shared<P4::Action>("perform_lb",
                                            std::vector<std::string>{"ip", "port", "switchPort"},
                                            stmts);

    prog.add_table(std::make_shared<P4::Table>("in_port_tab",
                                               reads,
                                               std::vector<std::shared_ptr<P4::Action>>{act},
                                               65536));
    P4::Apply::Cases cases = {
        {"act1", stmts},
        {"miss", stmts},
    };
    auto apply = std::make_shared<P4::Apply>("in_port_tab", cases);
                   
    prog.set_ingress(std::make_shared<P4::Control>("ingress",
                                                   std::vector<std::shared_ptr<P4::Stmt>>{apply}));
    
    auto code = prog.code(conf);

    std::cout << code << std::endl;
    
    return 0;
}
