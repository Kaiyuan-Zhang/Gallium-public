#include "p4-parser-common.hpp"
#include <memory>

namespace Target {
    namespace P4 {
        namespace Common {
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

            Prog default_l4_prog_template(void) {
                HeaderDef ether_hdr("ethernet_t", ethernet_fields);
                HeaderDef ipv4_hdr("ipv4_t", ipv4_fields);
                HeaderDef ports_hdr("ports_t", ports_fields);
                HeaderDef udp_hdr("udp_t", udp_fields);
                HeaderDef tcp_hdr("tcp_t", tcp_fields);

                Prog prog ({ether_hdr, ipv4_hdr, ports_hdr, udp_hdr, tcp_hdr},
                           default_l4_parser());

                prog.header_decls = {
                    {"ethernet_t", "ethernet"},
                    {"ipv4_t", "ipv4"},
                    {"ports_t", "ports"},
                    {"udp_t", "udp"},
                    {"tcp_t", "tcp"},
                };
                
                return prog;
            }

            Parser default_l4_parser(void) {
                using PS = P4::ParserStage;
                    
                auto parse_ethernet = std::make_shared<PS>("parse_ethernet",
                                                           std::vector<std::string>{"ethernet"});
                auto parse_ipv4 = std::make_shared<PS>("parse_ipv4",
                                                       std::vector<std::string>{"ipv4"});
                auto parse_ports = std::make_shared<PS>("parse_ports",
                                                        std::vector<std::string>{"ports"});
                auto parse_udp = std::make_shared<PS>("parse_udp",
                                                      std::vector<std::string>{"udp"});
                auto parse_tcp = std::make_shared<PS>("parse_tcp",
                                                      std::vector<std::string>{"tcp"});

                parse_ethernet->match_field = std::make_shared<P4::HeaderRef>("ethernet", "etherType");
                parse_ethernet->add_match_rule("0x0800", parse_ipv4);
    
                parse_ipv4->match_field = std::make_shared<P4::HeaderRef>("ipv4", "protocol");
                parse_ethernet->add_match_rule("0x06", parse_ports);
                parse_ethernet->add_match_rule("0x11", parse_ports);

                parse_ports->match_field = std::make_shared<P4::HeaderRef>("ipv4", "protocol");
                parse_ports->add_match_rule("0x06", parse_tcp);
                parse_ports->add_match_rule("0x11", parse_udp);

                std::vector<std::shared_ptr<ParserStage>> stages = {parse_ethernet, parse_ipv4,
                                                                    parse_ports, parse_udp, parse_tcp};

                Parser parser(stages);
                return parser;
            }
        }
    }
}
