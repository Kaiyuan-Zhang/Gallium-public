#ifndef _P4_PARSER_COMMON_HPP_
#define _P4_PARSER_COMMON_HPP_


#include "target-p4.hpp"


namespace Target {
    namespace P4 {
        namespace Common {
            extern std::vector<std::tuple<std::string, int>> ethernet_fields;
            extern std::vector<std::tuple<std::string, int>> ipv4_fields;
            extern std::vector<std::tuple<std::string, int>> ports_fields;
            extern std::vector<std::tuple<std::string, int>> udp_fields;
            extern std::vector<std::tuple<std::string, int>> tcp_fields;

            Parser default_l4_parser(void);
            Prog default_l4_prog_template(void);
        }
    }
}

#endif /* _P4_PARSER_COMMON_HPP_ */
