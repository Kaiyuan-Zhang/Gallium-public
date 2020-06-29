#include "headerdef.hpp"
#include <cassert>

namespace NetHeader {
    const std::vector<std::tuple<std::string, int>> ip_field_sizes = {
        {"vihl", 1},
        {"tos", 1},
        {"len", 2},
        {"id", 2},
        {"off", 2},
        {"ttl", 1},
        {"protocol", 1},
        {"sum", 2},
        {"src", 4},
        {"dst", 4},
    };

    const std::vector<std::tuple<std::string, int>> transport_field_sizes = {
        {"sport", 2},
        {"dport", 2},
    };


    const std::unordered_map<std::string, HeaderDef> header_defs = {
        {"click_ip", ip_field_sizes},
        {"click_transport", transport_field_sizes},
        {"ipv4", ip_field_sizes},
        {"tcp", transport_field_sizes},
    };

    int get_hdr_total_bytes(const HeaderDef &def) {
        int result = 0;
        for (auto &e : def) {
            result += std::get<1>(e);
        }
        return result;
    }

    FieldEntry find_field_by_idx(const HeaderDef &def, int idx) {
        assert(idx >= 0 && idx < def.size());
        return def[idx];
    }

    FieldEntry find_field_by_off(const HeaderDef &def, int off) {
        FieldEntry ret = {"", -1};

        int t = off;
        for (int i = 0; i < def.size(); i++) {
            if (t == 0) {
                ret = def[i];
                goto out;
            }
            if (t < 0) {
                goto out;
            }
            t -= std::get<1>(def[i]);
        }
    out:
        return ret;
    }

    int find_field_num_bytes(const std::string &header_name,
                             const std::string &field_name) {
        int ret = 0;
        auto h_iter = header_defs.find(header_name);
        if (h_iter == header_defs.end()) {
            return 0;
        }

        auto &f_list = h_iter->second;
        for (int i = 0; i < f_list.size(); i++) {
            if (std::get<0>(f_list[i]) == field_name) {
                return std::get<1>(f_list[i]);
            }
        }
        return ret;
    }
}

