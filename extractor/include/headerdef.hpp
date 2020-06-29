#ifndef _MORULA_HEADER_DEF_HPP_
#define _MORULA_HEADER_DEF_HPP_

#include <utility>
#include <vector>
#include <string>
#include <unordered_map>

using FieldEntry = std::tuple<std::string, int>; /* name, size pair */
using HeaderDef = std::vector<FieldEntry>;

namespace NetHeader {
    extern const HeaderDef ip_field_sizes;
    extern const HeaderDef transport_field_sizes;
    extern const std::unordered_map<std::string, HeaderDef> header_defs;

    int get_hdr_total_bytes(const HeaderDef &def);
    FieldEntry find_field_by_idx(const HeaderDef &def, int idx);
    FieldEntry find_field_by_off(const HeaderDef &def, int off);

    int find_field_num_bytes(const std::string &header_name,
                             const std::string &field_name);
}

#endif /* _MORULA_HEADER_DEF_HPP_ */
