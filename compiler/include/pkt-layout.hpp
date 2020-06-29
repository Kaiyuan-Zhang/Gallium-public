#pragma once


#include <iostream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <string>


class HeaderLayout {
public:
    struct Entry {
        std::string field_name;
        size_t field_n_bytes;
    };
    std::string name;
    std::vector<Entry> fields;

    HeaderLayout();
    HeaderLayout(std::string n, std::vector<Entry> fields);

    std::optional<Entry> FindFieldByOffset(size_t offset) const;
    size_t HeaderSize() const;
};

class PacketLayout {
public:
    std::unordered_map<std::string, HeaderLayout> headers;

    PacketLayout() {}
    PacketLayout(
        std::unordered_map<std::string, HeaderLayout> hdrs)
    : headers(std::move(hdrs)) {}
};

namespace CommonHdr {
extern HeaderLayout ether_layout;

extern HeaderLayout ipv4_layout;
extern HeaderLayout arp_layout;

extern HeaderLayout tcp_layout;
extern HeaderLayout udp_layout;

extern PacketLayout default_layout;
}
