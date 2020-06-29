#include "pkt-layout.hpp"

HeaderLayout::HeaderLayout() {}

HeaderLayout::HeaderLayout(std::string n, std::vector<Entry> fs)
    : name(std::move(n)),
      fields(std::move(fs)) {
}

std::optional<HeaderLayout::Entry>
HeaderLayout::FindFieldByOffset(size_t offset) const {
    auto off = 0;
    for (int i = 0; i < fields.size(); i++) {
        if (off == offset) {
            return fields[i];
        }
        if (off > offset) {
            break;
        }
        off += fields[i].field_n_bytes;
    }
    return std::nullopt;
}

size_t HeaderLayout::HeaderSize() const {
    auto sz = 0;
    for (auto &e : fields) {
        sz += e.field_n_bytes;
    }
    return sz;
}

namespace CommonHdr {
HeaderLayout ether_layout{
    "ether_hdr_t",
    {{"dst", 6},
     {"src", 6},
     {"ethertype", 2},
    }
};

HeaderLayout ipv4_layout{
    "ipv4_hdr_t",
    {{"vihl",     1},
     {"tos",      1},
     {"tot_len",  2},
     {"id",       2},
     {"frag_off", 2},
     {"ttl",      1},
     {"protocol", 1},
     {"check",    2},
     {"saddr",    4},
     {"daddr",    4},
    }
};

HeaderLayout arp_layout{
    "arp_hdr_t",
    {{"htype", 2},
     {"ptype", 2},
     {"hlen",  1},
     {"plen",  1},
     {"oper",  2},
     {"sha",   6},
     {"spa",   4},
     {"tha",   6},
     {"tpa",   4},
    }
};

HeaderLayout tcp_layout{
    "tcp_hdr_t",
    {{"source",  2},
     {"dest",    2},
     {"seq",     4},
     {"ack_seq", 4},
     {"flags",   2},
     {"window",  2},
     {"check",   2},
     {"urg_ptr", 2},
    }
};

HeaderLayout udp_layout{
    "udp_hdr_t",
    {{"src",      2},
     {"dest",     2},
     {"len",      2},
     {"checksum", 2},
    }
};

PacketLayout default_layout{
    {{"ether", ether_layout},
     {"ipv4",  ipv4_layout},
     {"tcp",   tcp_layout},
     {"udp",   udp_layout},
    }
};
}
