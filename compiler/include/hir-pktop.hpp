#pragma once

#include "hilvl-ir.hpp"
#include "pkt-layout.hpp"

namespace HIR {
    void replace_packet_access_op(Element &ele, const PacketLayout &layout);

    // meta op means operations like dropping or sending packet
    void replace_packet_meta_op(Element &ele);
    void replace_packet_access_op(Module &m, const PacketLayout &layout);
}
