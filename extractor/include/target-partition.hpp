#ifndef _TARGET_PARTITION_HPP_
#define _TARGET_PARTITION_HPP_

#include "target-lang.hpp"

namespace Target {
    using BlockSet = std::unordered_map<std::string, BasicBlock *>;

    struct SplitResult {
        BlockSet blocks;
    };

    SplitResult peel(const BlockSet &blocks, const std::string &start_point,
                     const PlaceResult &p, bool reversed);
}

#endif /* _TARGET_PARTITION_HPP_ */
