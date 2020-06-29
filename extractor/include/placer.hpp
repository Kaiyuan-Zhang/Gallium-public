#ifndef _PLACER_HPP_
#define _PLACER_HPP_

#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include <vector>
#include <tuple>
#include <memory>

/*
 * We first define a "Conditional placement"
 * which means that a object (state / instruction) can be placed to a target platform
 * only if ALL of its precursors could be placed on the same target
 */


using InstID = std::tuple<std::string, int>;

std::ostream &operator<<(std::ostream &os, const InstID &id);

struct InstIDHasher : std::unary_function<InstID, std::size_t> {
    std::size_t operator()(const InstID &id) const;
};

struct InstIDEqual : std::binary_function<InstID, InstID, bool> {
    bool operator()(const InstID &lhs, const InstID &rhs) const;
};

struct InstIDCmp : std::less<InstID> {
    bool operator()(const InstID &lhs, const InstID &rhs) const;
};

using InstIDUset = std::unordered_set<InstID, InstIDHasher, InstIDEqual>;

template<typename V>
using InstIDUmap = std::unordered_map<InstID, V, InstIDHasher, InstIDEqual>;

class Placement {
public:
    std::unordered_map<std::string, std::string> fixed_state;
    std::unordered_map<InstID, std::string, InstIDHasher, InstIDEqual> fixed_inst;
};

class PlaceReq {
public:
    PlaceReq();
    PlaceReq(const std::string &target);

    std::string find_placement(Placement &ctx) const;

    std::vector<std::string> state_pre_req;
    std::vector<InstID> inst_pre_req;
    std::string target;
    std::shared_ptr<PlaceReq> next = nullptr;
    friend std::ostream &operator<<(std::ostream &os, const PlaceReq &req);
protected:
};

std::ostream &operator<<(std::ostream &os, const PlaceReq &req);

struct PlaceReqSet {
    std::unordered_map<std::string, PlaceReq> state_reqs;
    std::unordered_map<InstID, PlaceReq, InstIDHasher, InstIDEqual> inst_reqs;
};


Placement run_placement(const PlaceReqSet &req_set);


enum class PlaceType {
    CPU,
    P4_PREFIX,
    P4_SUFFIX,
    P4_BOTH,
};

class PlaceResult {
public:
    std::unordered_map<std::string, PlaceType> fixed_state;
    std::unordered_map<InstID, PlaceType, InstIDHasher, InstIDEqual> fixed_inst;
};

class PlaceInfo {
public:
    bool can_be_prefix;
    bool can_be_suffix;

    std::vector<std::string> prefix_state_dep;
    std::vector<InstID> prefix_inst_dep;

    std::vector<std::string> suffix_state_dep;
    std::vector<InstID> suffix_inst_dep;
    
    PlaceInfo();

    static PlaceInfo P4_prefix();
    static PlaceInfo P4_suffix();
    static PlaceInfo P4_both();
    static PlaceInfo CPU();

    const static int YES = 1;
    const static int NO = 0;
    const static int UNKNOWN = -1;
    int is_prefix(const PlaceResult &ctx) const;
    int is_suffix(const PlaceResult &ctx) const;
};

struct InfoSet {
    std::unordered_map<std::string, PlaceInfo> state_info;
    std::unordered_map<InstID, PlaceInfo, InstIDHasher, InstIDEqual> inst_info;
};

struct LabelCtx {
    std::unordered_map<InstID, PlaceType, InstIDHasher, InstIDEqual> inst_visited;
    std::unordered_set<InstID, InstIDHasher, InstIDEqual> inst_visiting;

    std::unordered_map<std::string, PlaceType> state_visited;
    std::unordered_set<std::string> state_visiting;
    
    LabelCtx() {}
};

PlaceResult label_insts(const InfoSet &info);

#endif /* _PLACER_HPP_ */
