#include <queue>
#include "placer.hpp"

std::ostream &operator<<(std::ostream &os, const InstID &id) {
    os << "{" << std::get<0>(id) << ", " << std::get<1>(id) << "}";
    return os;
}

std::size_t InstIDHasher::operator()(const InstID &id) const {
    return std::hash<std::string>{}(std::get<0>(id)) ^ std::hash<int>{}(std::get<1>(id));
}

bool InstIDEqual::operator()(const InstID &lhs, const InstID &rhs) const {
    return std::get<0>(lhs) == std::get<0>(rhs)
        && std::get<1>(lhs) == std::get<1>(rhs);
}

bool InstIDCmp::operator()(const InstID &lhs, const InstID &rhs) const {
    return (std::get<0>(lhs) < std::get<0>(rhs))
        || ((std::get<0>(lhs) == std::get<0>(rhs))
            && (std::get<1>(lhs) < std::get<1>(rhs)));
}

PlaceReq::PlaceReq() {
}

PlaceReq::PlaceReq(const std::string &t): target(t) {}

std::string PlaceReq::find_placement(Placement &ctx) const {
    const PlaceReq *curr = this;
    while (curr != nullptr) {
        auto req_met = true;
        for (auto &s : curr->state_pre_req) {
            auto p_iter = ctx.fixed_state.find(s);
            if (p_iter == ctx.fixed_state.end() || p_iter->second == "") {
                return "";
            }
            if (p_iter->second != curr->target) {
                req_met = false;
            }
        }
        for (auto &i : curr->inst_pre_req) {
            auto p_iter = ctx.fixed_inst.find(i);
            if (p_iter == ctx.fixed_inst.end() || p_iter->second == "") {
                return "";
            }
            if (p_iter->second != curr->target) {
                req_met = false;
            }
        }
        if (req_met) {
            return curr->target;
        }
        curr = (curr->next).get();
    }
    return "";
}

std::ostream &operator<<(std::ostream &os, const PlaceReq &req) {
    const PlaceReq *curr = &req;
    int num_lvl = 0;
    while (curr != nullptr) {
        auto req_met = true;
        os << "<PlaceReq: ";
        num_lvl++;
        os << "state-req: [";
        for (auto &s : curr->state_pre_req) {
            os << s << ", ";
        }
        os << "], inst-req: [";
        for (auto &i : curr->inst_pre_req) {
            os << "(" << std::get<0>(i) << ", " << std::get<1>(i) << "), ";
        }
        os << "]";
        curr = (curr->next).get();
        if (curr != nullptr) {
            os << ", next: ";
        }
    }
    for (int i = 0; i < num_lvl; i++) {
        os << ">";
    }
    return os;
}

Placement run_placement(const PlaceReqSet &req_set) {
    Placement result;
    result.fixed_state.clear();
    result.fixed_inst.clear();

    const auto &state_reqs = req_set.state_reqs;
    const auto &inst_reqs = req_set.inst_reqs;
    
    // here we simply use a greedy approach
    while (true) {
        int delta = 0;
        for (auto iter = state_reqs.begin(); iter != state_reqs.end(); iter++) {
            if (result.fixed_state.find(iter->first) != result.fixed_state.end()) {
                continue;
            }
            const auto &req = iter->second;
            auto target = req.find_placement(result);
            if (target != "") {
                result.fixed_state.insert({iter->first, target});
                delta++;
            }
        }

        for (auto iter = inst_reqs.begin(); iter != inst_reqs.end(); iter++) {
            if (result.fixed_inst.find(iter->first) != result.fixed_inst.end()) {
                continue;
            }
            const auto &req = iter->second;
            auto target = req.find_placement(result);
            if (target != "") {
                result.fixed_inst.insert({iter->first, target});
                delta++;
            }
        }
        if (delta == 0) {
            break;
        }
    }
    return result;
}

PlaceInfo::PlaceInfo(): can_be_prefix(false), can_be_suffix(false) {}

PlaceInfo PlaceInfo::P4_prefix() {
    PlaceInfo result;
    result.can_be_prefix = true;
    result.can_be_suffix = false;
    return result;
}

PlaceInfo PlaceInfo::P4_suffix() {
    PlaceInfo result;
    result.can_be_prefix = false;
    result.can_be_suffix = true;
    return result;
}

PlaceInfo PlaceInfo::P4_both() {
    PlaceInfo result;
    result.can_be_prefix = true;
    result.can_be_suffix = true;
    return result;
}

PlaceInfo PlaceInfo::CPU() {
    PlaceInfo result;
    result.can_be_prefix = false;
    result.can_be_suffix = false;
    return result;
}

int PlaceInfo::is_prefix(const PlaceResult &ctx) const {
    int result = YES;
    if (can_be_prefix) {
        for (auto &s : prefix_state_dep) {
            auto t_iter = ctx.fixed_state.find(s);
            if (t_iter == ctx.fixed_state.end()) {
                result = UNKNOWN;
                goto out;
            }
            auto t = t_iter->second;
            if (t != PlaceType::P4_PREFIX && t != PlaceType::P4_BOTH) {
                result = NO;
                goto out;
            }
        }

        for (auto &inst_id : prefix_inst_dep) {
            auto t_iter = ctx.fixed_inst.find(inst_id);
            if (t_iter == ctx.fixed_inst.end()) {
                result = UNKNOWN;
                goto out;
            }
            auto t = t_iter->second;
            if (t != PlaceType::P4_PREFIX && t != PlaceType::P4_BOTH) {
                result = NO;
                goto out;
            }
        }
    } else {
        result = NO;
    }
 out:
    return result;
}

int PlaceInfo::is_suffix(const PlaceResult &ctx) const {
    int result = YES;
    if (can_be_suffix) {
        for (auto &s : suffix_state_dep) {
            auto t_iter = ctx.fixed_state.find(s);
            if (t_iter == ctx.fixed_state.end()) {
                result = UNKNOWN;
                goto out;
            }
            auto t = t_iter->second;
            if (t != PlaceType::P4_SUFFIX && t != PlaceType::P4_BOTH) {
                result = NO;
                goto out;
            }
        }
        for (auto &inst_id : suffix_inst_dep) {
            auto t_iter = ctx.fixed_inst.find(inst_id);
            if (t_iter == ctx.fixed_inst.end()) {
                result = UNKNOWN;
                goto out;
            }
            auto t = t_iter->second;
            if (t != PlaceType::P4_SUFFIX && t != PlaceType::P4_BOTH) {
                result = NO;
                goto out;
            }
        }
    } else {
        result = NO;
    }
 out:
    return result;
}

static PlaceType label_insts_aux(InstID id,
                                 const InfoSet &info,
                                 bool is_prefix,
                                 LabelCtx &ctx);

static PlaceType label_states_aux(const std::string &state,
                                  const InfoSet &info,
                                  bool is_prefix,
                                  LabelCtx &ctx) {
    PlaceType result = PlaceType::CPU;
    PlaceType t;
    auto target_label = is_prefix ? PlaceType::P4_PREFIX : PlaceType::P4_SUFFIX;
    auto v_iter = ctx.state_visited.find(state);
    auto info_iter = info.state_info.find(state);
    const std::vector<std::string> *state_dep_ptr = nullptr;
    const std::vector<InstID> *inst_dep_ptr = nullptr;
    const PlaceInfo *state_info_ptr = nullptr;
    
    if (v_iter != ctx.state_visited.end()) {
        result = v_iter->second;
        goto out;
    }

    if (ctx.state_visiting.find(state) != ctx.state_visiting.end()) {
        /* this instruction is currently being visited
         * this means a loop is detected
         * simply put it on cpu
         */
        result = PlaceType::CPU;
        goto out_update;
    }

    if (info_iter == info.state_info.end()) {
        result = PlaceType::CPU;
        goto out_update;
    }
    state_info_ptr = &info_iter->second;
    if (is_prefix) {
        state_dep_ptr = &state_info_ptr->prefix_state_dep;
        inst_dep_ptr = &state_info_ptr->prefix_inst_dep;
        if (!state_info_ptr->can_be_prefix) {
            result = PlaceType::CPU;
            goto out_update;
        }
    } else {
        state_dep_ptr = &state_info_ptr->suffix_state_dep;
        inst_dep_ptr = &state_info_ptr->suffix_inst_dep;
        if (!state_info_ptr->can_be_suffix) {
            result = PlaceType::CPU;
            goto out_update;
        }
    }

    for (auto &s : *state_dep_ptr) {
        t = label_states_aux(s, info, is_prefix, ctx);
        if (t != target_label) {
            goto out_update;
        }
    }

    for (auto &inst_id : *inst_dep_ptr) {
        t = label_insts_aux(inst_id, info, is_prefix, ctx);
        if (t != target_label) {
            goto out_update;
        }
    }

    result = target_label;
 out_update:
    ctx.state_visited.insert({state, result});
 out:
    return result;
}

static PlaceType label_insts_aux(InstID id,
                                 const InfoSet &info,
                                 bool is_prefix,
                                 LabelCtx &ctx) {
    PlaceType result = PlaceType::CPU;
    PlaceType t;
    auto target_label = is_prefix ? PlaceType::P4_PREFIX : PlaceType::P4_SUFFIX;
    //std::cerr << "Try labeling (" << std::get<0>(id) << ", " << std::get<1>(id) << ")" << std::endl;
    auto v_iter = ctx.inst_visited.find(id);
    auto info_iter = info.inst_info.find(id);
    const std::vector<std::string> *state_dep_ptr = nullptr;
    const std::vector<InstID> *inst_dep_ptr = nullptr;
    const PlaceInfo *inst_info_ptr = nullptr;
    
    if (v_iter != ctx.inst_visited.end()) {
        result = v_iter->second;
        goto out;
    }

    if (ctx.inst_visiting.find(id) != ctx.inst_visiting.end()) {
        /* this instruction is currently being visited
         * this means a loop is detected
         * simply put it on cpu
         */
        result = PlaceType::CPU;
        goto out_update;
    }
    
    if (info_iter == info.inst_info.end()) {
        result = PlaceType::CPU;
        goto out_update;
    }
    inst_info_ptr = &info_iter->second;
    ctx.inst_visiting.insert(id);
    if (is_prefix) {
        state_dep_ptr = &inst_info_ptr->prefix_state_dep;
        inst_dep_ptr = &inst_info_ptr->prefix_inst_dep;
        if (!inst_info_ptr->can_be_prefix) {
            result = PlaceType::CPU;
            goto out_recursive;
        }
    } else {
        state_dep_ptr = &inst_info_ptr->suffix_state_dep;
        inst_dep_ptr = &inst_info_ptr->suffix_inst_dep;
        if (!inst_info_ptr->can_be_suffix) {
            result = PlaceType::CPU;
            goto out_recursive;
        }
    }

    for (auto &s : *state_dep_ptr) {
        t = label_states_aux(s, info, is_prefix, ctx);
        //std::cerr << "Labeling for " << s << " : " << (int)t << std::endl;
        if (t != target_label) {
            goto out_recursive;
        }
    }

    for (auto &inst_id : *inst_dep_ptr) {
        //std::cerr << "dep inst: " << std::get<0>(inst_id) << " " << std::get<1>(inst_id) << std::endl;
        auto t = label_insts_aux(inst_id, info, is_prefix, ctx);
        if (t != target_label) {
            goto out_recursive;
        }
    }

    result = target_label;

 out_recursive:
    ctx.inst_visiting.erase(id);

 out_update:
    ctx.inst_visited.insert({id, result});
 out:
    //std::cerr << "inst_label_result: " << (int)result << std::endl;
    return result;
}

PlaceResult label_insts(const InfoSet &info) {
    LabelCtx prefix_ctx;
    LabelCtx suffix_ctx;
    for (auto &kv : info.inst_info) {
        auto id = kv.first;
        label_insts_aux(id, info, true, prefix_ctx);
        label_insts_aux(id, info, false, suffix_ctx);
    }

    for (auto &kv : info.state_info) {
        auto state = kv.first;
        label_states_aux(state, info, true, prefix_ctx);
        label_states_aux(state, info, false, suffix_ctx);
    }

    PlaceResult result;
    result.fixed_state = prefix_ctx.state_visited;
    result.fixed_inst = prefix_ctx.inst_visited;

    for (auto &kv : suffix_ctx.state_visited) {
        auto state = kv.first;
        auto &t = kv.second;
        auto s_iter = result.fixed_state.find(state);
        if (s_iter != result.fixed_state.end()) {
            // there is a duplicate
            if (t != PlaceType::CPU) {
                if (s_iter->second != PlaceType::CPU) {
                    s_iter->second = PlaceType::P4_BOTH;
                } else {
                    s_iter->second = t;
                }
            }
        } else {
            result.fixed_state.insert({state, t});
        }
    }

    for (auto &kv : suffix_ctx.inst_visited) {
        auto inst_id = kv.first;
        auto &t = kv.second;
        auto i_iter = result.fixed_inst.find(inst_id);
        if (i_iter != result.fixed_inst.end()) {
            if (t != PlaceType::CPU) {
                if (i_iter->second != PlaceType::CPU) {
                    i_iter->second = PlaceType::P4_BOTH;
                } else {
                    i_iter->second = t;
                }
            }
        } else {
            result.fixed_inst.insert({inst_id, t});
        }
    }
    
    return result;
}
