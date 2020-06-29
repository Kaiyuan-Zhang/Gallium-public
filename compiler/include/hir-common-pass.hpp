#pragma once

#include "hilvl-ir.hpp"
#include "graph.hpp"
#include <unordered_map>

namespace HIR {
    struct OpLoc {
        BasicBlock *bb;
        int op_idx;
    };

    void element_function_inline(Element &ele);

    bool has_side_effect(const Operation &op);

    void remove_all_meta(Function& f);
    void remove_all_meta(Element& ele);
    void update_uses(Function& f);
    void update_uses(Element& ele);
    void remove_unused_ops(Element& ele);

    // find phi-node and select inst regarding to global states
    // and expand them
    // we assume that these ops are not in loops
    void replace_next_bb(
        std::shared_ptr<BasicBlock> from,
        std::shared_ptr<BasicBlock> old_bb,
        std::shared_ptr<BasicBlock> new_bb);
    void fork_from_bb(Function& f, int bb_idx);
    void remove_unused_phi_entry(Function& f);
    void remove_empty_bb(Function& f);

    void break_select_op(Function& f, std::shared_ptr<Operation> op);

    std::unordered_map<std::shared_ptr<BasicBlock>, std::shared_ptr<BasicBlock>>
    duplicate_bbs(std::shared_ptr<BasicBlock>);

    Graph<
        std::shared_ptr<Function>,
        std::monostate,
        AdjacencyList<std::monostate>
    > call_graph_of_ele(const Element& ele);

    Graph<
        std::shared_ptr<BasicBlock>,
        std::monostate,
        AdjacencyList<std::monostate>
    > control_graph_of_func(const Function& f);

    Graph<
        std::monostate,
        std::monostate,
        AdjacencyList<std::monostate>
    > scc_graph_from_scc(
        const std::vector<std::vector<size_t>>& scc_list,
        const Graph<
            std::shared_ptr<BasicBlock>,
            std::monostate,
            AdjacencyList<std::monostate>>& ctl_graph); 
}
