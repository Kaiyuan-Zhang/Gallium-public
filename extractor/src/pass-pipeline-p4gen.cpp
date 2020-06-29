#include "pass-pipeline-p4gen.hpp"
#include <sstream>

namespace Morula {
    PASS_IMPL(SplitPipeStage, s) {
        auto new_ctx = std::make_unique<PipeCtx>();
        std::vector<std::unique_ptr<PipeIR::Stage>> new_stages;
        for (auto &kv : s->program->stages_) {
            // for each stage, split them by dependency
            std::unordered_map<PipeIR::Operation *, int> op_idx;
            auto stage_ptr = kv.second.get();
            for (int i = 0; i < stage_ptr->ops.size(); i++) {
                op_idx.insert({stage_ptr->ops[i].get(), i});
            }

            /* iterative approach:
             * first find all ops that does not depend on any other ops in the same stage
             * then remove them from the stage
             * keep trying until the stage is empty
             */
            std::vector<PipeIR::Operation *> to_remove;
            do {
                to_remove.clear();
                for (auto &kv : op_idx) {
                    auto op = kv.first;
                    auto idx = kv.second;
                    bool have_dep = false;
                    for (auto dep_op : s->dependency[op]) {
                        if (op_idx.find(dep_op) != op_idx.end()) {
                            // this operation depends on any one in the same stage
                            have_dep = true;
                            break;
                        }
                    }
                    if (!have_dep) {
                        to_remove.push_back(op);
                    }
                }

                // create new stage from every inst in to_remove
                std::vector<std::unique_ptr<PipeIR::Operation>> new_ops;
                for (auto op : to_remove) {
                    auto idx = op_idx[op];
                    new_ops.push_back(std::move(stage_ptr->ops[idx]));
                    op_idx.erase(op);
                }
                auto new_stage = std::make_unique<PipeIR::Stage>(std::move(new_ops));
                new_stages.push_back(std::move(new_stage));
            } while (op_idx.size() > 0);

            // now connect all the new stages together
            std::vector<PipeIR::Stage *> prev_stages;
            for (auto prev_id : s->program->rev_edges[stage_ptr->get_uuid()]) {
                prev_stages.push_back(s->program->stages_[prev_id].get());
            }
            for (auto s : prev_stages) {
                for (int i = 0; i < s->next_stages.size(); i++) {
                    if (s->next_stages[i] == stage_ptr) {
                        s->next_stages[i] = new_stages[0].get();
                    }
                }
            }

            auto last = new_stages[new_stages.size() - 1].get();
            last->terminator_type = stage_ptr->terminator_type;
            for (auto v : stage_ptr->cond_vars) {
                last->cond_vars.push_back(v);
            }
            for (auto s : stage_ptr->next_stages) {
                last->next_stages.push_back(s);
            }
        }
        new_ctx->program = std::make_unique<PipeIR::Prog>(std::move(new_stages));
        return new_ctx;
    }

    static void topological_sort(PipeIR::Stage *curr, std::vector<PipeIR::Stage *> &topo_order,
                                 std::unordered_set<PipeIR::Stage *> &visiting,
                                 std::unordered_set<PipeIR::Stage *> &visited,
                                 const std::unordered_map<PipeIR::Stage *, std::unordered_set<PipeIR::Stage *>> &edges) {
        if (visited.find(curr) != visited.end()) {
            return;
        }
        if (visiting.find(curr) != visiting.end()) {
            assert(false && "topological sort on cyclic graph");
        }
        if (edges.find(curr) != edges.end()) {
            visiting.insert(curr);
            auto &neighbors = edges.find(curr)->second;
            for (auto &n : neighbors) {
                topological_sort(n, topo_order, visiting, visited, edges);
            }
            visiting.erase(curr);
        }
        visited.insert(curr);
        topo_order.push_back(curr);
    }

    using cond_var_bitmap_t = std::unordered_map<PipeIR::Var *, int>;
    static void build_cond_var_set(std::unordered_map<PipeIR::Stage *, cond_var_bitmap_t> &cond_var_map,
                                   PipeIR::Stage *curr,
                                   const std::unordered_map<PipeIR::Stage *, std::unordered_set<PipeIR::Stage *>> &edges) {
        // we assume that there isn't a loop
        std::function<int(int, int)> or_func = [](int a, int b) -> int {
            int result = a + b;
            return std::max(-1, std::min(1, result));
        };
        std::function<int(int, int)> and_func = [](int a, int b) -> int {
            if (a > 0 && b < 0) {
                // error: x and \not x
                std::cerr << "Found unreachable cond" << std::endl;
                return -2;
            }
            return std::max(-1, std::min(1, a + b));
        };
        if (edges.find(curr) != edges.end()) {
            auto &neighbors = edges.find(curr)->second;
            for (auto &n : neighbors) {
                build_cond_var_set(cond_var_map, n, edges);
                assert(cond_var_map.find(n) != cond_var_map.end());
                auto &var_list = cond_var_map[curr];
                cond_var_bitmap_t neighbor_bitmap;
                for (auto &kv : cond_var_map[n]) {
                    neighbor_bitmap.insert({kv.first, kv.second});
                }
                assert(n->next_stages.size() <= 2);
                if (n->next_stages.size() == 1) {
                    assert(n->next_stages[0] == curr);
                } else {
                    assert(n->cond_vars.size() == 1);
                    auto cond_var = n->cond_vars[0];
                    auto new_cond = -2;
                    if (n->next_stages[0] == curr) {
                        new_cond = and_func(neighbor_bitmap[cond_var], 1);
                    } else if (n->next_stages[1] == curr) {
                        new_cond = and_func(neighbor_bitmap[cond_var], -1);
                    }
                    assert(new_cond != -2);
                    neighbor_bitmap[cond_var] = new_cond;
                }

                for (auto &kv : neighbor_bitmap) {
                    var_list[kv.first] = or_func(var_list[kv.first], kv.second);
                }
            }
        }
    }

    struct LiveVarRecord {
        using VarSet = std::unordered_set<PipeIR::Var *>;
        std::vector<VarSet> live_before;
    };

    void gen_var_liveness_record(std::unordered_map<PipeIR::Stage *, LiveVarRecord> &records,
                                 const PipeIR::Prog &prog) {
        // generate liveness record for each operation
        // STEP 1 : initilize records (make all of them empty)
        for (auto &kv : prog.stages_) {
            auto s = kv.second.get();
            auto &rec = records[s];
            for (int i = 0; i < s->ops.size(); i++) {
                rec.live_before.emplace_back();
            }
        }

        // STEP 2 : continue liveness infer until converge
        bool has_delta = false;
        do {
            for (auto &kv : prog.stages_) {
                auto s = kv.second.get();
                auto &rec = records[s];
                // get all next stages
                LiveVarRecord::VarSet vars_alive;
                for (auto n : s->next_stages) {
                    const auto &next_rec = records[n];
                    for (auto v : next_rec.live_before[0]) {
                        vars_alive.insert(v);
                    }
                }

                // now start from the very end and construct the live variable list
                for (int i = s->ops.size() - 1; i >= 0; i--) {
                    // first get the read_set of the inst
                    auto vars_read = s->ops[i]->vars_read();
                    for (auto v : vars_read) {
                        vars_alive.insert(v);
                    }
                    auto vars_written = s->ops[i]->vars_written();
                    for (auto v : vars_written) {
                        if (vars_alive.find(v) != vars_alive.end()) {
                            vars_alive.erase(v);
                        }
                    }

                    // now `vars_alive` should contain the variables alive at his point
                    // (before ops[i] got executed)
                    // check if there are new variables added
                    for (auto v : vars_alive) {
                        if (rec.live_before[i].find(v) == rec.live_before[i].end()) {
                            has_delta = true;
                            break;
                        }
                    }
                    // also check if there are any live variables got removes
                    // (This should never happen, but we check it anyway)
                    for (auto v: rec.live_before[i]) {
                        assert(vars_alive.find(v) != vars_alive.end());
                    }
                    rec.live_before[i] = vars_alive;
                }
            }
        } while (has_delta);
    }

    static void p4_stage_code_gen(P4Stage &stage) {
        Block stage_code;
        for (int i = 0; i < stage.ops.size(); i++) {
            auto op_ptr = stage.ops[i].get();
        }
    }

    class Op2P4Visitor : public PipeIR::OperationVisitor<void> {
    public:
        std::vector<std::string> &code;
        const std::unordered_map<PipeIR::Var *, std::string> &var_mapping;
        const std::unordered_map<PipeIR::GlobalState *, std::string> &state_mapping;
        // TODO: add global state mapping

        Op2P4Visitor(std::vector<std::string> &_c,
                     const std::unordered_map<PipeIR::Var *,
                                              std::string> &_m,
                     const std::unordered_map<PipeIR::GlobalState *,
                                              std::string> &_s_m) : code(_c),
                                                                    var_mapping(_m),
                                                                    state_mapping(_s_m) {}

        virtual void visitOtherOp(PipeIR::Operation &op) override {
            assert(false && "not supported");
        }
        virtual void visitArith(PipeIR::Operation &op) override {
            auto op_name = op.arith_op_name;
            std::vector<std::string> dst_var;
            std::vector<std::string> oprands_var;
            for (auto i = 0; i < op.dst_var.size(); i++) {
                assert(var_mapping.find(op.dst_var[i].get()) != var_mapping.end());
                oprands_var.push_back(var_mapping.find(op.dst_var[i].get())->second);
            }
            for (auto i = 0; i < op.oprands.size(); i++) {
                assert(var_mapping.find(op.oprands[i].get()) != var_mapping.end());
                oprands_var.push_back(var_mapping.find(op.oprands[i].get())->second);
            }
            std::stringstream ss;
            auto print_bin_op_func = [&ss, &oprands_var, &dst_var](const std::string &op_str) -> void {
                assert(oprands_var.size() == 2);
                assert(dst_var.size() == 1);
                ss << dst_var[0] << " = "
                   << oprands_var[0] << " "
                   << op_str << " "
                   << oprands_var[1] << ";";
            };
            if (op_name == "add") {
                print_bin_op_func("+");
            } else if (op_name == "sub") {
                print_bin_op_func("-");
            } else if (op_name == "and") {
                print_bin_op_func("&");
            } else if (op_name == "or") {
                print_bin_op_func("|");
            } else if (op_name == "xor") {
                print_bin_op_func("^");
            } else if (op_name == "l_and") {
                print_bin_op_func("&&");
            } else if (op_name == "l_or") {
                print_bin_op_func("||");
            } else if (op_name == "not") {
                assert(oprands_var.size() == 1);
                assert(dst_var.size() == 1);
                ss << dst_var[0] << " = "
                   << "~"
                   << oprands_var[0] << ";";
            } else if (op_name == "l_not") {
                assert(oprands_var.size() == 1);
                assert(dst_var.size() == 1);
                ss << dst_var[0] << " = "
                   << "!"
                   << oprands_var[0] << ";";
            }
            code.push_back(ss.str());
        }
        virtual void visitPhi(PipeIR::Operation &op) override {
            assert(false && "phi node should be removed earlier");
        }
        virtual void visitStateOp(PipeIR::Operation &op) override {
            auto global_state = op.state;
            auto state_type = global_state->type;
            std::stringstream ss;
            assert(state_mapping.find(op.state) != state_mapping.end());
            auto state_var_name = state_mapping.find(op.state)->second;
            switch (state_type) {
            case PipeIR::GlobalState::Type::ARRAY: {
                assert(false && "TODO: handle array");
                assert(op.state_op_name == "get");
                ss << state_var_name << ".apply();";
                break;
            }
            case PipeIR::GlobalState::Type::TABLE: {
                assert(op.state_op_name == "lookup");
                ss << state_var_name << ".apply();";
                break;
            }
            default:
                assert(false && "unknown state type");
            }
            code.push_back(ss.str());
        }
    };

    std::unique_ptr<Block> translate_stage(const PipeIR::Stage &stage,
                                          const std::unordered_map<PipeIR::Var *,
                                                                   std::string> &var_map,
                                          const std::unordered_map<PipeIR::GlobalState *,
                                                                   std::string> &state_map) {
        std::vector<std::string> code;
        Op2P4Visitor visitor(code, var_map, state_map);
        for (int i = 0; i < stage.ops.size(); i++) {
            auto op = stage.ops[i].get();
            visitor.visit(*op);
        }
        return std::make_unique<Block>(code);
    }

    PASS_IMPL(GenP4Prog, s) {
        auto code = std::make_unique<P4CodeGenCtx>();
        // first find out all the tables
        std::unordered_map<PipeIR::GlobalState *, PipeIR::Operation *> global_states;
        for (auto &kv : s->program->stages_) {
            auto stage_ptr = kv.second.get();
            for (auto &op : stage_ptr->ops) {
                if (op->type == PipeIR::Operation::Type::STATE_OP) {
                    assert(global_states.find(op->state) == global_states.end());
                    global_states.insert({op->state, op.get()});
                }
            }
        }

        // create global states
        for (auto &kv : global_states) {
            auto s = kv.first;
            auto op = kv.second;

            auto state = std::make_unique<P4GlobalState>();
            code->prog->states.push_back(std::move(state));
        }

        // now perform a topological sort on the DAG of edges
        std::vector<PipeIR::Stage *> topo_order;
        std::unordered_map<PipeIR::Stage *, std::unordered_set<PipeIR::Stage *>> rev_edges;
        std::unordered_set<PipeIR::Stage *> visiting;
        std::unordered_set<PipeIR::Stage *> visited;

        // construct reverse edges
        for (auto &kv : s->program->rev_edges) {
            auto src_id = kv.first;
            assert(s->program->stages_.find(src_id) != s->program->stages_.end());
            auto src_ptr = s->program->stages_[src_id].get();
            for (auto &dst_id : kv.second) {
                assert(s->program->stages_.find(dst_id) != s->program->stages_.end());
                auto dst_ptr = s->program->stages_[dst_id].get();
                rev_edges[dst_ptr].insert(src_ptr);
            }
        }
        for (auto &kv : s->program->stages_) {
            auto s = kv.second.get();
            if (visited.find(s) == visited.end()) {
                topological_sort(s, topo_order, visiting, visited, rev_edges);
            }
        }

        // now create P4 stage base on this order
        // first get the set of execution conditions
        // get the list of all condition variables
        std::unordered_set<PipeIR::Var *> cond_vars;
        for (auto &kv : s->program->stages_) {
            auto s = kv.second.get();
            assert(s->terminator_type == PipeIR::StageTerminatorType::BRANCH
                   || s->terminator_type == PipeIR::StageTerminatorType::NEXT_DEV);
            if (s->terminator_type == PipeIR::StageTerminatorType::BRANCH) {
                assert(s->cond_vars.size() == 1);
                cond_vars.insert(s->cond_vars[0]);
            }
        }

        std::unordered_map<PipeIR::Stage *, cond_var_bitmap_t> cond_var_map;
        for (auto &kv : s->program->stages_) {
            auto s = kv.second.get();
            for (auto v : cond_vars) {
                cond_var_map[s].insert({v, 0});
            }
        }

        for (auto &kv : s->program->stages_) {
            auto s = kv.second.get();
            build_cond_var_set(cond_var_map, s, rev_edges);
        }

        // metadata variable allocation, this will eliminate some of the phi node from the program
        // first perform a liveness analysis on each variable

        std::unordered_map<PipeIR::Stage *, LiveVarRecord> records;

        gen_var_liveness_record(records, *s->program);

        // from the variable liveness record, find out the maxiumum number
        // of variables that are alive at the same time
        std::unordered_map<int, int> max_num_alive; // number of vars alive for each bitwidth
        for (auto &kv : records) {
            for (auto &set : kv.second.live_before) {
                std::unordered_map<int, int> num_alive;
                for (auto &v : set) {
                    auto &vt = v->type;
                    assert(vt->type == PipeIR::VarType::T::INT);
                    int bit_width = vt->int_bitwidth;
                    if (num_alive.find(bit_width) == num_alive.end()) {
                        num_alive[bit_width] = 0;
                    }
                    num_alive[bit_width]++;
                }
                for (auto &kv : num_alive) {
                    if (max_num_alive.find(kv.first) == max_num_alive.end()) {
                        max_num_alive[kv.first] = 0;
                    }
                    max_num_alive[kv.first] = std::max(max_num_alive[kv.first], kv.second);
                }
            }
        }


        // Allocate metadata fields based on maxinum number of alive variables
        std::unordered_map<PipeIR::Var *, std::string> var_meta_mapping;
        std::unordered_map<int, std::vector<std::string>> meta_field_for_size;
        for (auto &kv : max_num_alive) {
            for (int i = 0; i < kv.second; i++) {
                std::stringstream ss;
                ss << "var_" << kv.first << "_bit_" << i;
                auto var_name = ss.str();
                meta_field_for_size[kv.first].push_back(var_name);
            }
        }

        for (auto &kv : records) {
            auto &rec = kv.second;
            for (auto &entry : rec.live_before) {
                std::unordered_set<std::string> used_field;
                for (auto v : entry) {
                    if (var_meta_mapping.find(v) != var_meta_mapping.end()) {
                        used_field.insert(var_meta_mapping[v]);
                    }
                }
                for (auto v : entry) {
                    if (var_meta_mapping.find(v) == var_meta_mapping.end()) {
                        auto var_bit_width = v->type->int_bitwidth;
                        auto &available_fields = meta_field_for_size[var_bit_width];
                        std::string new_f = "";
                        for (auto &f : available_fields) {
                            if (used_field.find(f) == used_field.end()) {
                                new_f = f;
                                used_field.insert(f);
                                break;
                            }
                        }
                        assert(new_f != "");
                        var_meta_mapping[v] = new_f;
                    }
                }
            }
        }

        // assign name to each of the state
        std::unordered_map<PipeIR::GlobalState *, std::string> state_mapping;
        int cnt = 0;
        for (auto &kv : s->program->stages_) {
            auto s_ptr = kv.second.get();
            for (auto &op : s_ptr->ops) {
                if (op->type == PipeIR::Operation::Type::STATE_OP) {
                    auto state_ptr = op->state;
                    if (state_mapping.find(state_ptr) != state_mapping.end()) {
                        // create new name for the state
                        std::string name;
                        if (state_ptr->name_anno != "") {
                            name = state_ptr->name_anno;
                        } else {
                            switch (state_ptr->type) {
                                case PipeIR::GlobalState::Type::TABLE:
                                    name = "table";
                                    break;
                                case PipeIR::GlobalState::Type::ARRAY:
                                    name = "array";
                                    break;
                                default:
                                    name = "state";
                            }
                        }
                        name = name + std::to_string(cnt);
                        cnt++;
                        state_mapping[state_ptr] = name;
                    }
                }
            }
        }

        // move to p4 stage
        // each stage will have a variable that is used to determine
        // whether this stage should be executed or not
        std::unordered_map<PipeIR::Stage *, int> stage_idx;
        for (int i = 0; i < topo_order.size(); i++) {
            stage_idx[topo_order[i]] = i;
        }
        // Now start translate PipeIR::Operation to p4 code
        // Each stage should become an action
        // Assign a table for each stage, except for stages that
        // already have one global state access

        auto main_code = std::make_shared<Block>();
        std::vector<std::unique_ptr<P4Action>> actions;
        std::vector<std::unique_ptr<P4GlobalState>> p4_states;
        for (int i = 0; i < topo_order.size(); i++) {
            auto s = topo_order[i];
            auto block_code = std::make_unique<Block>();
            if (s->ops.size() > 0) {
                auto code = translate_stage(*s, var_meta_mapping, state_mapping);
                if (s->ops[0]->type == PipeIR::Operation::Type::STATE_OP) {
                    assert(s->ops.size() == 1);
                    block_code->merge_code(std::move(code));
                } else {
                    // This is not state op, put into action
                    auto action_name = "stage_" + std::to_string(stage_idx[s]);
                    auto action = std::make_unique<P4Action>();
                    action->action_name = action_name;
                    action->code = std::move(code);
                    actions.push_back(std::move(action));

                    auto tab = std::make_unique<P4GlobalState>();
                    tab->type = P4GlobalState::Type::TABLE;
                    tab->default_action = action_name;
                    tab->default_only = true;
                    p4_states.push_back(std::move(tab));
                }
            }
            if (s->terminator_type == PipeIR::StageTerminatorType::BRANCH) {
                assert(s->cond_vars.size() <= 1);
                assert(s->next_stages.size() <= 2);
                if (s->next_stages.size() == 1) {
                    assert(var_meta_mapping.find(s->cond_vars[0]) != var_meta_mapping.end());
                    auto cond_var = var_meta_mapping[s->cond_vars[0]];
                    auto t_idx = stage_idx[s->next_stages[0]];
                    auto f_idx = stage_idx[s->next_stages[1]];
                    std::stringstream ss;
                    ss << "next_bb = "
                    << "(" << cond_var << ") ? "
                    << std::to_string(t_idx)
                    << " : " << std::to_string(f_idx) << ";";
                    block_code->append_line(ss.str());
                } else {
                    // unconditional jump
                    auto next_idx = stage_idx[s->next_stages[0]];
                    block_code->append_line("next_bb = " + std::to_string(next_idx) + ";");
                }
            } else if (s->terminator_type == PipeIR::StageTerminatorType::TABLE_DISPATCH) {
                // TODO: create a table and let control plane add rules
                assert(false && "not implemented");
            } else {
                assert(false && "unknown terminator");
            }
            block_code->append_line("from_bb = " + std::to_string(stage_idx[s]));
            main_code->append_line("if (next_bb == " + std::to_string(stage_idx[s]) + ")");
            main_code->append_block(std::move(block_code));
        }

        auto control_body = std::make_shared<Block>();
        for (auto &a : actions) {
            control_body->append_line("action " + a->action_name + "()");
            control_body->append_code(a->code);
        }

        for (auto &s : p4_states) {
            if (s->type == P4GlobalState::Type::TABLE) {
                control_body->append_line("table " + s->name);
                auto tab_body = std::make_shared<Block>();

                tab_body->append_line("key =");
                auto key_body = std::make_shared<Block>();
                // TODO: fill in key
                key_body->append_line("hdr.ipv4.src : exact;");
                tab_body->append_block(key_body);

                tab_body->append_line("actions =");
                auto action_body = std::make_shared<Block>();
                // TODO: fill in body
                action_body->append_line("my_act;");
                tab_body->append_block(action_body);

                if (s->default_action != "") {
                    tab_body->append_line("default_action = " + s->default_action + "();");
                }

                // TODO: fix the size
                tab_body->append_line("size = 1024;");

                control_body->append_block(tab_body);
            } else {
                assert(false && "unsupported state type");
            }
        }

        control_body->merge_code(main_code);

        code->code = control_body;
        return code;
    }
}
