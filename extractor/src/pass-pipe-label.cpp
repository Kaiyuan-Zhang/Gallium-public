#include "pass-pipe-label.hpp"
#include "pass-llvm2pipe.hpp"
#include "pass-pipe-common.hpp"
#include "pass-pipe-oprw.hpp"

namespace Morula {
    class InitialLabelVisitor : public PipeIR::OperationVisitor<void> {
    public:
        std::unordered_set<std::string> &labels_;
        PktPtrTraceCtx &ctx;
        InitialLabelVisitor(std::unordered_set<std::string> &l, PktPtrTraceCtx &_c) : labels_(l), ctx(_c) {
            labels_.insert("cpu");
        }

        virtual void visitOtherOp(PipeIR::Operation &op) override {
            assert(false && "unknown op");
        }

        virtual void visitAllocTmp(PipeIR::Operation &op) override {
            labels_.insert("pre");
            labels_.insert("post");
        }

        virtual void visitArith(PipeIR::Operation &op) override {
            static std::unordered_set<std::string> supported_op = {
                "add", "sub", "and", "or", "xor",
                "eq", "ne", "sle", "slt", "sge", "sgt",
                "ule", "ult", "uge", "ugt",
                "ite",
            };
            if (supported_op.find(op.arith_op_name) != supported_op.end()) {
                labels_.insert("pre");
                labels_.insert("post");
            }
        }

        virtual void visitPhi(PipeIR::Operation &op) override {
            labels_.insert("pre");
            labels_.insert("post");
        }

        virtual void visitStateOp(PipeIR::Operation &op) override {
            static std::unordered_set<std::string> supported_op = {
                "map_lkup", "array_get", "Packet::uniqueify",
                "Packet::transport_length const",
                "Packet::has_network_header const",
                "Element::checked_output_push const",
                "rorw $$8, ${0:w}",
                "HashMap::findp const",
                "Vector::operator[]",
            };
            if (supported_op.find(op.state_op_name) != supported_op.end()) {
                labels_.insert("pre");
                labels_.insert("post");
            }
        }

        virtual void visitPointerOffOp(PipeIR::Operation &op) override {
            auto base_info = find_pkt_ptr_info(op.oprands[0].get(), ctx);
            auto dst_info = find_pkt_ptr_info(op.dst_var[0].get(), ctx);
            if (base_info.is_stack_ptr) {
                labels_.insert("pre");
                labels_.insert("post");
            }

            if (dst_info.is_element_state_ptr) {
                labels_.insert("pre");
                labels_.insert("post");
            }
        }

        virtual void visitLoadOp(PipeIR::Operation &op) override {
            auto ptr_info = find_pkt_ptr_info(op.get_load_store_pointer().get(), ctx);

            if (ptr_info.is_stack_ptr) {
                labels_.insert("pre");
                labels_.insert("post");
            }
        }

        virtual void visitStoreOp(PipeIR::Operation &op) override {
        }

        virtual void visitHdrReadOp(PipeIR::Operation &op) override {
            labels_.insert("pre");
            labels_.insert("post");
        }

        virtual void visitHdrWriteOp(PipeIR::Operation &op) override {
            labels_.insert("pre");
            labels_.insert("post");
        }
    };
    PASS_IMPL(PipeIRLabel, ctx) {
        auto s = PassSeq<PipeIRRemoveUnused, PipeUpdateUseDef>::apply_pass(std::move(ctx));
        using LabelSet = std::unordered_set<std::string>;

        // some assertions to make sure we are at a reasonable point
        assert(s->funcs.size() == 1);
        assert(s->funcs.find(s->entry_name) != s->funcs.end());
        
        // record all argument vars
        std::unordered_set<PipeIR::Var *> args;
        for (auto &v : s->funcs[s->entry_name]->params_) {
            std::cout << "add param: ";
            v->print(std::cout);
            std::cout << std::endl;
            args.insert(v.get());
        }

        PktPtrTraceCtx trace_ctx;
        trace_ctx.pass_ctx = s.get();

        // initialize packet object
        assert(s->funcs.find(s->entry_name) != s->funcs.end());
        auto &entry_f = s->funcs[s->entry_name];
        PktPtrInfo pkt_obj_info;
        pkt_obj_info.is_pkt_obj = true;
        std::shared_ptr<PipeIR::Var> pkt_obj_var;
        if (entry_f->params_.size() == 2) {
            // simple_action
            pkt_obj_var = entry_f->params_[1];
        } else if (entry_f->params_.size() == 3) {
            // push
            pkt_obj_var = entry_f->params_[2];
        } else {
            assert(false && "unknown entry func");
        }
        pkt_obj_info.pkt_obj = pkt_obj_var;
        trace_ctx.cache.insert({pkt_obj_var.get(), pkt_obj_info});

        PktPtrInfo ele_obj_info;
        ele_obj_info.is_element_ptr = true;
        ele_obj_info.element_obj = entry_f->params_[0];
        trace_ctx.cache.insert({entry_f->params_[0].get(), ele_obj_info});

        // initialize the labels
        std::unordered_map<PipeIR::Operation *, LabelSet> labels;
        for (auto &f_kv : s->funcs) {
            for (auto &s_kv : f_kv.second->bbs_) {
                for (auto &op : s_kv.second->ops) {
                    std::unordered_set<std::string> initial_labels;
                    InitialLabelVisitor visitor(initial_labels, trace_ctx);
                    visitor.visit(*op);
                    labels.insert({op.get(), initial_labels});
                }
            }
        }

        int num_label_delta;

        do {
            num_label_delta = 0;

            for (auto &f_kv : s->funcs) {
                for (auto &s_kv : f_kv.second->bbs_) {
                    for (auto &op : s_kv.second->ops) {
                        // remove "pre" label
                        auto &label = labels[op.get()];
                        for (auto &v : op->vars_read()) {
                            auto src_op = v->from;
                            if (src_op != nullptr) {
                                auto &src_label = labels[src_op];
                                if (src_label.find("pre") == src_label.end()) {
                                    if (label.find("pre") != label.end()) {
                                        std::cout << *(op.get()) << " pre removed by " << *src_op << std::endl;
                                        num_label_delta++;
                                        label.erase("pre");
                                    }
                                }
                            } else if (v->is_constant) {
                                // do nothing if this is a constant
                            } else {
                                // should be function parameter
                                assert(args.find(v) != args.end());
                            }
                        }
                        for (auto &v : op->vars_written()) {
                            for (auto &dep_op : v->uses) {
                                auto &dep_label = labels[dep_op];
                                if (dep_label.find("post") == dep_label.end()) {
                                    if (label.find("post") != label.end()) {
                                        std::cout << *op << " post removed by ";
                                        v->print(std::cout);
                                        std::cout << " from " << *dep_op;
                                        std::cout << std::endl;
                                        num_label_delta++;
                                        label.erase("post");
                                    }
                                }
                            }
                            if (label.find("pre") == label.end()) {
                                for (auto &use_stage : v->branch_uses) {
                                    for (auto &dep_stage : use_stage->next_stages) {
                                        std::cout << dep_stage->name << " pre removed by " << *op << std::endl;
                                        for (auto &op : dep_stage->ops) {
                                            auto &dep_label = labels[op.get()];
                                            if (dep_label.find("pre") != dep_label.end()) {
                                                num_label_delta++;
                                                dep_label.erase("pre");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } while (num_label_delta > 0);

        for (auto &f_kv : s->funcs) {
            for (auto &s_kv : f_kv.second->bbs_) {
                for (auto &op : s_kv.second->ops) {
                    auto &label = labels[op.get()];
                    bool could_be_pre = (label.find("pre") != label.end());
                    bool could_be_post = (label.find("post") != label.end());
                    if (could_be_pre) {
                        op->color_str = "#d5f5e3";
                    } else if (could_be_post) {
                        op->color_str = "#85c1e9";
                    }
                }
            }
        }
        return s;
    }
}
