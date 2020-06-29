#include "target-p4.hpp"
#include <unordered_map>
#include <cstdint>

namespace Target {
    namespace P4 {

        bool Value::is_lvalue() const {
            return this->is_lvalue_();
        }
        
        bool Value::is_rvalue() const {
            return this->is_rvalue_();
        }

        bool Value::is_lvalue_() const {
            return false;
        }

        bool Value::is_rvalue_() const {
            return false;
        }

        bool LValue::is_lvalue_() const {
            return true;
        }

        bool RValue::is_rvalue_() const {
            return true;
        }
        
        ConstVal::ConstVal(const std::string &v): val_(v) {}

        std::string ConstVal::str(const PrintConf &conf) const {
            return val_;
        }

        VarRef::VarRef(const std::string &var): var_(var) {}

        std::string VarRef::str(const PrintConf &conf) const {
            return var_;
        }

        MetadataRef::MetadataRef(const std::string &f): field_(f) {}

        std::string MetadataRef::str(const PrintConf &conf) const {
            return conf.metadata_name + "." + field_;
        }

        HeaderRef::HeaderRef(const std::string &h,
                             const std::string &f): header_(h),
                                                    field_(f) {}

        std::string HeaderRef::str(const PrintConf &conf) const {
            return header_ + "." + field_;
        }

        Stmt::Stmt() {}

        bool Stmt::is_assign() const {
            return false;
        }

        bool Stmt::is_apply() const {
            return false;
        }

        bool Stmt::is_action_stmt() const {
            return false;
        }

        UntranslatedStmt::UntranslatedStmt(const std::string &str): str_(str) {}

        CodeBlock UntranslatedStmt::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            result.append_line("<Untranslated: " + str_ + " >");
            return result;
        }

        Apply::Apply(const std::string &t): tab_(t) {}
        Apply::Apply(const std::string &t, const Apply::Cases &c): tab_(t), cases_(c) {}

        CodeBlock Apply::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            std::string apply_line = "apply(" + tab_ + ")";
            if (cases_.size() == 0) {
                apply_line.append(1, ';');
                result.append_line(apply_line);
                return result;
            } else {
                apply_line.append(" {");
                result.append_line(apply_line);
                
                CodeBlock cases;
                for (auto &kv : cases_) {
                    auto action_name = kv.first;
                    auto stmts = kv.second;
                    cases.append_line(action_name + " {");
                    for (int i = 0; i < stmts.size(); i++) {
                        auto blk = stmts[i]->gen_code(conf);
                        cases.append_blk(blk, indent_width);
                    }
                    cases.append_line("}");
                }
                result.append_blk(cases, indent_width);
                result.append_line("}");
                return result;
            }
        }

        Assign::Assign(std::shared_ptr<LValue> dst,
                       std::shared_ptr<RValue> val): dst_(dst),
                                                     val_(val) {}

        CodeBlock Assign::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            auto dst = dst_->str(conf);
            auto val = val_->str(conf);
            result.append_line("modify_field(" + dst + ", " + val + ");");
            return result;
        }

        PrimitiveStmt::PrimitiveStmt(const std::string &op,
                                     const std::vector<std::shared_ptr<Value>> args): op_(op),
                                                                                      args_(args) {}

        CodeBlock PrimitiveStmt::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            std::string arg_str = "";
            for (int i = 0; i < args_.size(); i++) {
                arg_str += args_[i]->str(conf);
                if (i != args_.size() - 1) {
                    arg_str += ", ";
                }
            }
            std::string line = op_ + "(" + arg_str + ");";
            result.append_line(line);
            return result;
        }

        OpStmt::OpStmt(const std::string &op_string,
                       std::shared_ptr<LValue> dst,
                       const std::vector<std::shared_ptr<RValue>> args): op_(op_string),
                                                                               dst_(dst),
                                                                               args_(args) {}

        CodeBlock OpStmt::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            auto dst = dst_->str(conf);
            std::string arg_str = "";
            for (int i = 0; i < args_.size(); i++) {
                arg_str += args_[i]->str(conf);
                if (i != args_.size() - 1) {
                    arg_str += ", ";
                }
            }
            std::string line = op_ + "(" + arg_str + ");";
            result.append_line(line);
            return result;
        }

        IfStmt::IfStmt(std::shared_ptr<RValue> c,
                       const std::vector<std::shared_ptr<Stmt>> &t,
                       const std::vector<std::shared_ptr<Stmt>> &f): cond_(c),
                                                                     t_branch_(t),
                                                                     f_branch_(f) {}

        CodeBlock IfStmt::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            result.append_line("if (" + cond_->str(conf) + ") {");
            CodeBlock t_blk;
            for (int i = 0; i < t_branch_.size(); i++) {
                auto stmt = t_branch_[i];
                auto blk = stmt->gen_code(conf);
                t_blk.append_blk(blk);
            }

            CodeBlock f_blk;
            for (int i = 0; i < f_branch_.size(); i++) {
                auto stmt = f_branch_[i];
                auto blk = stmt->gen_code(conf);
                f_blk.append_blk(blk);
            }
            result.append_blk(t_blk, indent_width);

            if (f_branch_.empty()) {
                result.append_line("}");
                return result;
            } else {
                result.append_line("} {");
                result.append_blk(f_blk, indent_width);
                result.append_line("}");
                return result;
            }
        }
        

        Table::Table(const std::string &name,
                     const std::vector<ReadEntry> &reads,
                     const std::vector<std::shared_ptr<Action>> &actions,
                     int size): name_(name),
                                reads_(reads),
                                actions_(actions),
                                size_(size),
                                default_action_(nullptr) {}
        
        Table::Table(const std::string &name,
                     const std::vector<ReadEntry> &reads,
                     const std::vector<std::shared_ptr<Action>> &actions,
                     int size,
                     std::shared_ptr<Action> default_action): name_(name),
                                                              reads_(reads),
                                                              actions_(actions),
                                                              size_(size),
                                                              default_action_(default_action) {}
        
        static std::string matchtype2str(Table::MatchType t) {
            switch (t) {
            case Table::MatchType::EXACT:
                return "exact";
                break;
            case Table::MatchType::LPM:
                return "lpm";
                break;
            default:
                throw CodeGenException{"unknown match type"};
            }
        }

        CodeBlock Table::code(const PrintConf &conf) const {
            CodeBlock result;
            result.append_line("table " + name_ + " {");
            auto idt = indent_width;
            
            // the "reads" part
            result.append_line("reads {", idt);
            idt += indent_width;
            for (int i = 0; i < reads_.size(); i++) {
                auto &e = reads_[i];
                auto field = std::get<0>(e);
                auto matchtype = std::get<1>(e);
                auto field_str = field->str(conf);
                auto match_str = matchtype2str(matchtype);
                result.append_line(field_str + " : " + match_str + ";", idt);
            }
            idt -= indent_width;
            result.append_line("}", idt);

            // the "actions" part
            result.append_line("actions {", idt);
            idt += indent_width;
            for (int i = 0; i < actions_.size(); i++) {
                auto act = actions_[i];
                result.append_line(act->name_ + ";", idt);            }
            idt -= indent_width;
            result.append_line("}", idt);

            // size
            result.append_line("size : " + std::to_string(size_) + ";", idt);

            // default_action
            if (default_action_ != nullptr) {
                result.append_line("default_action : " + default_action_->name_ + ";", idt);
            }
            result.append_line("}");
            return result;
        }

        Control::Control(const std::string &name,
                         const std::vector<std::shared_ptr<Stmt>> stmts): name_(name),
                                                                          stmts_(stmts) {}

        CodeBlock Control::code(const PrintConf &conf) const {
            CodeBlock result;
            result.append_line("control " + name_ + " {");

            for (int i = 0; i < stmts_.size(); i++) {
                result.append_blk(stmts_[i]->gen_code(conf), indent_width);
            }
            
            result.append_line("}");
            return result;
        }

        Action::Action(const std::string &name,
                       const std::vector<std::string> &params,
                       const std::vector<std::shared_ptr<Stmt>> stmts): name_(name),
                                                                        params_(params),
                                                                        stmts_(stmts) {}

        CodeBlock Action::gen_code(const PrintConf &conf) const {
            CodeBlock result;
            std::string param_str = "(";
            for (int i = 0; i < params_.size(); i++) {
                param_str += params_[i];
                if (i != params_.size() - 1) {
                    param_str += ", ";
                }
            }
            result.append_line("action " + name_ + param_str + ") {");

            for (int i = 0; i < stmts_.size(); i++) {
                result.append_blk(stmts_[i]->gen_code(conf), indent_width);
            }
            
            result.append_line("}");
            return result;
        }

        ParserStage::ParserStage(const std::string &name,
                                 const std::vector<std::string> &e): extracts_(e),
                                                                     name_(name) {
            next_stages_.clear();
        }

        // ParserStage::ParserStage(const std::string &name,
        //                          std::vector<std::string> e): extracts_(e),
        //                                                       name_(name) {
        //     next_stages_.clear();
        // }

        ParserStage::ParserStage(const std::string &name,
                                 const std::vector<std::string> &e,
                                 const std::vector<TransitionEntry> &n): extracts_(e),
                                                                         next_stages_(n),
                                                                         name_(name) {}

        CodeBlock ParserStage::code(const PrintConf &conf) const {
            CodeBlock result;
            result.append_line("parser " + name_ + " {");
            for (int i = 0; i < extracts_.size(); i++) {
                auto &e = extracts_[i];
                result.append_line("extract(" + e + ");", indent_width);
            }
            if (next_stages_.size() == 0) {
                result.append_line("return ingress;", indent_width);
            } else {
                assert(match_field != nullptr);
                result.append_line("return select(" + match_field->str(conf) + ") {", indent_width);
                for (int i = 0; i < next_stages_.size(); i++) {
                    auto &entry = next_stages_[i];
                    auto match = std::get<0>(entry);
                    auto next = std::get<1>(entry);
                    result.append_line(match + " : " + next->name_ + ";", indent_width * 2);
                }
                result.append_line("default : ingress;", indent_width * 2);
                result.append_line("}", indent_width);
            }
            result.append_line("}");
            
            return result;
        }

        void ParserStage::add_match_rule(const std::string &val,
                                         std::shared_ptr<ParserStage> next_stage) {
            next_stages_.push_back({val, next_stage});
        }

        Parser::Parser(const std::vector<std::shared_ptr<ParserStage>> &stages): stages_(stages) {}

        CodeBlock Parser::code(const PrintConf &conf) const {
            CodeBlock result;
            for (auto &s : stages_) {
                result.append_blk(s->code(conf));
            }
            return result;
        }

        HeaderDef::HeaderDef(const std::string &name,
                             const std::vector<std::tuple<std::string, int>> &fields) : name_(name),
                                                                                        fields_(fields) {}

        CodeBlock HeaderDef::code(const PrintConf &conf) const {
            CodeBlock result;
            result.append_line("header_type " + name_ + " {");
            result.append_line("fields {", indent_width);
            for (auto &e : fields_) {
                result.append_line(std::get<0>(e) + " : " + std::to_string(std::get<1>(e)) + ";",
                                   indent_width * 2);
            }
            result.append_line("}", indent_width);
            result.append_line("}");
            return result;
        }

        Prog::Prog(const std::vector<HeaderDef> &h_defs,
                   const Parser &parser): header_def_list_(h_defs),
                                          parser_(parser) {}

        void Prog::add_table(std::shared_ptr<Table> tab) {
            tables_.push_back(tab);
        }
        
        void Prog::add_control(std::shared_ptr<Control> control) {
            controls_.push_back(control);
        }

        void Prog::set_ingress(std::shared_ptr<Control> ingress) {
            ingress_ = ingress;
        }

        CodeBlock Prog::code(const PrintConf &conf) const {
            CodeBlock result;

            // Step 1 : add header definition
            // TODO: print parser
            for (auto &def : header_def_list_) {
                result.append_blk(def.code(conf));
            }

            for (auto &decl : header_decls) {
                result.append_line("header " + std::get<0>(decl) + " " + std::get<1>(decl) + ";");
            }

            result.append_line("metadata meta_t meta;");

            result.append_line("");
            result.append_blk(parser_.code(conf));
            
            // Step 2 : all tables, along with the actions
            // print actions first
            std::unordered_map<std::string, std::shared_ptr<Action>> actions;
            for (auto t : tables_) {
                for (auto act : t->actions_) {
                    if (actions.find(act->name_) != actions.end()) {
                        auto old_ptr = reinterpret_cast<uintptr_t>(actions[act->name_].get());
                        auto new_ptr = reinterpret_cast<uintptr_t>(act.get());
                        if (new_ptr != old_ptr) {
                            throw CodeGenException{"found action with same name"};
                        }
                    }
                    actions.insert({act->name_, act});
                }
            }

            for (auto &kv : actions) {
                result.append_blk(kv.second->gen_code(conf));
            }

            // Then print table definition
            // TODO: print table definition
            for (auto t : tables_) {
                result.append_blk(t->code(conf));
            }

            // Step 3 : control ingress
            result.append_blk(ingress_->code(conf));
            return result;
        }
    }
}
