#ifndef _TARGET_P4_HPP_
#define _TARGET_P4_HPP_


#include "target-lang.hpp"
#include "target-codegen.hpp"
#include "placer.hpp"
#include "formatter.hpp"
#include <unordered_map>
#include <unordered_set>
#include <tuple>
#include <vector>
#include <utility>
#include <memory>

namespace Target {
    namespace P4 {
        const int indent_width = 4;
        
        class Action;
        class Control;
        class Table;
        class Stmt;
        
        class UntranslatedStmt;

        class Parser;
        class HeaderDef;
        
        class Prog;

        class Value;
        class LValue;
        class RValue;

        class ConstVal;
        class VarRef;
        class MetadataRef;
        class HeaderRef;

        struct PrintConf {
            bool is_p4_14 = true;
            std::string metadata_name;
        };

        class Value {
        public:
            bool is_lvalue() const;
            bool is_rvalue() const;

            virtual std::string str(const PrintConf &conf) const = 0;
        protected:

            virtual bool is_lvalue_() const;
            virtual bool is_rvalue_() const;
        };

        class LValue : public virtual Value {
        protected:
            virtual bool is_lvalue_() const override;
        };

        class RValue : public virtual Value {
        protected:
            virtual bool is_rvalue_() const override;
        };

        class ConstVal : public RValue {
        public:
            std::string val_;

            ConstVal(const std::string &val);

            std::string str(const PrintConf &conf) const override;
        };

        class VarRef : public LValue, public RValue {
        public:
            std::string var_;

            VarRef(const std::string &var);
            std::string str(const PrintConf &conf) const override;
        };

        class MetadataRef : public LValue, public RValue {
        public:
            std::string field_;

            MetadataRef(const std::string &field);
            std::string str(const PrintConf &conf) const override;
        };

        class HeaderRef : public LValue, public RValue {
        public:
            std::string header_;
            std::string field_;

            HeaderRef(const std::string &hdr, const std::string &field);
            std::string str(const PrintConf &conf) const override;
        };

        class Stmt {
        public:
            Stmt();

            virtual bool is_assign() const;
            virtual bool is_apply() const;
            virtual bool is_action_stmt() const;

            virtual CodeBlock gen_code(const PrintConf &conf) const = 0;
        };

        class UntranslatedStmt : public Stmt {
        public:
            UntranslatedStmt(const std::string &str);
            virtual CodeBlock gen_code(const PrintConf &conf) const override;

            std::string str_;
        };

        using StmtBlock = std::vector<std::shared_ptr<Stmt>>;

        class Apply : public Stmt {
        public:
            using Cases = std::unordered_map<std::string, StmtBlock>;
            
            std::string tab_;
            Cases cases_;
            
            Apply(const std::string &table_name);
            Apply(const std::string &table_name, const Cases &cases);

            // TODO: add miss, hit and action_run conditions
            // https://github.com/p4lang/p4c/blob/master/testdata/p4_16_samples/apply-cf.p4
            CodeBlock gen_code(const PrintConf &conf) const override;
        };

        class Assign : public Stmt {
        public:
            Assign(std::shared_ptr<LValue> dst, std::shared_ptr<RValue> val);

            CodeBlock gen_code(const PrintConf &conf) const override;

            std::shared_ptr<LValue> dst_;
            std::shared_ptr<RValue> val_;
        };

        using ValList = std::vector<std::shared_ptr<Value>>;

        class PrimitiveStmt : public Stmt {
        public:
            PrimitiveStmt(const std::string &primitive,
                          const std::vector<std::shared_ptr<Value>> args);

            CodeBlock gen_code(const PrintConf &conf) const override;
            
            std::string op_;
            std::vector<std::shared_ptr<Value>> args_;
        };

        class OpStmt : public Stmt {
        public:
            OpStmt(const std::string &op_string,
                   std::shared_ptr<LValue> dst,
                   const std::vector<std::shared_ptr<RValue>> args);

            CodeBlock gen_code(const PrintConf &conf) const override;

            std::string op_;
            std::shared_ptr<LValue> dst_;
            std::vector<std::shared_ptr<RValue>> args_;
        };

        class IfStmt : public Stmt {
        public:
            IfStmt(std::shared_ptr<RValue> cond,
                   const std::vector<std::shared_ptr<Stmt>> &t_branch,
                   const std::vector<std::shared_ptr<Stmt>> &f_branch);

            CodeBlock gen_code(const PrintConf &conf) const override;
            
            std::shared_ptr<RValue> cond_;
            std::vector<std::shared_ptr<Stmt>> t_branch_;
            std::vector<std::shared_ptr<Stmt>> f_branch_;
        };

        using TableReadField = RValue;

        class Table {
        public:
            enum class MatchType {
                EXACT,
                LPM,
            };
            using ReadEntry = std::tuple<std::shared_ptr<TableReadField>, MatchType>;
            Table(const std::string &name,
                  const std::vector<ReadEntry> &reads,
                  const std::vector<std::shared_ptr<Action>> &actions,
                  int size);

            Table(const std::string &name,
                  const std::vector<ReadEntry> &reads,
                  const std::vector<std::shared_ptr<Action>> &actions,
                  int size,
                  std::shared_ptr<Action> default_action);

            CodeBlock code(const PrintConf &conf) const;

            std::string name_;
            std::vector<ReadEntry> reads_;
            std::vector<std::shared_ptr<Action>> actions_;
            int size_;
            std::shared_ptr<Action> default_action_;
        };
        
        class Control {
        public:
            std::string name_;
            std::vector<std::shared_ptr<Stmt>> stmts_;
            
            Control(const std::string &name,
                    const std::vector<std::shared_ptr<Stmt>> stmts);

            CodeBlock code(const PrintConf &conf) const;
        };

        class Action {
        public:
            std::string name_;
            std::vector<std::string> params_;
            std::vector<std::shared_ptr<Stmt>> stmts_;

            Action(const std::string &name,
                   const std::vector<std::string> &params,
                   const std::vector<std::shared_ptr<Stmt>> stmts);

            CodeBlock gen_code(const PrintConf &conf) const;
        };

        class ParserStage {
        public:
            using TransitionEntry = std::tuple<std::string, std::shared_ptr<ParserStage>>;
            ParserStage(const std::string &name,
                        const std::vector<std::string> &extracts);
            // ParserStage(const std::string &name,
            //             std::vector<std::string> extracts);
            ParserStage(const std::string &name,
                        const std::vector<std::string> &extracts,
                        const std::vector<TransitionEntry> &next_stages);
            
            CodeBlock code(const PrintConf &conf) const;

            void add_match_rule(const std::string &val,
                                std::shared_ptr<ParserStage> next_stage);

            std::string name_;
            std::shared_ptr<HeaderRef> match_field;
            std::vector<std::string> extracts_;
            std::vector<TransitionEntry> next_stages_;
        };

        class Parser {
        public:
            Parser(const std::vector<std::shared_ptr<ParserStage>> &stages);
            CodeBlock code(const PrintConf &conf) const;

            std::vector<std::shared_ptr<ParserStage>> stages_;
        };

        class HeaderDef {
        public:
            HeaderDef(const std::string &name,
                      const std::vector<std::tuple<std::string, int>> &fields);

            std::string name_;
            std::vector<std::tuple<std::string, int>> fields_;
            CodeBlock code(const PrintConf &conf) const;
        };

        class Prog {
        public:
            using HeaderDecl = std::tuple<std::string, std::string>;
            std::vector<HeaderDecl> header_decls;
            std::vector<HeaderDef> header_def_list_;
            Parser parser_;
            std::vector<std::shared_ptr<Table>> tables_;
            std::shared_ptr<Control> ingress_;
            std::vector<std::shared_ptr<Control>> controls_;

            Prog(const std::vector<HeaderDef> &h_defs,
                 const Parser &parser);

            void add_table(std::shared_ptr<Table> tab);
            void add_control(std::shared_ptr<Control> control);

            void set_ingress(std::shared_ptr<Control> ingress);

            CodeBlock code(const PrintConf &conf) const;
        };
    }
}


#endif /* _TARGET_P4_HPP_ */
