#pragma once

#include <iostream>
#include <vector>
#include <unordered_map>
#include <memory>
#include "utils.hpp"
#include "pkt-layout.hpp"
#include "graph.hpp"

namespace P4IR {
    class HeaderRef {
    public:
        HeaderRef(std::string hdr, std::string field)
            : is_meta(false),
              is_arg(false),
              is_constant(false),
              header(hdr),
              field(field) {}

        HeaderRef(bool meta_or_arg, std::string name)
            : is_meta(meta_or_arg),
              is_arg(!meta_or_arg),
              field(name) {}
        HeaderRef(std::string constant)
            : is_meta(false),
              is_arg(false),
              is_constant(true),
              header(""),
              field(constant) {}
        bool is_constant = false;
        bool is_meta = false;
        bool is_arg = false;
        std::string header;
        std::string field;

        void print(std::ostream& os) const;
    };

    class PktParser {
    public:
        struct ParsingEdge {
            HeaderRef field_name;
            uint64_t value;
            ParsingEdge(std::string hdr, std::string field, uint64_t v)
                : field_name(std::move(hdr), std::move(field)),
                  value(v) {}
        };
        PacketLayout layout;
        Graph<std::string, ParsingEdge, AdjacencyList<ParsingEdge>> parse_graph;

        PktParser(
                PacketLayout l,
                Graph<std::string, ParsingEdge, AdjacencyList<ParsingEdge>> g)
            : layout(l),
              parse_graph(std::move(g)) {}

        void print_single_header(
                const HeaderLayout& layout,
                std::ostream& os,
                int indent = 0) const;
        void print_headerdef(std::ostream& os, int indent = 0) const;
        void print_parser(std::ostream& os, int indent = 0) const;
    };

    class Type {
    public:
        enum T {
            BITVEC,
            TUPLE,
        };
        std::vector<size_t> field_sizes;
    };

    class GlobalState {
    public:
        enum T {
            MAP,
            ARRAY,
        };

        struct {
            std::shared_ptr<Type> etype;
        } array_info;

        struct {
            std::shared_ptr<Type> ktype;
            std::shared_ptr<Type> vtype;
        } map_info;

        std::string name;
    };


    class Operation {
    public:
        enum T {
            MOV,
            ALU,
        };
        T type;
        HeaderRef dst;
        std::vector<HeaderRef> args;
        std::string alu_op;

        Operation() : dst("0") {}

        Operation(HeaderRef d, std::string op, std::vector<HeaderRef> _args)
            : type(T::ALU),
              dst(std::move(d)),
              alu_op(op),
              args(std::move(_args)) {}

        Operation(HeaderRef d, std::vector<HeaderRef> _args)
            : type(T::MOV),
              dst(std::move(d)),
              args(std::move(_args)) {}

        void print(std::ostream& os, int indent = 0) const;
    };


    class Action {
    public:
        std::string name;
        std::vector<std::string> args;
        std::vector<std::shared_ptr<Operation>> ops;

        Action() {}
        Action(std::string n) : name(std::move(n)) {}

        void print(std::ostream& os, int indent = 0) const;
    };

    class Stage {
    public:
        enum class T {
            DIRECT_ACTION,
            TABLE,
        };

        T type;
        std::string name;
        struct {
            std::vector<HeaderRef> keys;
            std::vector<std::string> actions;
        } table_info;

        std::string act;
        std::vector<std::string> act_args;
        struct CondList {
            struct Entry {
                HeaderRef arg1;
                HeaderRef arg2;
                std::string cmp_op;
            };
            using AndList = std::vector<Entry>;
            std::vector<AndList> or_list;
        };
        CondList conds;

        std::unordered_map<std::string, std::string> branch_next_stage{};
        std::string default_next_stage{""};

        size_t sz;

        void print(std::ostream& os, int indent = 0) const;
    };

    class Metadata {
    public:
        std::unordered_map<std::string, size_t> fields;

        void print(std::ostream& os, int indent = 0) const;
    };

    class Program {
    public:
        std::shared_ptr<PktParser> parser;
        std::shared_ptr<Metadata> meta;
        std::unordered_map<std::string, std::shared_ptr<Action>> actions;
        std::unordered_map<std::string, std::shared_ptr<Stage>> stages;
        std::string init_stage;

        void add_action(std::shared_ptr<Action> act) {
            assert(actions.find(act->name) == actions.end());
            actions[act->name] = act;
        }

        void add_stage(std::shared_ptr<Stage> s) {
            assert(stages.find(s->name) == stages.end());
            stages[s->name] = s;
        }
        void print_main(std::ostream& os, int indent = 0) const;

    protected:
        void print_aux(std::ostream& os, const std::string &s, int indent) const;
    };

    void print_p4_prog_tofino(const Program& prog, std::ostream &os);
}
