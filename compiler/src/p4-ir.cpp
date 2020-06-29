#include "p4-ir.hpp"
#include <queue>

namespace P4IR {
    void print_p4_prog_tofino(const Program& prog, std::ostream &os) {
        os << "/* -*- P4_14 -*- */" << std::endl;
        os << "#ifdef __TARGET_TOFINO__\n";
        os << "#include <tofino/constants.p4>" << std::endl;
        os << "#include <tofino/intrinsic_metadata.p4>" << std::endl;
        os << "#include <tofino/primitives.p4>" << std::endl;
        os << "#else" << std::endl;
        os << "#error This program is intended to compile for Tofino P4 architecture only" << std::endl;
        os << "#endif" << std::endl;

        os << "/*************************************************************************" << std::endl;
        os << " ***********************  H E A D E R S  *********************************" << std::endl;
        os << " *************************************************************************/" << std::endl;

        // TODO: print header parser
        prog.parser->print_headerdef(os);
        os << std::endl;

        os << "/*************************************************************************" << std::endl;
        os << " ***********************  M E T A D A T A  *******************************" << std::endl;
        os << " *************************************************************************/" << std::endl;
        prog.meta->print(os);
        os << std::endl;

        for (auto& kv : prog.parser->layout.headers) {
            os << "header " << kv.second.name << " " << kv.first << ";";
            os << std::endl;
        }
        os << "metadata meta_t meta;" << std::endl;

        os << "/*************************************************************************" << std::endl;
        os << " ***********************  P A R S E R  ***********************************" << std::endl;
        os << " *************************************************************************/" << std::endl;
        prog.parser->print_parser(os);
        os << std::endl;


        for (auto& kv : prog.actions) {
            kv.second->print(os);
        }

        for (auto& kv : prog.stages) {
            auto&s = kv.second;
            os << "table " << s->name << " {" << std::endl;
            os << "  reads {" << std::endl;
            if (s->type == Stage::T::DIRECT_ACTION) {
                os << "  meta.__always_1 : exact;" << std::endl;
            } else {
                for (auto& k : s->table_info.keys) {
                    os << "  ";
                    k.print(os);
                    os << " : exact;" << std::endl;
                }
            }
            os << "  }" << std::endl;

            os << "  actions {" << std::endl;
            for (auto& a : s->table_info.actions) {
                os << "  " << a << ";" << std::endl;
            }
            os << "  }" << std::endl;

            os << "  default_action : " << s->act << "(";
            for (int i = 0; i < s->act_args.size(); i++) {
                if (i != 0) {
                    os << ", ";
                }
                os << s->act_args[i];
            }
            os << ");" << std::endl;
            if (s->type == Stage::T::DIRECT_ACTION) {
                os << "  size : " << 1 << ";" << std::endl;
            } else {
                os << "  size : " << s->sz << ";" << std::endl;
            }
            os << "}" << std::endl;
        }

        os << "/*************************************************************************" << std::endl;
        os << " ****************  I N G R E S S   P R O C E S S I N G   *****************" << std::endl;
        os << " *************************************************************************/" << std::endl;
        os << "control ingress {" << std::endl;
        prog.print_main(os, 1);
        os << "}" << std::endl;

        os << "/*************************************************************************" << std::endl;
        os << " ****************  E G R E S S   P R O C E S S I N G   *******************" << std::endl;
        os << " *************************************************************************/" << std::endl;
        os << "control egress {" << std::endl;
        os << "}" << std::endl;
    }

    void HeaderRef::print(std::ostream& os) const {
        if (is_meta) {
            os << "meta.";
        } else if (!is_arg && !is_constant) {
            os << header << ".";
        }
        os << field;
    }

    void PktParser::print_single_header(const HeaderLayout& layout, std::ostream& os, int indent) const {
        std::string indent_str{""};
        for (int i = 0; i < indent; i++) {
            indent_str = indent_str + "  ";
        }
        os << indent_str << "header_type " << layout.name << " {" << std::endl
           << indent_str << "  fields {" << std::endl;
        for (auto& e : layout.fields) {
            os << indent_str << "    "
               << e.field_name << " : " << e.field_n_bytes * 8 << ";" << std::endl;
        }
        os << indent_str << "  }" << std::endl
           << indent_str << "}" << std::endl;
    }

    void PktParser::print_headerdef(std::ostream& os, int indent) const {
        std::unordered_map<std::string, const HeaderLayout *> to_print;
        for (auto& kv : layout.headers) {
            to_print.insert({kv.second.name, &(kv.second)});
        }

        for (auto& kv : to_print) {
            print_single_header(*kv.second, os, indent);
            os << std::endl;
        }
    }

    void PktParser::print_parser(std::ostream& os, int indent) const {
        assert(parse_graph.IsAcyclic());
        auto topo_order = parse_graph.TopologicalSort();

        int num_emitted = 0;
        for (int i = topo_order.size() - 1; i >= 0; --i) {
            auto hdr_name = parse_graph.vertex_ref(i);
            assert(layout.headers.find(hdr_name) != layout.headers.end());
            os << "parser ";
            if (num_emitted == 0) {
                os << "start";
            } else {
                os << "parser_stage_" << std::to_string(num_emitted);
            }
            os << " {" << std::endl;
            os << "  extract(" << hdr_name << ");" << std::endl;
            std::optional<HeaderRef> match_field = std::nullopt;
            if (parse_graph.edges().out_edge_begin(i) == parse_graph.edges().out_edge_end(i)) {
                os << "  return ingress;" << std::endl;
            } else {
                for (auto it = parse_graph.edges().out_edge_begin(i); it != it.end(); ++it) {
                    auto e = it.value();
                    if (!match_field.has_value()) {
                        match_field = e.field_name;
                        os << "  return select(";
                        match_field->print(os);
                        os << ") {" << std::endl;
                    }
                    assert(e.field_name.header == match_field->header);
                    assert(e.field_name.field == match_field->field);
                    auto dst = *it;
                    os << std::hex;
                    os << "    0x" << e.value << " : " << parse_graph.vertex_ref(dst) << ";" << std::endl;
                    os << std::dec;
                }
                os << "    default : ingress;" << std::endl;
                os << "  }" << std::endl;
            }

            os << "}" << std::endl;
            num_emitted++;
        }
    }

    void Operation::print(std::ostream& os, int indent) const {
        std::string indent_str{""};
        for (int i = 0; i < indent; i++) {
            indent_str = indent_str + "  ";
        }
        os << indent_str;
        os << alu_op;
        os << "(";
        dst.print(os);
        for (int i = 0; i < args.size(); i++) {
                os << ", ";
            args[i].print(os);
        }
        os << ");";
    }

    void Action::print(std::ostream& os, int indent) const {
        std::string indent_str{""};
        for (int i = 0; i < indent; i++) {
            indent_str = indent_str + "  ";
        }
        os << indent_str << "action " << name << "(";
        for (int i = 0; i < args.size(); i++) {
            if (i != 0) {
                os << ", ";
            }
            os << args[i];
        }
        os << ") {" << std::endl;
        for (auto& op : ops) {
            op->print(os, indent + 1);
            os << std::endl;
        }
        os << indent_str << "}" << std::endl;
    }

    void Metadata::print(std::ostream& os, int indent) const {
        std::string indent_str{""};
        for (int i = 0; i < indent; i++) {
            indent_str = indent_str + "  ";
        }
        os << indent_str << "header_type meta_t {" << std::endl
           << indent_str << "  fields {" << std::endl;
        for (auto& kv : fields) {
            os << indent_str << "    "
               << kv.first << " : " << kv.second << ";" << std::endl;
        }
        os << indent_str << "  }" << std::endl
           << indent_str << "}" << std::endl;
    }

    void Program::print_main(std::ostream& os, int indent) const {
        print_aux(os, init_stage, indent);
    }

    void Program::print_aux(std::ostream& os, const std::string &s, int indent) const {
        if (s == "") {
            return;
        }
        assert(stages.find(s) != stages.end());
        auto& stage = stages.find(s)->second;
        std::string indent_str{""};
        for (int i = 0; i < indent; i++) {
            indent_str = indent_str + "  ";
        }
        std::string old_indent = "";
        if (stage->conds.or_list.size() > 0) {
            os << indent_str << "if (";
            for (int i = 0; i < stage->conds.or_list.size(); i++) {
                if (i != 0) {
                    os << " or ";
                }
                auto& and_list = stage->conds.or_list[i];
                os << "(";
                for (int j = 0; j < and_list.size(); j++) {
                    if (j != 0) {
                        os << " and ";
                    }
                    auto& e = and_list[j];
                    os << "(";
                    e.arg1.print(os);
                    os << " " << e.cmp_op << " ";
                    e.arg2.print(os);
                    os << ")";
                }
                os << ")";
            }
            os << ") {" << std::endl;
            old_indent = indent_str;
            indent_str += "  ";
        }
        os << indent_str << "apply(" << s << ")";

        if (stage->branch_next_stage.size() > 0) {
            os << " {" << std::endl;
            indent_str = indent_str + "  ";
            for (auto& kv : stage->branch_next_stage) {
                os << indent_str << kv.first << " {" << std::endl;
                os << indent_str << "  ";
                print_aux(os, kv.second, indent + 1);
                os << indent_str << "}";
            }
            indent_str = indent_str.substr(indent_str.length() - 2);
            os << indent_str << "}";
            if (stage->conds.or_list.size() > 0) {
                os << old_indent << "}" << std::endl;
            }
        } else {
            os << ";" << std::endl;
            if (stage->conds.or_list.size() > 0) {
                os << old_indent << "}" << std::endl;
            }
            print_aux(os, stage->default_next_stage, indent);
        }
    }
}
