#include "click-state.hpp"

namespace Morula {
    namespace Click {
        void StateEntry::print(std::ostream &os, int indent) const {
            switch (type) {
                case T::HASH_MAP:
                    os << "hash_map<"
                       << map_key_size << " -> "
                       << map_val_size << ">";
                    break;
                case T::VECTOR:
                    os << "vector<" << vector_ele_size << ">";
                    break;
                case T::HASH_SET:
                    os << "hash_set<" << set_key_size << ">";
                    break;
                case T::INT:
                    os << "int<" << int_num_bytes << ">";
                    break;
                case T::POINTER:
                    os << "pointer";
                    break;
                case T::ARRAY:
                    os << "array<" << array_ele_size << ", " << array_num_ele << ">";
                    break;
                case T::ELEMENT_BASE:
                    os << "element_base";
                    break;
                case T::STRUCT:
                    os << std::endl;
                    struct_rec->print(os, indent);
                    break;
                case T::UNKNOWN:
                    os << "unknown";
                    break;
            }
        }

        void ElementStateType::push_back_field(int offset, const StateEntry &e) {
            assert(field_offset.size() == field_type.size());
            field_offset.push_back(offset);
            field_type.push_back(e);
        }
        std::shared_ptr<ElementStateType> parse_click_state(llvm::Module *m, llvm::Type *element_t) {
            auto result = std::make_shared<ElementStateType>();
            assert(element_t->isStructTy());
            auto dl = std::make_shared<llvm::DataLayout>(m);
            auto sl = dl->getStructLayout(static_cast<llvm::StructType *>(element_t));
            for (int i = 0; i < element_t->getStructNumElements(); i++) {
                auto t = element_t->getStructElementType(i);
                auto t_name = get_llvm_type_str(*t);
                auto field_off = sl->getElementOffset(i);
                if (str_begin_with(t_name, "%class.Element.base")) {
                    StateEntry e;
                    e.type = StateEntry::T::ELEMENT_BASE;
                    result->push_back_field(field_off, e);
                } else if (str_begin_with(t_name, "%class.HashMap")) {
                    auto bucket_p = t->getStructElementType(0)->getPointerElementType();
                    auto bucket_t = bucket_p->getPointerElementType();
                    auto pair_t = bucket_t->getStructElementType(0);
                    auto kt = pair_t->getStructElementType(0);
                    auto vt = pair_t->getStructElementType(1);

                    StateEntry e;
                    e.type = StateEntry::T::HASH_MAP;
                    e.map_key_size = get_type_size(m, kt);
                    e.map_val_size = get_type_size(m, vt);

                    result->push_back_field(field_off, e);
                } else if (str_begin_with(t_name, "%class.Vector")) {
                    auto vec_ptr = t->getStructElementType(0)->getStructElementType(0);
                    auto vec_ele = vec_ptr->getPointerElementType();                                                                                                                                                                       
                    auto ele_size = get_type_size(m, vec_ele);
                    StateEntry e;
                    e.type = StateEntry::T::VECTOR;
                    e.vector_ele_size = ele_size;

                    result->push_back_field(field_off, e);
                } else if (t->isIntegerTy()) {
                    StateEntry e;
                    e.type = StateEntry::T::INT;
                    assert(t->getIntegerBitWidth() % 8 == 0);
                    e.int_num_bytes = t->getIntegerBitWidth() / 8;
                    result->push_back_field(field_off, e);
                } else if (t->isPointerTy()) {
                    StateEntry e;
                    e.type = StateEntry::T::POINTER;
                    result->push_back_field(field_off, e);
                } else if (t->isStructTy()) {
                    auto et = parse_click_state(m, t);
                    StateEntry e;
                    e.type = StateEntry::T::STRUCT;
                    e.struct_rec = std::move(et);
                    result->push_back_field(field_off, e);
                } else {
                    StateEntry e;
                    e.type = StateEntry::T::UNKNOWN;
                    result->push_back_field(field_off, e);
                }
            }
            return result;
        }

        void assign_state_name(std::shared_ptr<ElementStateType> &es, NameFactory &name_gen) {
            using ST = StateEntry::T;
            for (auto &e : es->field_type) {
                std::string name = "";
                switch (e.type) {
                    case ST::HASH_MAP:
                        name = name_gen("hash_map");
                        break;
                    case ST::HASH_SET:
                        name = name_gen("hash_set");
                        break;
                    case ST::VECTOR:
                        name = name_gen("vector");
                        break;
                    case ST::INT:
                        name = name_gen("glbl_int");
                        break;
                    case ST::ARRAY:
                        name = name_gen("arr");
                        break;
                    case ST::STRUCT:
                        assign_state_name(e.struct_rec, name_gen);
                        break;
                    case ST::POINTER:
                        name = name_gen("ptr");
                        break;
                    case ST::ELEMENT_BASE:
                        name = name_gen("ele_base");
                        break;
                    case ST::UNKNOWN:
                        break;
                }
                e.state_name = name;
            }
        }

        void ElementStateType::print(std::ostream &os, int indent) const {
            for (int i = 0; i < indent; i++) {
                os << " ";
            }
            if (indent >= 0) {
                indent += 2;
            }
            os << "ElementState {";
            if (indent >= 0)
                os << std::endl;
            assert(field_offset.size() == field_type.size());
            for (int i = 0; i < field_offset.size(); i++) {
                if (i != 0) {
                    os << ", ";
                    if (indent >= 0)
                        os << std::endl;
                }

                for (int i = 0; i < indent; i++) {
                    os << " ";
                }

                os << field_offset[i] << " : ";
                field_type[i].print(os, indent);
            }
            os << "}";
        }
    }
}
std::ostream &operator<<(std::ostream &os, const Morula::Click::ElementStateType &t) {
    t.print(os);
    return os;
}
