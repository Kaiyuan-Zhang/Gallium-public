#ifndef __MOURLA_CLICK_STATE_HPP__
#define __MOURLA_CLICK_STATE_HPP__

#include "llvm-incl.hpp"
#include "utils.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <utility>

namespace Morula {
    namespace Click {
        class ElementStateType;

        class StateEntry {
        public:
            enum class T {
                HASH_MAP,
                VECTOR,
                HASH_SET,
                INT,
                ARRAY,
                STRUCT,
                POINTER,
                ELEMENT_BASE,
                UNKNOWN,
            };

            T type;

            std::string unknown_name;

            // all size are in bytes
            int map_key_size;
            int map_val_size;

            int vector_ele_size;
            int array_ele_size;
            int array_num_ele;
            int set_key_size;
            int int_num_bytes;

            int entry_size;

            std::string state_name;

            std::shared_ptr<ElementStateType> struct_rec;

            void print(std::ostream &os, int indent=-1) const;
        };

        class ElementStateType {
        public:
            std::vector<int> field_offset;
            std::vector<StateEntry> field_type;

            void push_back_field(int offset, const StateEntry &e);

            void print(std::ostream &os, int indent=-1) const;
        };

        std::shared_ptr<ElementStateType> parse_click_state(llvm::Module *m, llvm::Type *elemnt_t);

        void assign_state_name(std::shared_ptr<ElementStateType> &es, NameFactory &name_gen);
    }
}

std::ostream &operator<<(std::ostream &os, const Morula::Click::ElementStateType &t);

#endif
