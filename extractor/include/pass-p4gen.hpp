#ifndef _MORULA_PASS_P4GEN_HPP_
#define _MORULA_PASS_P4GEN_HPP_

#include "pass.hpp"
#include "target-p4.hpp"
#include "target-codegen.hpp"

namespace Morula {
    using P4Entry = std::vector<int>;
    
    struct P4TableInfo {
        P4Entry key_info;
        P4Entry val_info;

        std::vector<std::string> key_fields;
        std::vector<std::string> val_fields;

        void print(std::ostream &os) const;
    };
    
    struct P4GenCtx : public PassCtx {
        std::unordered_map<std::string, StructLayout> metadata_entries;
        std::unordered_map<std::string, P4TableInfo> tables;
        std::unordered_map<std::string,
                           std::shared_ptr<Target::P4::Value>> reg2p4val;
        std::unordered_map<std::string, int> metadata_field;
        
        P4GenCtx() {}
        P4GenCtx(PassCtx &&ctx) : PassCtx(std::move(ctx)) {}
    };

    struct P4Source {
        Target::P4::Prog prog;

        P4Source(const Target::P4::Prog &p) : prog(p) {}
    };

    std::string p4_ident_sanitize(const std::string &ident);

    class P4ExtendCtx : public Pass<P4ExtendCtx, PassCtx, P4GenCtx> {
        friend class Pass<P4ExtendCtx, PassCtx, P4GenCtx>;
        static std::unique_ptr<P4GenCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };
    
    class P4Alloca : public Pass<P4Alloca, P4GenCtx, P4GenCtx> {
        friend class Pass<P4Alloca, P4GenCtx, P4GenCtx>;
        static std::unique_ptr<P4GenCtx> pass_impl(std::unique_ptr<P4GenCtx> s);
    };

    using P4UpdateMeta = PassSeq<CastPass<P4GenCtx, PassCtx>,
                                 UpdateVarSource<PassCtx>,
                                 UpdateEdges,
                                 UpdateDeps,
                                 CastPass<PassCtx, P4GenCtx>>;

    DECLARE_PASS(P4EntryAlloc, P4GenCtx, P4GenCtx);
    DECLARE_PASS(P4Map, P4GenCtx, P4GenCtx);
    DECLARE_PASS(P4SplitAction, P4GenCtx, P4GenCtx);
    DECLARE_PASS(P4AssignMeta, P4GenCtx, P4GenCtx);
    DECLARE_PASS(P4AssignEntry, P4GenCtx, P4GenCtx);

    DECLARE_PASS(P4CodeGen, P4GenCtx, P4Source);
}

bool operator==(const Morula::P4TableInfo &lsh, const Morula::P4TableInfo &rhs);

#endif /* _MORULA_PASS_P4GEN_HPP_ */
