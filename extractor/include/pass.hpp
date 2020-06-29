#ifndef _MORULA_PASS_HPP_
#define _MORULA_PASS_HPP_

#include <type_traits>
#include "target-lang.hpp"

namespace Morula {
    /*
     * Base class for those "common states" that is used during
     * compilation passes
     */
    using BlkName = std::string;
    using BlkNameSet = std::unordered_set<BlkName>;
    struct PassCtx {
        std::shared_ptr<llvm::Module> llvm_module;
        std::shared_ptr<NameFactory> name_gen;
        std::unordered_map<BlkName, std::shared_ptr<Target::BasicBlock>> blocks;
        std::unordered_map<BlkName, BlkNameSet> fwd_edges;
        std::unordered_map<BlkName, BlkNameSet> rev_edges;
        std::unordered_map<std::string, InstID> var_source;
        InstIDUmap<InstIDUset> inst_pre_req;
        InstIDUmap<InstIDUset> inst_rev_dep;

        PassCtx() {}
        virtual ~PassCtx() = default;
        PassCtx(PassCtx &&ctx): llvm_module(ctx.llvm_module),
                                name_gen(ctx.name_gen),
                                blocks(std::move(ctx.blocks)),
                                fwd_edges(std::move(ctx.fwd_edges)),
                                rev_edges(std::move(ctx.rev_edges)),
                                var_source(std::move(ctx.var_source)),
                                inst_pre_req(std::move(ctx.inst_pre_req)),
                                inst_rev_dep(std::move(ctx.inst_rev_dep)) {}

        std::shared_ptr<Target::Instruction> get_inst(const InstID &id) const;
    };

    /*
     * Base class for all compile passes
     * This should be a static method only class.
     */
    template<typename D, typename S, typename T>
    class Pass {
    public:
        using SrcT = S;
        using DstT = T;
        Pass();

        static std::unique_ptr<T> apply_pass(std::unique_ptr<S> s) {
            return D::pass_impl(std::move(s));
        }
    };

    template<typename T>
    class NopPass : public Pass<NopPass<T>, T, T> {
    public:
        static std::unique_ptr<T> pass_impl(std::unique_ptr<T> s) {
            return s;
        }
    };

    /*
     * Helper template that checks if the type parameter is empty
     */
    template<typename... TS>
    struct EmptyTArgs {
        static constexpr bool value = true;
    };

    template<typename T, typename... TS>
    struct EmptyTArgs<T, TS...> {
        static constexpr bool value = false;
    };

    /*
     * A Helper class that can apply a sequence of passes
     */

    // The base class of pass seq
    // (Other than PassSeq, this class SHOULD NOT be used or subclassed)
    class PassSeqBase {};

    template<typename... PS>
    class PassSeq : public PassSeqBase {
    public:
        using SrcT = int;
        using DstT = int;
    };

    template<typename P, typename... PS>
    class PassSeq<P, PS...> : public PassSeqBase {
        static_assert(std::is_base_of<Pass<P, typename P::SrcT, typename P::DstT>, P>::value
                      || std::is_base_of<PassSeqBase, P>::value,
                      "P is not a Pass");
        static_assert(EmptyTArgs<PS...>::value ||
                      std::is_same<typename P::DstT, typename PassSeq<PS...>::SrcT>::value,
                      "Mismatched types on the seq");
    public:
        using SrcT = typename P::SrcT;
        using DstT = typename std::conditional<EmptyTArgs<PS...>::value,
                                               typename P::DstT,
                                               typename PassSeq<PS...>::DstT>::type;
        static std::unique_ptr<DstT>
        apply_pass(std::unique_ptr<SrcT> s) {
            using NextT = typename std::conditional<EmptyTArgs<PS...>::value,
                                                    NopPass<DstT>,
                                                    PassSeq<PS...>>::type;
            return NextT::apply_pass(P::apply_pass(std::move(s)));
        }
    };
}

#define DECLARE_PASS(NAME, STYPE, DTYPE)                                \
    class NAME : public Pass<NAME, STYPE, DTYPE> {                      \
    friend class Pass<NAME, STYPE, DTYPE>;                              \
    static std::unique_ptr<DTYPE> pass_impl(std::unique_ptr<STYPE> s);  \
    }

#define PASS_IMPL(NAME, ARG)                              \
    std::unique_ptr<NAME::DstT> NAME::pass_impl(std::unique_ptr<NAME::SrcT> ARG)

namespace Morula {
    template<typename S, typename T>
    class CastPass : public Pass<CastPass<S, T>, S, T> {
    public:
        static std::unique_ptr<T> pass_impl(std::unique_ptr<S> s) {
            // dirty hack that may not work for std::unique_ptr<T, Deleter>
            auto raw_ptr = s.get();
            std::unique_ptr<T> ptr(dynamic_cast<T *>(raw_ptr));
            s.release();
            return ptr;
        }
    };

    class UpdateEdges : public Pass<UpdateEdges, PassCtx, PassCtx> {
        friend class Pass<UpdateEdges, PassCtx, PassCtx>;
    protected:
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };

    template<typename T>
    class UpdateVarSource : public Pass<UpdateVarSource<T>, PassCtx, T> {
        friend class Pass<UpdateVarSource<T>, PassCtx, T>;
        static_assert(std::is_base_of<PassCtx, T>::value,
                      "T is not derived from PassCtx");
    protected:
        static std::unique_ptr<T> pass_impl(std::unique_ptr<PassCtx> s) {
            s->var_source.clear();
            for (auto &kv : s->blocks) {
                auto insts = kv.second->insts_mut();
                for (int i = 0; i < insts.size(); i++) {
                    auto dst = insts[i]->get_dst_reg();
                    s->var_source.insert({dst, InstID{kv.first, i}});
                }
            }
            return s;
        }
    };

    class UpdateDeps : public Pass<UpdateDeps, PassCtx, PassCtx> {
        friend class Pass<UpdateDeps, PassCtx, PassCtx>;
    protected:
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };

    DECLARE_PASS(RemoveUnusedInst, PassCtx, PassCtx);
}

#endif /* _MORULA_PASS_HPP_ */
