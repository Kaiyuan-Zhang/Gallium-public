#pragma once

#include <cassert>
#include <algorithm>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <variant>
#include <utility>
#include <unordered_set>
#include <unordered_map>


// EdgeStoreIf: just for reference, not used
template <typename E>
class EdgeStoreIf {
public:
    void set_edge(size_t src, size_t dst, const E& e);
    void set_edge(size_t src, size_t dst, E&& e);
    std::optional<const E*> get_edge(size_t src, size_t dst) const;
    std::optional<E*> get_edge(size_t src, size_t dst);
    bool have_edge(size_t src, size_t dst) const;
};

template <typename E>
class AdjacencyList {
public:
    AdjacencyList(int n_vertex)
        : n_vertex_(n_vertex),
          edge_lists_(n_vertex) {
    }

    void set_edge(size_t src, size_t dst, const E& e) {
        auto opt = get_edge(src, dst);
        if (!opt.has_value()) {
            edge_lists_[src].emplace_back(dst, e);
        } else {
            **opt = e;
        }
    }

    void set_edge(size_t src, size_t dst, E&& e) {
        auto opt = get_edge(src, dst);
        if (!opt.has_value()) {
            edge_lists_[src].emplace_back(dst, std::move(e));
        } else {
            **opt = std::move(e);
        }
    }

    std::optional<const E*> get_edge(size_t src, size_t dst) const {
        for (auto &e : edge_lists_[src]) {
            if (e.dst == dst) {
                return &e.value;
            }
        }
        return std::nullopt;
    }

    std::optional<E*> get_edge(size_t src, size_t dst) {
        for (auto &e : edge_lists_[src]) {
            if (e.dst == dst) {
                return &e.value;
            }
        }
        return std::nullopt;
    }

    bool have_edge(size_t src, size_t dst) const {
        for (auto &e : edge_lists_[src]) {
            if (e.dst == dst) {
                return true;
            }
        }
        return false;
    }

    class OutEdgeIter {
    public:
        OutEdgeIter(const AdjacencyList<E> *l, size_t src) : adj_list_(l), src_(src) {}
        OutEdgeIter(const AdjacencyList<E> *l, size_t src, size_t curr)
            : adj_list_(l), src_(src), curr_idx_(curr) {}
        OutEdgeIter end() {
            return OutEdgeIter(adj_list_, src_, adj_list_->edge_lists_[src_].size());
        }

        const E& value() {
            auto dst  = adj_list_->edge_lists_[src_][curr_idx_].dst;
            return *adj_list_->get_edge(src_, dst).value();
        }

        OutEdgeIter operator++() {
            if (curr_idx_ < adj_list_->edge_lists_[src_].size()) {
                curr_idx_++;
            }
            return OutEdgeIter(adj_list_, src_, curr_idx_);
        }

        OutEdgeIter operator++(int) {
            auto old = OutEdgeIter(adj_list_, src_, curr_idx_);
            if (curr_idx_ < adj_list_->edge_lists_[src_].size()) {
                curr_idx_++;
            }
            return old;
        }

        bool operator==(const OutEdgeIter &o) {
            return curr_idx_ == o.curr_idx_ && src_ == o.src_;
        }

        bool operator!=(const OutEdgeIter &o) {
            return !((*this) == o);
        }

        size_t operator*() {
            return adj_list_->edge_lists_[src_][curr_idx_].dst;
        }
    protected:
        size_t src_;
        size_t curr_idx_;
        const AdjacencyList<E> *adj_list_;
    };

    OutEdgeIter out_edge_begin(size_t src) const {
        return OutEdgeIter(this, src, 0);
    }

    OutEdgeIter out_edge_end(size_t src) const {
        return OutEdgeIter(this, src, edge_lists_[src].size());
    }
protected:
    class EdgeListEntry {
    public:
        size_t dst;
        E      value;
        EdgeListEntry(size_t d, E v) : dst(d), value(std::move(v)) {}
    };

    size_t n_vertex_;
    std::vector<std::vector<EdgeListEntry>> edge_lists_;
};

template <typename E>
class AdjacencyMatrix {
public:
    AdjacencyMatrix(int n_vertex)
        : n_vertex_(n_vertex),
          edge_val_(n_vertex * n_vertex, std::nullopt) {
    }

    void set_edge(size_t src, size_t dst, const E& e) {
        auto idx = edge_idx(src, dst);
        edge_val_[idx] = e;
    }

    void set_edge(size_t src, size_t dst, E&& e) {
        auto idx = edge_idx(src, dst);
        edge_val_[idx] = std::move(e);
    }

    std::optional<const E*> get_edge(size_t src, size_t dst) const {
        auto idx = edge_idx(src, dst);
        if (edge_val_[idx].has_value()) {
            return &edge_val_[idx].value();
        } else {
            return std::nullopt;
        }
    }

    std::optional<E*> get_edge(size_t src, size_t dst) {
        auto idx = edge_idx(src, dst);
        if (edge_val_[idx].has_value()) {
            return &edge_val_[idx].value();
        } else {
            return std::nullopt;
        }
    }

    bool have_edge(size_t src, size_t dst) const {
        auto idx = edge_idx(src, dst);
        return edge_val_[idx].has_value();
    }

    class OutEdgeIter {
    public:
        OutEdgeIter(const AdjacencyMatrix<E> *m, size_t src) : adj_mat_(m), src_(src) {}
        OutEdgeIter(const AdjacencyMatrix<E> *m, size_t src, size_t curr)
            : adj_mat_(m), src_(src), curr_vertex_(curr) {}
        OutEdgeIter end() {
            return OutEdgeIter(adj_mat_, src_, adj_mat_->n_vertex_);
        }

        const E& value() {
            return *adj_mat_->get_edge(src_, curr_vertex_).value();
        }

        OutEdgeIter operator++() {
            do {
                curr_vertex_++;
            } while (curr_vertex_ < adj_mat_->n_vertex_ &&
                     !adj_mat_->have_edge(src_, curr_vertex_));
            return OutEdgeIter(adj_mat_, src_, curr_vertex_);
        }

        OutEdgeIter operator++(int) {
            auto old = OutEdgeIter(adj_mat_, src_, curr_vertex_);
            do {
                curr_vertex_++;
            } while (curr_vertex_ < adj_mat_->n_vertex_ &&
                     !adj_mat_->have_edge(src_, curr_vertex_));
            return old;
        }

        bool operator==(const OutEdgeIter &o) {
            return curr_vertex_ == o.curr_vertex_ && src_ == o.src_;
        }

        bool operator!=(const OutEdgeIter &o) {
            return !((*this) == o);
        }

        size_t operator*() {
            return curr_vertex_;
        }
    protected:
        size_t src_;
        size_t curr_vertex_;
        const AdjacencyMatrix<E> *adj_mat_;
    };

    OutEdgeIter out_edge_begin(size_t src) const {
        size_t dst = 0;
        while (dst < n_vertex_ && !have_edge(src, dst)) {
            dst++;
        }
        return OutEdgeIter(this, src, dst);
    }

    OutEdgeIter out_edge_end(size_t src) const {
        return OutEdgeIter(this, src, n_vertex_);
    }
protected:
    size_t n_vertex_;
    std::vector<std::optional<E>> edge_val_;

    size_t edge_idx(size_t src, size_t dst) const {
        return src * n_vertex_ + dst;
    }
};

template <typename V, typename E, typename EdgeContainerT=AdjacencyMatrix<E>>
class Graph {
public:
    Graph(std::vector<V> vertices, EdgeContainerT edges)
        : vertices_(std::move(vertices)),
          edges_(std::move(edges)) {}

    size_t n_vertex() const {
        return vertices_.size();
    }

    V& vertex_ref(size_t vid) {
        assert(vid < vertices_.size());
        return vertices_[vid];
    }

    const V& vertex_ref(size_t vid) const {
        assert(vid < vertices_.size());
        return vertices_[vid];
    }

    EdgeContainerT& edges() { return edges_; }
    const EdgeContainerT& edges() const { return edges_; }

    template <typename VV, typename EE, typename EC>
    friend class Graph;

    bool IsAcyclic() const {
        std::vector<bool> visited(vertices_.size(), false);
        std::vector<bool> visiting(vertices_.size(), false);
        for (size_t i = 0; i < vertices_.size(); i++) {
            if (HasCycleFrom(visited, visiting, i)) {
                return false;
            }
        }
        return true;
    }

    bool HasCycleFrom(size_t v) {
        std::vector<bool> visited(vertices_.size(), false);
        std::vector<bool> visiting(vertices_.size(), false);
        return HasCycleFrom(visited, visiting, v);
    }

    std::vector<size_t> TopologicalSort() const {
        assert(IsAcyclic());
        std::vector<bool> visited(vertices_.size(), false);
        std::vector<size_t> order;
        for (size_t i = 0; i < vertices_.size(); i++) {
            dfs(visited, order, i);
        }
        return order;
    }

    std::vector<std::vector<size_t>> StronglyConnectedComponents() const {
        std::vector<std::vector<size_t>> scc_list;

        // Step 1 : DFS
        std::vector<size_t> dfs_order;
        std::vector<bool> dfs_visited(vertices_.size(), false);
        for (size_t i = 0; i < vertices_.size(); i++) {
            dfs(dfs_visited, dfs_order, i);
        }

        // Step 2 : reverse the graph
        std::vector<std::monostate> rev_verteices(vertices_.size(), std::monostate());
        AdjacencyList<std::monostate> rev_edges(vertices_.size());
        for (size_t i = 0; i < vertices_.size(); i++) {
            for (auto iter = edges_.out_edge_begin(i); iter != iter.end(); iter++) {
                rev_edges.set_edge(*iter, i, std::monostate());
            }
        }
        Graph<
            std::monostate,
            std::monostate,
            AdjacencyList<std::monostate>
        > rev_graph(std::move(rev_verteices), std::move(rev_edges));
        std::transform(
            dfs_visited.begin(),
            dfs_visited.end(),
            dfs_visited.begin(),
            [] (bool b) -> bool { return false; }
        );

        // Step 3 : do dfs on reverse graph
        for (int i = dfs_order.size() - 1; i >= 0; i--) {
            std::vector<size_t> scc;
            rev_graph.dfs(dfs_visited, scc, dfs_order[i]);
            if (scc.size() > 0) {
                scc_list.emplace_back(std::move(scc));
            }
        }
        return scc_list;
    }

    bool HasCycleFrom(std::vector<bool> &visited,
                      std::vector<bool> &visiting,
                      size_t curr) const {
        if (visited[curr]) {
            return false;
        }
        if (visiting[curr]) {
            return true;
        }
        visited[curr] = true;
        visiting[curr] = true;
        for (auto iter = edges_.out_edge_begin(curr); iter != iter.end(); iter++) {
            auto neighbor = *iter;
            auto found_cycle = HasCycleFrom(visited, visiting, neighbor);
            if (found_cycle) { return true; }
        }
        visiting[curr] = false;
        return false;
    }
protected:
    std::vector<V> vertices_;
    EdgeContainerT edges_;

    void dfs(std::vector<bool> &visited,
             std::vector<size_t> &result,
             size_t curr) const {
        if (visited[curr]) {
            return;
        }
        visited[curr] = true;
        for (auto iter = edges_.out_edge_begin(curr); iter != iter.end(); iter++) {
            dfs(visited, result, *iter);
        }
        result.emplace_back(curr);
    }
};

