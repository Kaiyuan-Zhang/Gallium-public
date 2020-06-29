#include "graph.hpp"
#include "gtest/gtest.h"

class AdjMatrixTest : public ::testing::Test {
protected:
    AdjMatrixTest() : edges_(100) {}
    void SetUp() override {
    }

    AdjacencyMatrix<int> edges_;
};

TEST_F(AdjMatrixTest, edge_set_get) {
    auto src = 10, dst = 20;
    edges_.set_edge(src, dst, 0);
    ASSERT_EQ(edges_.have_edge(src, dst), true);
    auto have_edge = edges_.get_edge(src, dst).has_value();
    ASSERT_EQ(have_edge, true);
    ASSERT_EQ(*edges_.get_edge(src, dst).value(), 0);
}

TEST_F(AdjMatrixTest, out_edge_iter) {
    std::vector<size_t> out_edges{1, 2, 3, 5, 8, 13, 21, 34};
    size_t src = 10;

    for (auto d : out_edges) {
        edges_.set_edge(src, d, (int)d);
    }

    int i = 0;
    for (auto iter = edges_.out_edge_begin(src); iter != edges_.out_edge_end(src); iter++) {
        ASSERT_LE(i, out_edges.size());
        ASSERT_EQ(*iter, out_edges[i]);
        ASSERT_EQ(iter.value(), out_edges[i]);
        i++;
    }
}


class AdjListTest : public ::testing::Test {
protected:
    AdjListTest() : edges_(100) {}
    void SetUp() override {
    }

    AdjacencyList<int> edges_;
};

TEST_F(AdjListTest, edge_set_get) {
    auto src = 10, dst = 20;
    edges_.set_edge(src, dst, 0);
    ASSERT_EQ(edges_.have_edge(src, dst), true);
    auto have_edge = edges_.get_edge(src, dst).has_value();
    ASSERT_EQ(have_edge, true);
    ASSERT_EQ(*edges_.get_edge(src, dst).value(), 0);
}

TEST_F(AdjListTest, out_edge_iter) {
    std::vector<size_t> out_edges{1, 2, 3, 5, 8, 13, 21, 34};
    size_t src = 10;

    for (auto d : out_edges) {
        edges_.set_edge(src, d, (int)d);
    }

    int i = 0;
    for (auto iter = edges_.out_edge_begin(src); iter != edges_.out_edge_end(src); iter++) {
        ASSERT_LE(i, out_edges.size());
        ASSERT_EQ(*iter, out_edges[i]);
        ASSERT_EQ(iter.value(), out_edges[i]);
        i++;
    }
}

class GraphTest : public ::testing::Test {
protected:
    GraphTest() : graph_(nullptr) {}
    void SetUp() override {
    }

    std::unique_ptr<Graph<int, int, AdjacencyMatrix<int>>> graph_;
};

TEST_F(GraphTest, scc_test) {
    AdjacencyMatrix<int> edges(5);
    edges.set_edge(0, 2, 0);
    edges.set_edge(2, 1, 0);
    edges.set_edge(1, 0, 0);
    edges.set_edge(0, 3, 0);
    edges.set_edge(3, 4, 0);

    std::vector<int> vertices(5, 0);

    graph_ = std::make_unique<Graph<int, int>>(std::move(vertices), std::move(edges));

    auto scc_list = graph_->StronglyConnectedComponents();

    std::unordered_set<size_t> scc_1 = {0, 1, 2};
    std::unordered_set<size_t> scc_2 = {3};
    std::unordered_set<size_t> scc_3 = {4};

    ASSERT_EQ(scc_list.size(), 3);

    std::vector<bool> found(3, false);
    for (auto &scc : scc_list) {
        std::unordered_set<size_t> scc_set(scc.begin(), scc.end());
        if (scc_set == scc_1) {
            found[0] = true;
        } else if (scc_set == scc_2) {
            found[1] = true;
        } else if (scc_set == scc_3) {
            found[2] = true;
        }
    }

    for (auto b : found) {
        ASSERT_EQ(b, true);
    }
    graph_ = nullptr;
}

TEST_F(GraphTest, topo_sort_test) {
    AdjacencyMatrix<int> edges(5);
    edges.set_edge(0, 2, 0);
    edges.set_edge(2, 1, 0);
    edges.set_edge(0, 3, 0);
    edges.set_edge(3, 4, 0);

    std::vector<int> vertices(5, 0);

    graph_ = std::make_unique<Graph<int, int>>(std::move(vertices), std::move(edges));

    auto topo_order = graph_->TopologicalSort();
    std::vector<size_t> correct_topo_order = {1, 2, 4, 3, 0};
    ASSERT_EQ(topo_order.size(), graph_->n_vertex());
    for (int i = 0; i < topo_order.size(); i++) {
        ASSERT_EQ(topo_order[i], correct_topo_order[i]);
    }
    graph_ = nullptr;
}
