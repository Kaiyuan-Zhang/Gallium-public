#ifndef _MORULA_FOMATTER_HPP_
#define _MORULA_FOMATTER_HPP_


#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <memory>

class CodeBlock {
public:
    CodeBlock();
    CodeBlock(const std::vector<std::string> &lines);

    void append_blk(const CodeBlock &blk, int indent = 0);
    void append_line(const std::string &line, int indent = 0);

    friend std::ostream& operator<<(std::ostream &os,
                                    const CodeBlock &blk);

protected:
    std::vector<std::string> lines_;
    int indent;

    void print(std::ostream &os, int indent = 0) const;
};

class CodePrinter {
public:
    CodePrinter();
};

std::ostream& operator<<(std::ostream &os, const CodeBlock &blk);

class Line;
class Block;

class Code {
public:
    virtual bool is_line() const { return false; }
    virtual bool is_block() const { return false; }
    virtual std::vector<std::string> to_lines() const = 0;
};

class Line : public Code {
public:
    std::string content;

    Line(const std::string &l) : content(l) {}

    virtual bool is_line() const override { return true; }

    virtual std::vector<std::string> to_lines() const override;
};

class Block : public Code {
public:
    std::vector<std::shared_ptr<Code>> lines;

    Block() {}
    Block(const std::vector<std::string> &ls) {
        for (auto &l : ls) {
            std::unique_ptr<Code> new_line = std::make_unique<Line>(l);
            lines.push_back(std::move(new_line));
        }
    }

    virtual bool is_block() const override { return true; }

    void append_line(const std::string &line);
    void append_block(std::shared_ptr<Block> block);
    void append_code(std::shared_ptr<Code> code);
    void merge_code(std::shared_ptr<Code> code);

    virtual std::vector<std::string> to_lines() const override;
};

#endif /* _MORULA_FOMATTER_HPP_ */
