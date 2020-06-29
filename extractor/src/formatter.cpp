#include "formatter.hpp"

CodeBlock::CodeBlock(): indent(0) {}

CodeBlock::CodeBlock(const std::vector<std::string> &lines): indent(0), lines_(lines) {}

void CodeBlock::append_blk(const CodeBlock &blk, int indent) {
    std::string indent_str = "";
    indent_str.append(indent, ' ');
    for (auto i = 0; i < blk.lines_.size(); i++) {
        lines_.push_back(indent_str + blk.lines_[i]);
    }
}

void CodeBlock::append_line(const std::string &line, int indent) {
    std::string indent_str = "";
    indent_str.append(indent, ' ');
    lines_.push_back(indent_str + line);
}

void CodeBlock::print(std::ostream &os, int indent) const {
    std::string indent_str = "";
    indent_str.append(indent, ' ');

    for (int i = 0; i < lines_.size(); i++) {
        os << indent_str << lines_[i] << std::endl;
    }
}

std::ostream& operator<<(std::ostream &os, const CodeBlock &blk) {
    blk.print(os);
    return os;
}

std::vector<std::string> Line::to_lines() const {
    return {content};
}

void Block::append_line(const std::string &line) {
    lines.push_back(std::move(std::make_unique<Line>(line)));
}

void Block::append_block(std::shared_ptr<Block> block) {
    lines.push_back(std::move(block));
}

void Block::append_code(std::shared_ptr<Code> code) {
    if (code->is_block()) {
        this->append_block(std::dynamic_pointer_cast<Block>(code));
    } else {
        this->append_line(std::dynamic_pointer_cast<Line>(code)->content);
    }
}

void Block::merge_code(std::shared_ptr<Code> code) {
    if (code->is_block()) {
        auto blk_ptr = static_cast<Block *>(code.get());
        for (auto &l : blk_ptr->lines) {
            lines.push_back(std::move(l));
        }
    } else {
        lines.push_back(std::move(code));
    }
}

std::vector<std::string> Block::to_lines() const {
    std::vector<std::string> result;
    static std::string indent_str = "    ";
    for (int i = 0; i < lines.size(); i++) {
        auto ls = lines[i]->to_lines();
        if (lines[i]->is_block()) {
            result.push_back("{");
        }
        for (int j = 0; j < ls.size(); j++) {
            if (lines[i]->is_block()) {
                result.push_back(indent_str + ls[j]);
            } else {
                result.push_back(ls[j]);
            }
        }
        if (lines[i]->is_block()) {
            result.push_back("}");
        }
    }
    return result;
}
