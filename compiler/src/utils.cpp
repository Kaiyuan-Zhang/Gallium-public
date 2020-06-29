#include <cassert>
#include "utils.hpp"
#include <cxxabi.h>


std::unique_ptr<NameFactory> NameFactory::instance_ = nullptr;

NameFactory& NameFactory::get() {
    if (NameFactory::instance_ == nullptr) {
        NameFactory::instance_ = std::make_unique<NameFactory>();
    }
    assert(NameFactory::instance_ != nullptr);
    return *NameFactory::instance_;
}

std::string NameFactory::GetUniqueName(const std::string &base_name) {
  std::lock_guard<std::mutex> lg(name_map_mutex_);
  if (name_map_.find(base_name) == name_map_.end()) {
    name_map_[base_name] = 0;
  }
  uint64_t cnt = name_map_[base_name];
  assert(cnt < 0xffffffffffffffffULL);
  name_map_[base_name] = cnt + 1;
  return base_name + "_" + std::to_string(cnt);
}

std::string NameFactory::base(const std::string &name) {
    auto pos = name.find_last_of('_');
    if (pos != std::string::npos) {
        return name.substr(0, pos);
    } else {
        return name;
    }
}

bool str_begin_with(const std::string &s, const std::string &prefix) {
    return s.find(prefix) == 0;
}
