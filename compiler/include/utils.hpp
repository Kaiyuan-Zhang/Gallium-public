#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>

class NameFactory {
  std::unordered_map<std::string, uint64_t> name_map_;
  std::mutex name_map_mutex_;

  static std::unique_ptr<NameFactory> instance_;
public:
  static NameFactory& get();
  std::string GetUniqueName(const std::string &base_name);
  std::string base(const std::string &name);
  std::string gen(const std::string &base_name) {
    return GetUniqueName(base_name);
  }
  std::string operator()(const std::string &base_name) {
    return GetUniqueName(base_name);
  }
};

bool str_begin_with(const std::string &s, const std::string &prefix);
