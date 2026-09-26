#pragma once
#include <string>
#include <vector>
#include <unordered_map>

namespace simple_json {

struct JsonValue {
    enum Type { Null, String, Object, Array };
    Type type = Null;
    std::string str;
    std::vector<JsonValue> arr;
    std::unordered_map<std::string, JsonValue> obj;

    bool has(const std::string& key) const;
    const JsonValue& get(const std::string& key) const;
    std::string asString(const std::string& fallback = "") const;
};

JsonValue parse(const std::string& content);

}
