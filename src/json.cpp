#include "json.h"
#include <cctype>
#include <stdexcept>

namespace simple_json {

static void skipWS(const std::string& s, size_t& pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos])))
        pos++;
}

static std::string parseString(const std::string& s, size_t& pos) {
    if (pos >= s.size() || s[pos] != '"')
        return {};
    pos++;
    std::string out;
    while (pos < s.size() && s[pos] != '"') {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            switch (s[++pos]) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'n':  out += '\n'; break;
                case 't':  out += '\t'; break;
                case 'r':  out += '\r'; break;
                default:   out += s[pos]; break;
            }
        } else {
            out += s[pos];
        }
        pos++;
    }
    if (pos < s.size())
        pos++;
    return out;
}

static JsonValue parseValue(const std::string& s, size_t& pos);

static JsonValue parseObject(const std::string& s, size_t& pos) {
    JsonValue val;
    val.type = JsonValue::Object;
    pos++;
    while (pos < s.size()) {
        skipWS(s, pos);
        if (pos >= s.size() || s[pos] == '}') {
            if (pos < s.size()) pos++;
            return val;
        }
        if (s[pos] == ',') { pos++; continue; }
        std::string key = parseString(s, pos);
        if (key.empty()) break;
        skipWS(s, pos);
        if (pos >= s.size() || s[pos] != ':') break;
        pos++;
        skipWS(s, pos);
        val.obj[std::move(key)] = parseValue(s, pos);
    }
    if (pos < s.size() && s[pos] == '}') pos++;
    return val;
}

static JsonValue parseArray(const std::string& s, size_t& pos) {
    JsonValue val;
    val.type = JsonValue::Array;
    pos++;
    while (pos < s.size()) {
        skipWS(s, pos);
        if (pos >= s.size() || s[pos] == ']') {
            if (pos < s.size()) pos++;
            return val;
        }
        if (s[pos] == ',') { pos++; continue; }
        val.arr.push_back(parseValue(s, pos));
    }
    if (pos < s.size() && s[pos] == ']') pos++;
    return val;
}

static JsonValue parseValue(const std::string& s, size_t& pos) {
    skipWS(s, pos);
    if (pos >= s.size()) return {};
    if (s[pos] == '{') return parseObject(s, pos);
    if (s[pos] == '[') return parseArray(s, pos);
    if (s[pos] == '"') {
        JsonValue v;
        v.type = JsonValue::String;
        v.str = parseString(s, pos);
        return v;
    }
    return {};
}

JsonValue parse(const std::string& content) {
    size_t pos = 0;
    return parseValue(content, pos);
}

bool JsonValue::has(const std::string& key) const {
    return type == Object && obj.count(key) > 0;
}

const JsonValue& JsonValue::get(const std::string& key) const {
    static JsonValue nullVal;
    if (type != Object) return nullVal;
    auto it = obj.find(key);
    if (it == obj.end()) return nullVal;
    return it->second;
}

std::string JsonValue::asString(const std::string& fallback) const {
    return type == String ? str : fallback;
}

}
