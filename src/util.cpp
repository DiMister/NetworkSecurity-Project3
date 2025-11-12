#include "../include/util.hpp"
#include "../include/io.hpp"

#include <iostream>
#include <stdexcept>

namespace pki487 {

long long read_pki_time(const std::string& path) {
    try {
        auto s = read_text_file(path);
        s = trim(s);
        if (s.empty()) return 0;
        return std::stoll(s);
    } catch(...) {
        return 0; // default if missing or invalid
    }
}

void write_pki_time(const std::string& path, long long t) {
    write_text_file(path, std::to_string(t) + "\n");
}

std::string prompt(const std::string& label, const std::string& def) {
    std::cout << label;
    if (!def.empty()) std::cout << " [" << def << "]";
    std::cout << ": ";
    std::string line;
    std::getline(std::cin, line);
    if (line.empty()) return def;
    return line;
}

long long to_ll(const std::string& s) {
    try { return std::stoll(s); } catch(...) { throw std::runtime_error("Invalid integer: " + s); }
}

} // namespace pki487
