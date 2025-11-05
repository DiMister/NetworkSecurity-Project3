#pragma once
#include <string>

namespace pki487 {

// Read or set PKI system time stored as a single integer in a file (e.g., pki_time.txt)
long long read_pki_time(const std::string& path);
void write_pki_time(const std::string& path, long long t);

// Simple prompt helper: prompts with label and returns line; if default provided and user inputs empty, returns default.
std::string prompt(const std::string& label, const std::string& def = "");

// Convert string to long long, throws on error.
long long to_ll(const std::string& s);

// Ensure directory exists (best-effort, noop if exists)
void ensure_dir(const std::string& path);

} // namespace pki487
