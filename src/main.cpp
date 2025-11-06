#include "crypto.hpp"
#include "io.hpp"
#include "util.hpp"
#include "cert487.hpp"
#include "crl487.hpp"
#include "CBCHash.hpp"

#include <iostream>
#include <stdexcept>
#include <vector>
#include <filesystem>

using namespace pki487;

const std::string PKI_TIME_FILE = "pki_time.txt";

static void cmd_keygen(const std::vector<std::string>& args) {
    std::string out = "keys/ca";
    int bits = 2048;
    for (size_t i=0;i<args.size();++i) {
        if (args[i] == "--out" && i+1<args.size()) out = args[i+1], ++i;
        else if (args[i] == "--bits" && i+1<args.size()) bits = std::stoi(args[i+1]), ++i;
    }
    ensure_dir("keys");
    auto kp = generate_rsa_key(bits);
    save_private_key_pem(kp, out + "_priv.pem");
    save_public_key_pem(kp, out + "_pub.pem");
    std::cout << "Generated keypair: " << out << "_[priv|pub].pem\n";
}

static void cmd_issue_cert(const std::vector<std::string>& args) {
    std::string issuer_priv_path;
    std::string subject_pub_path;
    std::string out_path = "certs/cert.cert487";
    long long not_before = 0, not_after = 0;
    long long serial = 1;
    int trust = 0;
    std::string issuer, subject;

    for (size_t i=0;i<args.size();++i) {
        if (args[i]=="--issuer-priv" && i+1<args.size()) issuer_priv_path=args[i+1], ++i;
        else if (args[i]=="--subject-pub" && i+1<args.size()) subject_pub_path=args[i+1], ++i;
        else if (args[i]=="--out" && i+1<args.size()) out_path=args[i+1], ++i;
        else if (args[i]=="--serial" && i+1<args.size()) serial=std::stoll(args[i+1]), ++i;
        else if (args[i]=="--issuer" && i+1<args.size()) issuer=args[i+1], ++i;
        else if (args[i]=="--subject" && i+1<args.size()) subject=args[i+1], ++i;
        else if (args[i]=="--not-before" && i+1<args.size()) not_before=std::stoll(args[i+1]), ++i;
        else if (args[i]=="--not-after" && i+1<args.size()) not_after=std::stoll(args[i+1]), ++i;
        else if (args[i]=="--trust" && i+1<args.size()) trust=std::stoi(args[i+1]), ++i;
    }

    if (issuer_priv_path.empty()) issuer_priv_path = prompt("Issuer private key (PEM)");
    if (subject_pub_path.empty()) subject_pub_path = prompt("Subject public key (PEM)");
    if (issuer.empty()) issuer = prompt("Issuer name");
    if (subject.empty()) subject = prompt("Subject name");
    if (serial==1) serial = std::stoll(prompt("Serial", "1"));
    if (not_before==0) not_before = std::stoll(prompt("Not-Before (int)", "0"));
    if (not_after==0) not_after = std::stoll(prompt("Not-After (int)", "100000"));
    if (trust==0) trust = std::stoi(prompt("Trust level (0..7)", "0"));

    if (trust < 0 || trust > 7) throw std::runtime_error("Trust level must be 0..7");

    auto issuer_priv = load_private_key_pem(issuer_priv_path);
    std::string subject_pub_pem = read_text_file(subject_pub_path);

    Cert487 cert;
    cert.version = 1;
    cert.signature_algo = "S-DES-CBC-8";
    cert.serial = serial;
    cert.issuer = issuer;
    cert.subject = subject;
    cert.not_before = not_before;
    cert.not_after = not_after;
    cert.trust_level = trust;
    cert.subject_pubkey_pem = subject_pub_pem;

    std::string tbs = cert.serialize_tbs();
    // Compute 8-bit CBC hash over TBS using S-DES CBC
    CBCHash hasher; // default key and IV
    std::vector<std::bitset<8>> blocks;
    blocks.reserve(tbs.size());
    for (unsigned char c : tbs) blocks.emplace_back(std::bitset<8>(c));
    auto h = hasher.hash(blocks);
    std::vector<unsigned char> sig = { static_cast<unsigned char>(h.to_ulong()) };
    cert.signature_b64 = base64_encode(sig);

    ensure_dir("certs");
    write_text_file(out_path, cert.serialize_full());
    std::cout << "Wrote certificate: " << out_path << "\n";
}

static void cmd_verify_cert(const std::vector<std::string>& args) {
    std::string cert_path;
    std::string issuer_pub_path;
    std::string time_path = PKI_TIME_FILE;
    int min_trust = -1;
    for (size_t i=0;i<args.size();++i) {
        if (args[i]=="--cert" && i+1<args.size()) cert_path=args[i+1], ++i;
        else if (args[i]=="--issuer-pub" && i+1<args.size()) issuer_pub_path=args[i+1], ++i;
        else if (args[i]=="--pki-time" && i+1<args.size()) time_path=args[i+1], ++i;
        else if (args[i]=="--min-tl" && i+1<args.size()) min_trust=std::stoi(args[i+1]), ++i;
    }
    if (cert_path.empty()) cert_path = prompt("Certificate path");
    if (issuer_pub_path.empty()) issuer_pub_path = prompt("Issuer public key (PEM)");

    auto cert_txt = read_text_file(cert_path);
    auto cert = Cert487::parse(cert_txt);
    auto pub = load_public_key_pem(issuer_pub_path);

    std::string tbs = cert.serialize_tbs();
    auto sig = base64_decode(cert.signature_b64);

    bool sig_ok = false;
    if (cert.signature_algo == "S-DES-CBC-8") {
        CBCHash hasher;
        std::vector<std::bitset<8>> blocks;
        blocks.reserve(tbs.size());
        for (unsigned char c : tbs) blocks.emplace_back(std::bitset<8>(c));
        auto h = hasher.hash(blocks);
        std::vector<unsigned char> expected = { static_cast<unsigned char>(h.to_ulong()) };
        sig_ok = (sig == expected);
    }
    long long now = read_pki_time(time_path);
    bool time_ok = cert_is_time_valid(cert, now);
    bool tl_ok = (min_trust < 0) || (cert.trust_level >= min_trust);

    std::cout << "Signature: " << (sig_ok?"OK":"FAIL") << "\n";
    std::cout << "Validity (now=" << now << "): " << (time_ok?"OK":"EXPIRED/NOT-YET-VALID") << "\n";
    if (min_trust>=0) std::cout << "Trust-Level >= " << min_trust << ": " << (tl_ok?"OK":"LOW") << "\n";

    if (sig_ok && time_ok && tl_ok) {
        std::cout << "CERT VERIFIED\n";
    } else {
        std::cout << "CERT REJECTED\n";
    }
}

static void cmd_gen_crl(const std::vector<std::string>& args) {
    std::string issuer_priv_path;
    std::string out_path = "crls/crl.crl487";
    std::string issuer;
    long long this_update=0, next_update=0;
    std::vector<long long> revoked;

    for (size_t i=0;i<args.size();++i) {
        if (args[i]=="--issuer-priv" && i+1<args.size()) issuer_priv_path=args[i+1], ++i;
        else if (args[i]=="--out" && i+1<args.size()) out_path=args[i+1], ++i;
        else if (args[i]=="--issuer" && i+1<args.size()) issuer=args[i+1], ++i;
        else if (args[i]=="--this-update" && i+1<args.size()) this_update=std::stoll(args[i+1]), ++i;
        else if (args[i]=="--next-update" && i+1<args.size()) next_update=std::stoll(args[i+1]), ++i;
        else if (args[i]=="--revoked" && i+1<args.size()) {
            for (auto &s : split(args[i+1], ',', false)) {
                auto t = trim(s);
                if (!t.empty()) revoked.push_back(std::stoll(t));
            }
            ++i;
        }
    }

    if (issuer_priv_path.empty()) issuer_priv_path = prompt("Issuer private key (PEM)");
    if (issuer.empty()) issuer = prompt("Issuer name");
    if (this_update==0) this_update = std::stoll(prompt("This-Update (int)", "0"));
    if (next_update==0) next_update = std::stoll(prompt("Next-Update (int)", "100000"));
    if (revoked.empty()) {
        auto s = prompt("Revoked serials (comma-separated)");
        for (auto &x : split(s, ',', false)) {
            auto t = trim(x); if (!t.empty()) revoked.push_back(std::stoll(t));
        }
    }

    auto issuer_priv = load_private_key_pem(issuer_priv_path);

    Crl487 crl;
    crl.version = 1;
    crl.signature_algo = "S-DES-CBC-8";
    crl.issuer = issuer;
    crl.this_update = this_update;
    crl.next_update = next_update;
    crl.revoked_serials = revoked;

    std::string tbs = crl.serialize_tbs();
    CBCHash hasher;
    std::vector<std::bitset<8>> blocks;
    blocks.reserve(tbs.size());
    for (unsigned char c : tbs) blocks.emplace_back(std::bitset<8>(c));
    auto h = hasher.hash(blocks);
    std::vector<unsigned char> sig = { static_cast<unsigned char>(h.to_ulong()) };
    crl.signature_b64 = base64_encode(sig);

    ensure_dir("crls");
    write_text_file(out_path, crl.serialize_full());
    std::cout << "Wrote CRL: " << out_path << "\n";
}

static void cmd_verify_crl(const std::vector<std::string>& args) {
    std::string crl_path;
    std::string issuer_pub_path;
    std::string time_path = PKI_TIME_FILE;
    for (size_t i=0;i<args.size();++i) {
        if (args[i]=="--crl" && i+1<args.size()) crl_path=args[i+1], ++i;
        else if (args[i]=="--issuer-pub" && i+1<args.size()) issuer_pub_path=args[i+1], ++i;
        else if (args[i]=="--pki-time" && i+1<args.size()) time_path=args[i+1], ++i;
    }
    if (crl_path.empty()) crl_path = prompt("CRL path");
    if (issuer_pub_path.empty()) issuer_pub_path = prompt("Issuer public key (PEM)");

    auto crl_txt = read_text_file(crl_path);
    auto crl = Crl487::parse(crl_txt);
    auto pub = load_public_key_pem(issuer_pub_path);

    std::string tbs = crl.serialize_tbs();
    auto sig = base64_decode(crl.signature_b64);

    bool sig_ok = false;
    if (crl.signature_algo == "S-DES-CBC-8") {
        CBCHash hasher;
        std::vector<std::bitset<8>> blocks;
        blocks.reserve(tbs.size());
        for (unsigned char c : tbs) blocks.emplace_back(std::bitset<8>(c));
        auto h = hasher.hash(blocks);
        std::vector<unsigned char> expected = { static_cast<unsigned char>(h.to_ulong()) };
        sig_ok = (sig == expected);
    }
    long long now = read_pki_time(time_path);
    bool time_ok = crl_time_valid(crl, now);

    std::cout << "Signature: " << (sig_ok?"OK":"FAIL") << "\n";
    std::cout << "Time window (now=" << now << "): " << (time_ok?"OK":"OUT-OF-DATE") << "\n";
    if (sig_ok && time_ok) std::cout << "CRL VERIFIED\n"; else std::cout << "CRL REJECTED\n";
}

static void cmd_is_revoked(const std::vector<std::string>& args) {
    std::string crl_path;
    long long serial = -1;
    for (size_t i=0;i<args.size();++i) {
        if (args[i]=="--crl" && i+1<args.size()) crl_path=args[i+1], ++i;
        else if (args[i]=="--serial" && i+1<args.size()) serial=std::stoll(args[i+1]), ++i;
    }
    if (crl_path.empty()) crl_path = prompt("CRL path");
    if (serial<0) serial = std::stoll(prompt("Serial"));
    auto crl_txt = read_text_file(crl_path);
    auto crl = Crl487::parse(crl_txt);
    std::cout << (crl_is_revoked(crl, serial) ? "REVOKED" : "NOT REVOKED") << "\n";
}

static void cmd_pki_time(const std::vector<std::string>& args) {
    std::string file = PKI_TIME_FILE;
    if (!args.empty() && args[0] == "show") {
        std::cout << read_pki_time(file) << "\n";
    } else if (!args.empty() && args[0] == "set") {
        if (args.size() < 2) throw std::runtime_error("Usage: pki-time set <int>");
        write_pki_time(file, std::stoll(args[1]));
        std::cout << "OK\n";
    } else {
        std::cout << "Usage: pki-time show | pki-time set <int>\n";
    }
}

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv+1, argv+argc);
        if (args.empty()) {
            std::cout << "pki487 <command> [options]\n";
            std::cout << "Commands:\n";
            std::cout << "  keygen [--out pathPrefix] [--bits 2048]\n";
            std::cout << "  issue-cert --issuer-priv file --subject-pub file [--out file] [--issuer name] [--subject name] [--serial n] [--not-before t] [--not-after t] [--trust 0..7]\n";
            std::cout << "  verify-cert --cert file --issuer-pub file [--pki-time file] [--min-tl n]\n";
            std::cout << "  gen-crl --issuer-priv file [--issuer name] [--this-update t] [--next-update t] [--revoked a,b,c] [--out file]\n";
            std::cout << "  verify-crl --crl file --issuer-pub file [--pki-time file]\n";
            std::cout << "  is-revoked --crl file --serial n\n";
            std::cout << "  pki-time show|set <int>\n";
            return 0;
        }
        std::string cmd = args[0];
        std::vector<std::string> rest(args.begin()+1, args.end());
        if (cmd == "keygen") cmd_keygen(rest);
        else if (cmd == "issue-cert") cmd_issue_cert(rest);
        else if (cmd == "verify-cert") cmd_verify_cert(rest);
        else if (cmd == "gen-crl") cmd_gen_crl(rest);
        else if (cmd == "verify-crl") cmd_verify_crl(rest);
        else if (cmd == "is-revoked") cmd_is_revoked(rest);
        else if (cmd == "pki-time") cmd_pki_time(rest);
        else {
            std::cerr << "Unknown command: " << cmd << "\n";
            return 2;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
