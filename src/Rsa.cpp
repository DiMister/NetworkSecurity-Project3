#include <cstdint>
#include <iostream>
#include "../include/Rsa.hpp"
#include "../include/MathUtils.hpp"

namespace pki487 {
Rsa::Rsa() {
    auto [p,q] = PickPrimes();
    auto [n,e,d] = GenerateKeypair(p, q);
    publicKey = {n, e};
    privateKey = {n, d};
}

std::pair<uint32_t, uint32_t> Rsa::PickPrimes() {
    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");

    if (primes.size() < 2) {
        std::cerr << "Not enough primes in primes.csv\n";
        return {};
    }

    // Generate RSA keypair for client (small primes from CSV)
    uint32_t p_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    uint32_t q_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    while (q_rsa == p_rsa) q_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));

    printf("Client: generated RSA primes p=%u q=%u\n", p_rsa, q_rsa);
    return {p_rsa, q_rsa};
}


std::tuple<uint32_t, uint32_t, uint32_t> Rsa::GenerateKeypair(uint32_t p_rsa, uint32_t q_rsa) {
    MathUtils mathUtils;
    unsigned long long n_tmp = static_cast<unsigned long long>(p_rsa) * static_cast<unsigned long long>(q_rsa);
    uint32_t n = static_cast<uint32_t>(n_tmp);
    uint32_t totient = (p_rsa - 1u) * (q_rsa - 1u);

    printf("Client: computed RSA modulus n=%u totient=%u\n", n, totient);

    uint32_t e = mathUtils.findPublicExponent(totient);
    if (e == 0u) {
        e = 65537u;
        if (mathUtils.findGCD(e, totient) != 1u) {
            std::cerr << "Failed to find suitable public exponent\n";
            return {};
        }
    }

    printf("Client: selected public exponent e=%u\n", e);

    uint32_t d = mathUtils.extendedEuclidean(e, totient);
    printf("Client: computed private exponent d=%u\n", d);

    return {n, e, d};
}
}