#include <cstdint>
#include <utility>


namespace pki487 {
    struct keypair{
        uint32_t n;
        uint32_t exponent;
    };

    class Rsa {
    public:
        keypair publicKey;
        keypair privateKey;

        Rsa(); 
        std::pair<uint32_t, uint32_t> PickPrimes();
        std::tuple<uint32_t, uint32_t, uint32_t> GenerateKeypair(uint32_t p_rsa, uint32_t q_rsa);
    };
}