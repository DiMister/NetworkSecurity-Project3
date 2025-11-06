#include <cstdint>
#include <utility>


namespace pki487 {
    class Rsa {
    public:
        Rsa(); 
        std::pair<uint32_t, uint32_t> PickPrimes();
        std::tuple<uint32_t, uint32_t, uint32_t> GenerateKeypair(uint32_t p_rsa, uint32_t q_rsa);
    };
}