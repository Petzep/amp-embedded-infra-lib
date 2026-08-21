#include "services/util/Sha256MbedTls.hpp"
#include "infra/util/ReallyAssert.hpp"
#include "psa/crypto.h"
#include <cassert>

#if MBEDTLS_VERSION_MAJOR < 3
#define mbedtls_sha256 mbedtls_sha256_ret
#endif

namespace services
{
    std::array<uint8_t, PSA_HASH_LENGTH(PSA_ALG_SHA_256)> Sha256MbedTls::Calculate(infra::ConstByteRange input) const
    {
        std::array<uint8_t, PSA_HASH_LENGTH(PSA_ALG_SHA_256)> output;

        really_assert(psa_hash_compute(PSA_ALG_SHA_256, reinterpret_cast<const uint8_t*>(input.begin()), input.size(), output.data(), output.size(), nullptr) == PSA_SUCCESS);

        return output;
    }
}
