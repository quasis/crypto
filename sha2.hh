/*
 * NAME
 *
 *     sha2 - secure hash algorithm 2
 *
 * SYNOPSIS
 *
 *     auto digest = SHA2<256,224>().update(...).digest();
 *     auto digest = SHA2<256,256>().update(...).digest();
 *     auto digest = SHA2<512,224>().update(...).digest();
 *     auto digest = SHA2<512,256>().update(...).digest();
 *     auto digest = SHA2<512,384>().update(...).digest();
 *     auto digest = SHA2<512,512>().update(...).digest();
 *
 * DESCRIPTION
 *
 *     SHA-2 (Secure Hash Algorithm 2) is a family of cryptographic hash
 *     functions designed to provide stronger security and resistance to
 *     attacks compared to its predecessor, SHA-1. SHA-2 family includes
 *     several variants, each producing different output sizes: SHA-224,
 *     SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.
 *
 * EXAMPLES
 *
 *     #include <crypto/sha2.h>
 *     using namespace crypto;
 *
 *     auto
 *     hash(const auto &trivially_copyable_objects) {
 *
 *         auto hasher = SHA2<512, 256>();
 *
 *         for (const auto &object: trivially_copyable_objects) {
 *             hasher.update(object);
 *         }
 *
 *         return sha2<256>(hasher.update("secret").digest());
 *     }
 *
 * COPYRIGHT
 *
 *     Copyright 2022 Quasis - The MIT License
 */

namespace crypto {

    template<unsigned state_bits, unsigned output_bits = state_bits>
    class SHA2 {

        using uint8_type   = __UINT8_TYPE__;
        using uint16_type  = __UINT16_TYPE__;
        using uint32_type  = __UINT32_TYPE__;
        using uint64_type  = __UINT64_TYPE__;
        using uint128_type = unsigned __int128;

        template<unsigned bits> struct uint {
            using type = void;
        };

        template<> struct uint<32> {
            using type = uint32_type;
        };

        template<> struct uint<64> {
            using type = uint64_type;
        };

        template<> struct uint<128> {
            using type = uint128_type;
        };

        template<typename value_type, auto count>
        struct buffer {

            value_type              m_data[count];

            using size_type       = decltype(sizeof(void*));
            using pointer         = uint8_type*;
            using const_pointer   = const uint8_type*;
            using reference       = value_type&;
            using const_reference = const value_type&;

            constexpr size_type
            size() const noexcept {
                return count;
            }

            constexpr const_pointer
            data() const noexcept {
                return reinterpret_cast<const_pointer>(m_data);
            }

            constexpr pointer
            data() noexcept {
                return reinterpret_cast<pointer>(m_data);
            }

            constexpr reference
            operator[](size_type index) noexcept {
                return m_data[index];
            }

            constexpr const_reference
            operator[](size_type index) const noexcept {
                return m_data[index];
            }
        };

    public:

        using size_type   = typename uint<state_bits / 4>::type;
        using word_type   = typename uint<state_bits / 8>::type;
        using state_type  = buffer<word_type, 8>;
        using block_type  = buffer<word_type, 16>;
        using round_type  = buffer<word_type, 48 + state_bits / 16>;
        using output_type = buffer<uint8_type, output_bits / 8>;

        constexpr
        SHA2() noexcept;

        constexpr
       ~SHA2() noexcept {
            __builtin_memset(m_block.data(), 0, sizeof(block_type));
        }

        constexpr size_type
        size() const noexcept {
            return m_count;
        }

        constexpr SHA2&
        update(size_type count, uint8_type input) noexcept {

            auto cursor = m_count % sizeof(block_type);
            auto excess = (cursor + count) % sizeof(block_type);
            auto blocks = (cursor + count) / sizeof(block_type);

            while (blocks-- != 0) {

                while (cursor < sizeof(block_type)) {
                    m_block.data()[cursor++] = input;
                }

                cursor = (compress(m_block), 0);
            }

            while (cursor < excess) {
                m_block.data()[cursor++] = input;
            }

            return (m_count += count, *this);
        }

        constexpr SHA2&
        update(const uint8_type *input, size_type count) noexcept {

            auto cursor = m_count % sizeof(block_type);
            auto excess = (cursor + count) % sizeof(block_type);
            auto blocks = (cursor + count) / sizeof(block_type);

            while (blocks-- != 0) {

                while (cursor < sizeof(block_type)) {
                    m_block.data()[cursor++] = *input++;
                }

                cursor = (compress(m_block), 0);
            }

            while (cursor < excess) {
                m_block.data()[cursor++] = *input++;
            }

            return (m_count += count, *this);
        }

        template<typename input_type> constexpr SHA2&
        update(const input_type *input, size_type count) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type, auto count> constexpr SHA2&
        update(const input_type (&input)[count]) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type> constexpr SHA2&
        update(const input_type *begin, const input_type *end) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(begin), sizeof(input_type) * (end - begin));
        }

        template<typename input_type> constexpr SHA2&
        update(const input_type &input) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(&input), sizeof(input_type));
        }

        constexpr SHA2&
        update(const char *input) noexcept {
            return update(reinterpret_cast<const uint8_type*>(input), __builtin_strlen(input));
        }

        template<typename input_type> constexpr SHA2&
        update(const size_type count, input_type &&input) noexcept {
            for (size_type i = 0; i < count; ++i) update(static_cast<input_type&&>(input)); return *this;
        }

        constexpr output_type
        digest() const noexcept {

            auto hasher = SHA2{*this};

            hasher.update(size_type{1}, uint8_type{0x80});

            auto length = hasher.size() % sizeof(block_type) + sizeof(size_type);
            auto factor = (length + sizeof(block_type) - 1) / sizeof(block_type);

            hasher.update(factor * sizeof(block_type) - length, uint8_type{0x00});
            hasher.update(h2be(m_count << 3));

            for (auto i = 0U; i < hasher.m_state.size(); ++i) {
                hasher.m_state[i] = h2be(hasher.m_state[i]);
            }

            return *reinterpret_cast<output_type*>(&hasher.m_state);
        }

        static constexpr inline round_type g_round;

    private:

        size_type                          m_count = {};
        block_type                         m_block = {};
        state_type                         m_state = {};

        static constexpr uint32_type
        h2be(uint32_type value) noexcept {
            return __builtin_bswap32(value);
        }

        static constexpr uint64_type
        h2be(uint64_type value) noexcept {
            return __builtin_bswap64(value);
        }

        static constexpr uint128_type
        h2be(uint128_type value) noexcept {
            return (static_cast<uint128_type>(h2be(static_cast<uint64_type>(value))) << 64) | static_cast<uint128_type>(h2be(static_cast<uint64_type>(value >> 64)));
        }

        static constexpr uint32_type
        rotr(uint32_type value, int count) noexcept {
            return __builtin_rotateright32(value, count);
        }

        static constexpr uint64_type
        rotr(uint64_type value, int count) noexcept {
            return __builtin_rotateright64(value, count);
        }

        static constexpr uint32_type
        sigma0(uint32_type value) noexcept {
            return rotr(value, 7) ^ rotr(value,18) ^ (value >>  3);
        }

        static constexpr uint64_type
        sigma0(uint64_type value) noexcept {
            return rotr(value, 1) ^ rotr(value, 8) ^ (value >>  7);
        }

        static constexpr uint32_type
        sigma1(uint32_type value) noexcept {
            return rotr(value,17) ^ rotr(value,19) ^ (value >> 10);
        }

        static constexpr uint64_type
        sigma1(uint64_type value) noexcept {
            return rotr(value,19) ^ rotr(value,61) ^ (value >>  6);
        }

        static constexpr uint32_type
        delta0(uint32_type value) noexcept {
            return rotr(value, 2) ^ rotr(value,13) ^ rotr(value,22);
        }

        static constexpr uint64_type
        delta0(uint64_type value) noexcept {
            return rotr(value,28) ^ rotr(value,34) ^ rotr(value,39);
        }

        static constexpr uint32_type
        delta1(uint32_type value) noexcept {
            return rotr(value, 6) ^ rotr(value,11) ^ rotr(value,25);
        }

        static constexpr uint64_type
        delta1(uint64_type value) noexcept {
            return rotr(value,14) ^ rotr(value,18) ^ rotr(value,41);
        }

        static constexpr word_type
        bop202(word_type word1, word_type word2, word_type word3) noexcept {
            return (word1 & (word2 ^ word3)) ^ word3;
        }

        static constexpr word_type
        bop232(word_type word1, word_type word2, word_type word3) noexcept {
            return (word1 & word2) | ((word1 ^ word2) & word3);
        }

        static constexpr void
        unshift(state_type &state, word_type value1, word_type value2) {

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + value2;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = value1 + value2;
        }

        constexpr void
        compress(const block_type &block) noexcept {

            round_type round;
            state_type state = m_state;

            for (auto i = 0U; i < block.size(); ++i) {
                round[i] = h2be(block[i]);
            }

            for (auto i = block.size(); i < round.size(); ++i) {
                round[i] = round[i - 16] + sigma0(round[i - 15]) + round[i - 7] + sigma1(round[i - 2]);
            }

            for (auto i = 0U; i < round.size(); ++i) {
                unshift(state, delta0(state[0]) + bop232(state[0], state[1], state[2]), delta1(state[4]) +
                    bop202(state[4], state[5], state[6]) + state[7] + round[i] + SHA2<state_bits>::g_round[i]);
            }

            for (auto i = 0U; i < state.size(); ++i) {
                m_state[i] += state[i];
            }
        }
    };

    // 256

    template<> constexpr
    SHA2<256, 224>::SHA2() noexcept : m_state{

        0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4} {
    }

    template<> constexpr
    SHA2<256, 256>::SHA2() noexcept : m_state{

        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19} {
    }

    template<> decltype(SHA2<256, 256>::g_round)
    SHA2<256, 256>::g_round = {

        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    };

    // 512

    template<> constexpr
    SHA2<512, 224>::SHA2() noexcept : m_state{

        0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1} {
    }

    template<> constexpr
    SHA2<512, 256>::SHA2() noexcept : m_state{

        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2} {
    }

    template<> constexpr
    SHA2<512, 384>::SHA2() noexcept : m_state{

        0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
        0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4} {
    }

    template<> constexpr
    SHA2<512, 512>::SHA2() noexcept : m_state{

        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179} {
    }

    template<> decltype(SHA2<512, 512>::g_round)
    SHA2<512, 512>::g_round = {

        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    };


    template<unsigned state_bits, unsigned output_bits = state_bits, typename ...input_type> constexpr decltype(auto)
    sha2(input_type &&...input) noexcept {
        return SHA2<state_bits, output_bits>().update(static_cast<input_type&&>(input)...).digest();
    }
}

#if __INCLUDE_LEVEL__

    #pragma once

#else

    #include <cassert>
    using namespace crypto;

    template<auto count, typename right_type> constexpr bool
    operator==(const char (&left)[count], const right_type &right) noexcept {
        return count - 1 == sizeof(right_type) && __builtin_memcmp(&left, &right, sizeof(right_type)) == 0;
    }

    int
    main() {

        assert(("\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9\x47\x61\x02\xbb\x28\x82\x34\xc4\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a\xc5\xb3\xe4\x2f" == sha2<256,224>("")));
        assert(("\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7" == sha2<256,224>("abc")));
        assert(("\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\x01\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25" == sha2<256,224>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
        assert(("\xc9\x7c\xa9\xa5\x59\x85\x0c\xe9\x7a\x04\xa9\x6d\xef\x6d\x99\xa9\xe0\xe0\xe2\xab\x14\xe6\xb8\xdf\x26\x5f\xc0\xb3" == sha2<256,224>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")));
        assert(("\x20\x79\x46\x55\x98\x0c\x91\xd8\xbb\xb4\xc1\xea\x97\x61\x8a\x4b\xf0\x3f\x42\x58\x19\x48\xb2\xee\x4e\xe7\xad\x67" == sha2<256,224>(1000000, 'a')));
        assert(("\xb5\x98\x97\x13\xca\x4f\xe4\x7a\x00\x9f\x86\x21\x98\x0b\x34\xe6\xd6\x3e\xd3\x06\x3b\x2a\x0a\x2c\x86\x7d\x8a\x85" == sha2<256,224>(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")));

        assert(("\x6e\xd0\xdd\x02\x80\x6f\xa8\x9e\x25\xde\x06\x0c\x19\xd3\xac\x86\xca\xbb\x87\xd6\xa0\xdd\xd0\x5c\x33\x3b\x84\xf4" == sha2<512,224>("")));
        assert(("\x46\x34\x27\x0f\x70\x7b\x6a\x54\xda\xae\x75\x30\x46\x08\x42\xe2\x0e\x37\xed\x26\x5c\xee\xe9\xa4\x3e\x89\x24\xaa" == sha2<512,224>("abc")));
        assert(("\xe5\x30\x2d\x6d\x54\xbb\x24\x22\x75\xd1\xe7\x62\x2d\x68\xdf\x6e\xb0\x2d\xed\xd1\x3f\x56\x4c\x13\xdb\xda\x21\x74" == sha2<512,224>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
        assert(("\x23\xfe\xc5\xbb\x94\xd6\x0b\x23\x30\x81\x92\x64\x0b\x0c\x45\x33\x35\xd6\x64\x73\x4f\xe4\x0e\x72\x68\x67\x4a\xf9" == sha2<512,224>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")));
        assert(("\x37\xab\x33\x1d\x76\xf0\xd3\x6d\xe4\x22\xbd\x0e\xde\xb2\x2a\x28\xac\xcd\x48\x7b\x7a\x84\x53\xae\x96\x5d\xd2\x87" == sha2<512,224>(1000000, 'a')));
        assert(("\x9a\x7f\x86\x72\x7c\x3b\xe1\x40\x3d\x67\x02\x61\x76\x46\xb1\x55\x89\xb8\xc5\xa9\x2c\x70\xf1\x70\x3c\xd2\x5b\x52" == sha2<512,224>(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")));

        assert(("\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" == sha2<256,256>("")));
        assert(("\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" == sha2<256,256>("abc")));
        assert(("\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" == sha2<256,256>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
        assert(("\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92\x37\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe\xe9\xd1" == sha2<256,256>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")));
        assert(("\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0" == sha2<256,256>(1000000, 'a')));
        assert(("\x50\xe7\x2a\x0e\x26\x44\x2f\xe2\x55\x2d\xc3\x93\x8a\xc5\x86\x58\x22\x8c\x0c\xbf\xb1\xd2\xca\x87\x2a\xe4\x35\x26\x6f\xcd\x05\x5e" == sha2<256,256>(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")));

        assert(("\xc6\x72\xb8\xd1\xef\x56\xed\x28\xab\x87\xc3\x62\x2c\x51\x14\x06\x9b\xdd\x3a\xd7\xb8\xf9\x73\x74\x98\xd0\xc0\x1e\xce\xf0\x96\x7a" == sha2<512,256>("")));
        assert(("\x53\x04\x8e\x26\x81\x94\x1e\xf9\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46\xe0\xe2\xf1\x31\x07\xe7\xaf\x23" == sha2<512,256>("abc")));
        assert(("\xbd\xe8\xe1\xf9\xf1\x9b\xb9\xfd\x34\x06\xc9\x0e\xc6\xbc\x47\xbd\x36\xd8\xad\xa9\xf1\x18\x80\xdb\xc8\xa2\x2a\x70\x78\xb6\xa4\x61" == sha2<512,256>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
        assert(("\x39\x28\xe1\x84\xfb\x86\x90\xf8\x40\xda\x39\x88\x12\x1d\x31\xbe\x65\xcb\x9d\x3e\xf8\x3e\xe6\x14\x6f\xea\xc8\x61\xe1\x9b\x56\x3a" == sha2<512,256>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")));
        assert(("\x9a\x59\xa0\x52\x93\x01\x87\xa9\x70\x38\xca\xe6\x92\xf3\x07\x08\xaa\x64\x91\x92\x3e\xf5\x19\x43\x94\xdc\x68\xd5\x6c\x74\xfb\x21" == sha2<512,256>(1000000, 'a')));
        assert(("\xb5\x85\x5a\x61\x79\x80\x2c\xe5\x67\xcb\xf4\x38\x88\x28\x4c\x6a\xc7\xc3\xf6\xc4\x8b\x08\xc5\xbc\x1e\x8a\xd7\x5d\x12\x78\x2c\x9e" == sha2<512,256>(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")));

        assert(("\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b" == sha2<512,384>("")));
        assert(("\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7" == sha2<512,384>("abc")));
        assert(("\x33\x91\xfd\xdd\xfc\x8d\xc7\x39\x37\x07\xa6\x5b\x1b\x47\x09\x39\x7c\xf8\xb1\xd1\x62\xaf\x05\xab\xfe\x8f\x45\x0d\xe5\xf3\x6b\xc6\xb0\x45\x5a\x85\x20\xbc\x4e\x6f\x5f\xe9\x5b\x1f\xe3\xc8\x45\x2b" == sha2<512,384>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
        assert(("\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0\xf7\x12\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91\x74\x60\x39" == sha2<512,384>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")));
        assert(("\x9d\x0e\x18\x09\x71\x64\x74\xcb\x08\x6e\x83\x4e\x31\x0a\x4a\x1c\xed\x14\x9e\x9c\x00\xf2\x48\x52\x79\x72\xce\xc5\x70\x4c\x2a\x5b\x07\xb8\xb3\xdc\x38\xec\xc4\xeb\xae\x97\xdd\xd8\x7f\x3d\x89\x85" == sha2<512,384>(1000000, 'a')));
        assert(("\x54\x41\x23\x5c\xc0\x23\x53\x41\xed\x80\x6a\x64\xfb\x35\x47\x42\xb5\xe5\xc0\x2a\x3c\x5c\xb7\x1b\x5f\x63\xfb\x79\x34\x58\xd8\xfd\xae\x59\x9c\x8c\xd8\x88\x49\x43\xc0\x4f\x11\xb3\x1b\x89\xf0\x23" == sha2<512,384>(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")));

        assert(("\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e" == sha2<512,512>("")));
        assert(("\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f" == sha2<512,512>("abc")));
        assert(("\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4\x16\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31\xa7\x03\xc3\x35\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa\x1d\x3b\xea\x57\x78\x9c\xa0\x31\xad\x85\xc7\xa7\x1d\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45" == sha2<512,512>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
        assert(("\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09" == sha2<512,512>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")));
        assert(("\xe7\x18\x48\x3d\x0c\xe7\x69\x64\x4e\x2e\x42\xc7\xbc\x15\xb4\x63\x8e\x1f\x98\xb1\x3b\x20\x44\x28\x56\x32\xa8\x03\xaf\xa9\x73\xeb\xde\x0f\xf2\x44\x87\x7e\xa6\x0a\x4c\xb0\x43\x2c\xe5\x77\xc3\x1b\xeb\x00\x9c\x5c\x2c\x49\xaa\x2e\x4e\xad\xb2\x17\xad\x8c\xc0\x9b" == sha2<512,512>(1000000, 'a')));
        assert(("\xb4\x7c\x93\x34\x21\xea\x2d\xb1\x49\xad\x6e\x10\xfc\xe6\xc7\xf9\x3d\x07\x52\x38\x01\x80\xff\xd7\xf4\x62\x9a\x71\x21\x34\x83\x1d\x77\xbe\x60\x91\xb8\x19\xed\x35\x2c\x29\x67\xa2\xe2\xd4\xfa\x50\x50\x72\x3c\x96\x30\x69\x1f\x1a\x05\xa7\x28\x1d\xbe\x6c\x10\x86" == sha2<512,512>(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno")));

        return 0;
    }

#endif
