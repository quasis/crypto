/*
 * NAME
 *
 *     md4 - message digest algorithm 4
 *
 * SYNOPSIS
 *
 *     auto digest = crypto::MD4().update(...).digest();
 *
 * DESCRIPTION
 *
 *     MD4 (Message Digest Algorithm 4) is a cryptographic hash function,
 *     that calculates a 128-bit hash value for a given input.  MD4 is an
 *     older algorithm that is now considered insecure and unsuitable for
 *     cryptographic purposes.
 *
 * EXAMPLES
 *
 *     #include <crypto/md4.h>
 *     using namespace crypto;
 *
 *     auto
 *     hash(const auto &trivially_copyable_objects) {
 *
 *         auto hasher = MD4();
 *
 *         for (const auto &object: trivially_copyable_objects) {
 *             hasher.update(object);
 *         }
 *
 *         return md4(hasher.update("secret").digest());
 *     }
 *
 * COPYRIGHT
 *
 *     Copyright 2022 Quasis - The MIT License
 */

namespace crypto {

    template<unsigned state_bits = 128>
    class MD4 {

        using uint8_type  = __UINT8_TYPE__;
        using uint16_type = __UINT16_TYPE__;
        using uint32_type = __UINT32_TYPE__;
        using uint64_type = __UINT64_TYPE__;

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

        using size_type   = uint64_type;
        using word_type   = uint32_type;
        using state_type  = buffer<word_type, 4>;
        using block_type  = buffer<word_type, 16>;
        using round_type  = buffer<word_type, 48>;
        using output_type = buffer<uint8_type, 16>;

        constexpr
        MD4() noexcept : m_state{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476} {
            static_assert(state_bits == 128);
        }

        constexpr
       ~MD4() noexcept {
            __builtin_memset(m_block.data(), 0, sizeof(block_type));
        }

        constexpr size_type
        size() const noexcept {
            return m_count;
        }

        constexpr MD4&
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

        constexpr MD4&
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

        template<typename input_type> constexpr MD4&
        update(const input_type *input, size_type count) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type, auto count> constexpr MD4&
        update(const input_type (&input)[count]) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type> constexpr MD4&
        update(const input_type *begin, const input_type *end) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(begin), sizeof(input_type) * (end - begin));
        }

        template<typename input_type> constexpr MD4&
        update(const input_type &input) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(&input), sizeof(input_type));
        }

        constexpr MD4&
        update(const char *input) noexcept {
            return update(reinterpret_cast<const uint8_type*>(input), __builtin_strlen(input));
        }

        template<typename input_type> constexpr MD4&
        update(const size_type count, input_type &&input) noexcept {
            for (size_type i = 0; i < count; ++i) update(static_cast<input_type&&>(input)); return *this;
        }

        constexpr output_type
        digest() const noexcept {

            auto hasher = MD4{*this};

            hasher.update(size_type{1}, uint8_type{0x80});

            auto length = hasher.size() % sizeof(block_type) + sizeof(size_type);
            auto factor = (length + sizeof(block_type) - 1) / sizeof(block_type);

            hasher.update(factor * sizeof(block_type) - length, uint8_type{0x00});
            hasher.update(m_count << 3);

            return *reinterpret_cast<output_type*>(&hasher.m_state);
        }

    private:

        size_type  m_count = {};
        block_type m_block = {};
        state_type m_state = {};

        static constexpr uint32_type
        rotl(uint32_type value, int count) noexcept {
            return __builtin_rotateleft32(value, count);
        }

        static constexpr word_type
        bop150(word_type word1, word_type word2, word_type word3) noexcept {
            return word1 ^ word2 ^ word3;
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
        unshift(state_type &state, word_type value) {

            state[0] = state[3];
            state[3] = state[2];
            state[2] = state[1];
            state[1] = value;
        }

        constexpr void
        compress(const block_type &block) noexcept {

            state_type state = m_state;

            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 0],  3));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 1],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 2], 11));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 3], 19));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 4],  3));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 5],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 6], 11));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 7], 19));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 8],  3));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[ 9],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[10], 11));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[11], 19));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[12],  3));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[13],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[14], 11));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x00000000 + block[15], 19));

            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 0],  3));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 4],  5));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 8],  9));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[12], 13));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 1],  3));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 5],  5));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 9],  9));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[13], 13));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 2],  3));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 6],  5));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[10],  9));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[14], 13));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 3],  3));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[ 7],  5));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[11],  9));
            unshift(state, rotl(state[0] + bop232(state[1], state[2], state[3]) + 0x5A827999 + block[15], 13));

            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 0],  3));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 8],  9));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 4], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[12], 15));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 2],  3));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[10],  9));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 6], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[14], 15));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 1],  3));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 9],  9));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 5], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[13], 15));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 3],  3));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[11],  9));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[ 7], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6ED9EBA1 + block[15], 15));

            for (auto i = 0U; i < state.size(); ++i) {
                m_state[i] += state[i];
            }
        }
    };

    template<unsigned state_bits = 128, typename ...input_type> constexpr decltype(auto)
    md4(input_type &&...input) noexcept {
        return MD4<state_bits>().update(static_cast<input_type&&>(input)...).digest();
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

        assert("\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0" == md4(""));
        assert("\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24" == md4("a"));
        assert("\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d" == md4("abc"));
        assert("\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b" == md4("message digest"));
        assert("\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9" == md4("abcdefghijklmnopqrstuvwxyz"));
        assert("\x46\x91\xa9\xec\x81\xb1\xa6\xbd\x1a\xb8\x55\x72\x40\xb2\x45\xc5" == md4("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4" == md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
        assert("\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36" == md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
        assert("\xbb\xce\x80\xcc\x6b\xb6\x5e\x5c\x67\x45\xe3\x0d\x4e\xec\xa9\xa4" == md4(1000000, 'a'));

        return 0;
    }

#endif
