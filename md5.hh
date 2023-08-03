/*
 * NAME
 *
 *     md5 - message digest algorithm 5
 *
 * SYNOPSIS
 *
 *     auto digest = MD5().update(...).digest();
 *
 * DESCRIPTION
 *
 *     MD5 (Message Digest Algorithm 5) is a cryptographic hash function,
 *     that calculates a 128-bit hash value for a given input.  MD5 is an
 *     older algorithm that is now considered insecure and unsuitable for
 *     cryptographic purposes.
 *
 * EXAMPLES
 *
 *     #include <crypto/md5.h>
 *     using namespace crypto;
 *
 *     auto
 *     hash(const auto &trivially_copyable_objects) {
 *
 *         auto hasher = MD5();
 *
 *         for (const auto &object: trivially_copyable_objects) {
 *             hasher.update(object);
 *         }
 *
 *         return md5(hasher.update("secret").digest());
 *     }
 *
 * COPYRIGHT
 *
 *     Copyright 2022 Quasis - The MIT License
 */

namespace crypto {

    template<unsigned state_bits = 128>
    class MD5 {

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
        using round_type  = buffer<word_type, 64>;
        using output_type = buffer<uint8_type, 16>;

        constexpr
        MD5() noexcept : m_state{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476} {
            static_assert(state_bits == 128);
        }

        constexpr
       ~MD5() noexcept {
            __builtin_memset(m_block.data(), 0, sizeof(block_type));
        }

        constexpr size_type
        size() const noexcept {
            return m_count;
        }

        constexpr MD5&
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

        constexpr MD5&
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

        template<typename input_type> constexpr MD5&
        update(const input_type *input, size_type count) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type, auto count> constexpr MD5&
        update(const input_type (&input)[count]) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type> constexpr MD5&
        update(const input_type *begin, const input_type *end) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(begin), sizeof(input_type) * (end - begin));
        }

        template<typename input_type> constexpr MD5&
        update(const input_type &input) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(&input), sizeof(input_type));
        }

        constexpr MD5&
        update(const char *input) noexcept {
            return update(reinterpret_cast<const uint8_type*>(input), __builtin_strlen(input));
        }

        template<typename input_type> constexpr MD5&
        update(const size_type count, input_type &&input) noexcept {
            for (size_type i = 0; i < count; ++i) update(static_cast<input_type&&>(input)); return *this;
        }

        constexpr output_type
        digest() const noexcept {

            auto hasher = MD5{*this};

            hasher.update(size_type{1}, uint8_type{0x80});

            auto length = hasher.size() % sizeof(block_type) + sizeof(size_type);
            auto factor = (length + sizeof(block_type) - 1) / sizeof(block_type);

            hasher.update(factor * sizeof(block_type) - length, uint8_type{0x00});
            hasher.update(m_count << 3);

            return *reinterpret_cast<output_type*>(&hasher.m_state);
        }

    private:

        size_type          m_count = {};
        block_type         m_block = {};
        state_type         m_state = {};

        static constexpr uint32_type
        rotl(uint32_type value, int count) noexcept {
            return __builtin_rotateleft32(value, count);
        }

        static constexpr word_type
        bop057(word_type word1, word_type word2, word_type word3) noexcept {
            return (word1 | ~word3) ^ word2;
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
        bop228(word_type word1, word_type word2, word_type word3) noexcept {
            return (word1 & word3) | (word2 & ~word3);
        }

        static constexpr void
        unshift(state_type &state, word_type value) {

            state[0] = state[3];
            state[3] = state[2];
            state[2] = state[1];
            state[1] += value;
        }

        constexpr void
        compress(const block_type &block) noexcept {

            state_type state = m_state;

            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xD76AA478 + block[ 0],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xE8C7B756 + block[ 1], 12));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x242070DB + block[ 2], 17));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xC1BDCEEE + block[ 3], 22));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xF57C0FAF + block[ 4],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x4787C62A + block[ 5], 12));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xA8304613 + block[ 6], 17));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xFD469501 + block[ 7], 22));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x698098D8 + block[ 8],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x8B44F7AF + block[ 9], 12));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xFFFF5BB1 + block[10], 17));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x895CD7BE + block[11], 22));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x6B901122 + block[12],  7));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xFD987193 + block[13], 12));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0xA679438E + block[14], 17));
            unshift(state, rotl(state[0] + bop202(state[1], state[2], state[3]) + 0x49B40821 + block[15], 22));

            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xF61E2562 + block[ 1],  5));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xC040B340 + block[ 6],  9));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0x265E5A51 + block[11], 14));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xE9B6C7AA + block[ 0], 20));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xD62F105D + block[ 5],  5));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0x02441453 + block[10],  9));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xD8A1E681 + block[15], 14));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xE7D3FBC8 + block[ 4], 20));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0x21E1CDE6 + block[ 9],  5));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xC33707D6 + block[14],  9));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xF4D50D87 + block[ 3], 14));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0x455A14ED + block[ 8], 20));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xA9E3E905 + block[13],  5));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0xFCEFA3F8 + block[ 2],  9));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0x676F02D9 + block[ 7], 14));
            unshift(state, rotl(state[0] + bop228(state[1], state[2], state[3]) + 0x8D2A4C8A + block[12], 20));

            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xFFFA3942 + block[ 5],  4));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x8771F681 + block[ 8], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x6D9D6122 + block[11], 16));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xFDE5380C + block[14], 23));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xA4BEEA44 + block[ 1],  4));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x4BDECFA9 + block[ 4], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xF6BB4B60 + block[ 7], 16));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xBEBFBC70 + block[10], 23));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x289B7EC6 + block[13],  4));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xEAA127FA + block[ 0], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xD4EF3085 + block[ 3], 16));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x04881D05 + block[ 6], 23));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xD9D4D039 + block[ 9],  4));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xE6DB99E5 + block[12], 11));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0x1FA27CF8 + block[15], 16));
            unshift(state, rotl(state[0] + bop150(state[1], state[2], state[3]) + 0xC4AC5665 + block[ 2], 23));

            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xF4292244 + block[ 0],  6));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x432AFF97 + block[ 7], 10));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xAB9423A7 + block[14], 15));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xFC93A039 + block[ 5], 21));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x655B59C3 + block[12],  6));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x8F0CCC92 + block[ 3], 10));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xFFEFF47D + block[10], 15));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x85845DD1 + block[ 1], 21));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x6FA87E4F + block[ 8],  6));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xFE2CE6E0 + block[15], 10));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xA3014314 + block[ 6], 15));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x4E0811A1 + block[13], 21));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xF7537E82 + block[ 4],  6));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xBD3AF235 + block[11], 10));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0x2AD7D2BB + block[ 2], 15));
            unshift(state, rotl(state[0] + bop057(state[1], state[2], state[3]) + 0xEB86D391 + block[ 9], 21));

            for (auto i = 0U; i < state.size(); ++i) {
                m_state[i] += state[i];
            }
        }
    };

    template<unsigned state_bits = 128, typename ...input_type> constexpr decltype(auto)
    md5(input_type &&...input) noexcept {
        return MD5<state_bits>().update(static_cast<input_type&&>(input)...).digest();
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

        assert("\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e" == md5(""));
        assert("\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61" == md5("a"));
        assert("\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72" == md5("abc"));
        assert("\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0" == md5("message digest"));
        assert("\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b" == md5("abcdefghijklmnopqrstuvwxyz"));
        assert("\x82\x15\xef\x07\x96\xa2\x0b\xca\xaa\xe1\x16\xd3\x87\x6c\x66\x4a" == md5("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f" == md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
        assert("\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a" == md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
        assert("\x77\x07\xd6\xae\x4e\x02\x7c\x70\xee\xa2\xa9\x35\xc2\x29\x6f\x21" == md5(1000000, 'a'));

        return 0;
    }

#endif
