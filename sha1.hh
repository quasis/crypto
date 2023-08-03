/*
 * NAME
 *
 *     sha1 - secure hash algorithm 1
 *
 * SYNOPSIS
 *
 *     auto digest = SHA1().update(...).digest();
 *
 * DESCRIPTION
 *
 *     SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function
 *     that produces a 160-bit hash value. The algorithm was designed by
 *     the National Security Agency (NSA) and published by the National
 *     Institute of Standards and Technology (NIST) in 1995.
 *
 * EXAMPLES
 *
 *     #include <crypto/sha1.h>
 *     using namespace crypto;
 *
 *     auto
 *     hash(const auto &trivially_copyable_objects) {
 *
 *         auto hasher = SHA1();
 *
 *         for (const auto &object: trivially_copyable_objects) {
 *             hasher.update(object);
 *         }
 *
 *         return sha1(hasher.update("secret").digest());
 *     }
 *
 * COPYRIGHT
 *
 *     Copyright 2022 Quasis - The MIT License
 */

namespace crypto {

    template<unsigned state_bits = 160>
    class SHA1 {

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
        using state_type  = buffer<word_type, 5>;
        using block_type  = buffer<word_type, 16>;
        using round_type  = buffer<word_type, 80>;
        using output_type = buffer<uint8_type, 20>;

        constexpr
        SHA1() noexcept : m_state{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0} {
            static_assert(state_bits == 160);
        }

        constexpr
       ~SHA1() noexcept {
            __builtin_memset(m_block.data(), 0, sizeof(block_type));
        }

        constexpr size_type
        size() const noexcept {
            return m_count;
        }

        constexpr SHA1&
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

        constexpr SHA1&
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

        template<typename input_type> constexpr SHA1&
        update(const input_type *input, size_type count) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type, auto count> constexpr SHA1&
        update(const input_type (&input)[count]) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type> constexpr SHA1&
        update(const input_type *begin, const input_type *end) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(begin), sizeof(input_type) * (end - begin));
        }

        template<typename input_type> constexpr SHA1&
        update(const input_type &input) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(&input), sizeof(input_type));
        }

        constexpr SHA1&
        update(const char *input) noexcept {
            return update(reinterpret_cast<const uint8_type*>(input), __builtin_strlen(input));
        }

        template<typename input_type> constexpr SHA1&
        update(const size_type count, input_type &&input) noexcept {
            for (size_type i = 0; i < count; ++i) update(static_cast<input_type&&>(input)); return *this;
        }

        constexpr output_type
        digest() const noexcept {

            auto hasher = SHA1{*this};

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

    private:

        size_type  m_count = {};
        block_type m_block = {};
        state_type m_state = {};

        static constexpr uint32_type
        h2be(uint32_type value) noexcept {
            return __builtin_bswap32(value);
        }

        static constexpr uint64_type
        h2be(uint64_type value) noexcept {
            return __builtin_bswap64(value);
        }

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

            state[4] = state[3];
            state[3] = state[2];
            state[2] = rotl(state[1], 30);
            state[1] = state[0];
            state[0] = value;
        }

        constexpr void
        compress(const block_type &block) noexcept {

            round_type round;
            state_type state = m_state;

            for (auto i = 0U; i < block.size(); ++i) {
                round[i] = h2be(block[i]);
            }

            for (auto i = block.size(); i < round.size(); ++i) {
                round[i] = rotl(round[i - 16] ^ round[i - 14] ^ round[i - 8] ^ round[i - 3], 1);
            }

            for (auto i =  0; i < 20; ++i) {
                unshift(state, rotl(state[0], 5) + bop202(state[1], state[2], state[3]) + state[4] + round[i] + 0x5A827999);
            }

            for (auto i = 20; i < 40; ++i) {
                unshift(state, rotl(state[0], 5) + bop150(state[1], state[2], state[3]) + state[4] + round[i] + 0x6ED9EBA1);
            }

            for (auto i = 40; i < 60; ++i) {
                unshift(state, rotl(state[0], 5) + bop232(state[1], state[2], state[3]) + state[4] + round[i] + 0x8F1BBCDC);
            }

            for (auto i = 60; i < 80; ++i) {
                unshift(state, rotl(state[0], 5) + bop150(state[1], state[2], state[3]) + state[4] + round[i] + 0xCA62C1D6);
            }

            for (auto i = 0U; i < state.size(); ++i) {
                m_state[i] += state[i];
            }
        }
    };

    template<unsigned state_bits = 160, typename ...input_type> constexpr decltype(auto)
    sha1(input_type &&...input) noexcept {
        return SHA1<state_bits>().update(static_cast<input_type&&>(input)...).digest();
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

        assert("\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09" == sha1(""));
        assert("\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d" == sha1("abc"));
        assert("\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1" == sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\xa4\x9b\x24\x46\xa0\x2c\x64\x5b\xf4\x19\xf9\x95\xb6\x70\x91\x25\x3a\x04\xa2\x59" == sha1("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
        assert("\x34\xaa\x97\x3c\xd4\xc4\xda\xa4\xf6\x1e\xeb\x2b\xdb\xad\x27\x31\x65\x34\x01\x6f" == sha1(1000000, 'a'));
        assert("\x77\x89\xf0\xc9\xef\x7b\xfc\x40\xd9\x33\x11\x14\x3d\xfb\xe6\x9e\x20\x17\xf5\x92" == sha1(16777216, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"));

        return 0;
    }

#endif
