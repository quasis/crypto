/*
 * NAME
 *
 *     rmd - RACE message digest
 *
 * SYNOPSIS
 *
 *     auto digest = RMD<128>().update(...).digest();
 *     auto digest = RMD<160>().update(...).digest();
 *     auto digest = RMD<256>().update(...).digest();
 *     auto digest = RMD<320>().update(...).digest();
 *
 * DESCRIPTION
 *
 *     R[IPE]MD (RACE Integrity Primitives Evaluation Message Digest) is
 *     a family of cryptographic hash functions that were developed as a
 *     part of the European Union's RACE project. The original algorithm,
 *     known as RIPEMD-160, was designed to produce a 160-bit hash value,
 *     but other variants like RIPEMD-128, RIPEMD-256 and RIPEMD-320 were
 *     later introduced to produce shorter or longer hash values.
 *
 * EXAMPLES
 *
 *     #include <crypto/rmd.h>
 *     using namespace crypto;
 *
 *     auto
 *     hash(const auto &trivially_copyable_objects) {
 *
 *         auto hasher = RMD<256>();
 *
 *         for (const auto &object: trivially_copyable_objects) {
 *             hasher.update(object);
 *         }
 *
 *         return rmd<160>(hasher.update("secret").digest());
 *     }
 *
 * COPYRIGHT
 *
 *     Copyright 2022 Quasis - The MIT License
 */

namespace crypto {

    template<unsigned state_bits>
    class RMD {

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
        using state_type  = buffer<word_type, state_bits / 32>;
        using block_type  = buffer<word_type, 16>;
        using round_type  = buffer<word_type, state_bits % 160 ? 64 : 80>;
        using output_type = buffer<uint8_type, state_bits / 8>;

        constexpr
        RMD() noexcept;

        constexpr
       ~RMD() noexcept {
            __builtin_memset(m_block.data(), 0, sizeof(block_type));
        }

        constexpr size_type
        size() const noexcept {
            return m_count;
        }

        constexpr RMD&
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

        constexpr RMD&
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

        template<typename input_type> constexpr RMD&
        update(const input_type *input, size_type count) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type, auto count> constexpr RMD&
        update(const input_type (&input)[count]) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(input), sizeof(input_type) * count);
        }

        template<typename input_type> constexpr RMD&
        update(const input_type *begin, const input_type *end) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(begin), sizeof(input_type) * (end - begin));
        }

        template<typename input_type> constexpr RMD&
        update(const input_type &input) noexcept requires (__is_trivially_copyable(input_type)) {
            return update(reinterpret_cast<const uint8_type*>(&input), sizeof(input_type));
        }

        constexpr RMD&
        update(const char *input) noexcept {
            return update(reinterpret_cast<const uint8_type*>(input), __builtin_strlen(input));
        }

        template<typename input_type> constexpr RMD&
        update(const size_type count, input_type &&input) noexcept {
            for (size_type i = 0; i < count; ++i) update(static_cast<input_type&&>(input)); return *this;
        }

        constexpr output_type
        digest() const noexcept {

            auto hasher = RMD{*this};

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

        static constexpr void
        swap(word_type &word1, word_type &word2) noexcept {

            word_type temp = static_cast<word_type&&>(word1);

            word1 = static_cast<word_type&&>(word2);
            word2 = static_cast<word_type&&>(temp);
        }

        static constexpr word_type
        bop045(word_type word1, word_type word2, word_type word3) noexcept {
            return word1 ^ (word2 | ~word3);
        }

        static constexpr word_type
        bop089(word_type word1, word_type word2, word_type word3) noexcept {
            return (word1 | ~word2) ^ word3;
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
        unshift(state_type &state, word_type value) noexcept;

        constexpr void
        compress(const block_type &block) noexcept;
    };

    // 128

    template<> constexpr
    RMD<128>::RMD() noexcept : m_state{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476} {
    }

    template<> constexpr void
    RMD<128>::unshift(state_type &state, word_type value) noexcept {

        state[0] = state[3];
        state[3] = state[2];
        state[2] = state[1];
        state[1] = value;
    }

    template<> constexpr void
    RMD<128>::compress(const block_type &block) noexcept {

        state_type hash1 = m_state, hash2 = m_state;

        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 0], 11));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 5],  8));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 1], 14));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[14],  9));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 2], 15));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 7],  9));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 3], 12));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 0], 11));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 4],  5));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 9], 13));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 5],  8));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 2], 15));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 6],  7));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[11], 15));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 7],  9));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 4],  5));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 8], 11));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[13],  7));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 9], 13));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 6],  7));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[10], 14));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[15],  8));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[11], 15));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 8], 11));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[12],  6));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 1], 14));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[13],  7));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[10], 14));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[14],  9));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 3], 12));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[15],  8));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[12],  6));

        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 7],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 6],  9));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 4],  6));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[11], 13));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[13],  8));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 3], 15));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 1], 13));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 7],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[10], 11));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 0], 12));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 6],  9));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[13],  8));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[15],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 5],  9));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 3], 15));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[10], 11));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[12],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[14],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 0], 12));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[15],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 9], 15));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 8], 12));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 5],  9));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[12],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 2], 11));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 4],  6));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[14],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 9], 15));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[11], 13));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 1], 13));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 8], 12));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 2], 11));

        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 3], 11));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[15],  9));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[10], 13));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 5],  7));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[14],  6));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 1], 15));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 4],  7));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 3], 11));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 9], 14));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 7],  8));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[15],  9));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[14],  6));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 8], 13));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 6],  6));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 1], 15));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 9], 14));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 2], 14));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[11], 12));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 7],  8));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 8], 13));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 0], 13));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[12],  5));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 6],  6));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 2], 14));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[13],  5));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[10], 13));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[11], 12));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 0], 13));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 5],  7));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 4],  7));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[12],  5));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[13],  5));

        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 1], 11));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 8], 15));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 9], 12));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 6],  5));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[11], 14));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 4],  8));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[10], 15));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 1], 11));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 0], 14));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 3], 14));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 8], 15));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[11], 14));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[12],  9));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[15],  6));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 4],  8));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 0], 14));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[13],  9));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 5],  6));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 3], 14));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[12],  9));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 7],  5));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 2], 12));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[15],  6));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[13],  9));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[14],  8));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 9], 12));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 5],  6));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 7],  5));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 6],  5));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[10], 15));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 2], 12));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[14],  8));

        auto value = m_state[1] + hash1[2] + hash2[3];
        m_state[1] = m_state[2] + hash1[3] + hash2[0];
        m_state[2] = m_state[3] + hash1[0] + hash2[1];
        m_state[3] = m_state[0] + hash1[1] + hash2[2];
        m_state[0] = value;
    }

    // 160

    template<> constexpr
    RMD<160>::RMD() noexcept : m_state{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0} {
    }

    template<> constexpr void
    RMD<160>::unshift(state_type &state, word_type value) noexcept {

        state[0] = state[4];
        state[4] = state[3];
        state[3] = rotl(state[2], 10);
        state[2] = state[1];
        state[1] = value;
    }

    template<> constexpr void
    RMD<160>::compress(const block_type &block) noexcept {

        state_type hash1 = m_state, hash2 = m_state;

        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 0], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 5],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 1], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[14],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 2], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 7],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 3], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 0], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 4],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 9], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 5],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 2], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 6],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[11], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 7],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 4],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 8], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[13],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 9], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 6],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[10], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[15],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[11], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 8], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[12],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 1], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[13],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[10], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[14],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 3], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[15],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[12],  6) + hash2[4]);

        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 7],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 6],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 4],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[11], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[13],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 3], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 1], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 7],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[10], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 0], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 6],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[13],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[15],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 5],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 3], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[10], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[12],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[14],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 0], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[15],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 9], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 8], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 5],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[12],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 2], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 4],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[14],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 9], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[11], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 1], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 8], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 2], 11) + hash2[4]);

        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 3], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[15],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[10], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 5],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[14],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 1], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 4],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 3], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 9], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 7],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[15],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[14],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 8], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 6],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 1], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 9], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 2], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[11], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 7],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 8], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 0], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[12],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 6],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 2], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[13],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[10], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[11], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 0], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 5],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 4],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[12],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[13],  5) + hash2[4]);

        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 1], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 8], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 9], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 6],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[11], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 4],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[10], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 1], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 0], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 3], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 8], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[11], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[12],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[15],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 4],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 0], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[13],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 5],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 3], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[12],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 7],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 2], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[15],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[13],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[14],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 9], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 5],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 7],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 6],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[10], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 2], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[14],  8) + hash2[4]);

        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 4],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[12],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 0], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[15],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 5],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[10], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 9], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 4],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 7],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 1], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[12],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 5],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 2], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 8], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[10], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 7],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[14],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 6],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 1], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 2], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 3], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[13],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 8], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[14],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[11], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 0], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 6],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 3], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[15],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 9], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[13],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[11], 11) + hash2[4]);

        auto value = m_state[1] + hash1[2] + hash2[3];
        m_state[1] = m_state[2] + hash1[3] + hash2[4];
        m_state[2] = m_state[3] + hash1[4] + hash2[0];
        m_state[3] = m_state[4] + hash1[0] + hash2[1];
        m_state[4] = m_state[0] + hash1[1] + hash2[2];
        m_state[0] = value;
    }

    // 256

    template<> constexpr
    RMD<256>::RMD() noexcept : m_state{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
        0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567} {
    }

    template<> constexpr void
    RMD<256>::unshift(state_type &state, word_type value) noexcept {

        state[0] = state[3];
        state[3] = state[2];
        state[2] = state[1];
        state[1] = value;
    }

    template<> constexpr void
    RMD<256>::compress(const block_type &block) noexcept {

        state_type state = m_state, &hash1 = state, &hash2 = *static_cast<state_type*>(static_cast<void*>(&state[4]));

        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 0], 11));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 5],  8));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 1], 14));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[14],  9));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 2], 15));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 7],  9));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 3], 12));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 0], 11));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 4],  5));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 9], 13));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 5],  8));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 2], 15));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 6],  7));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[11], 15));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 7],  9));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 4],  5));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 8], 11));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[13],  7));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 9], 13));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 6],  7));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[10], 14));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[15],  8));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[11], 15));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 8], 11));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[12],  6));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 1], 14));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[13],  7));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[10], 14));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[14],  9));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 3], 12));
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[15],  8));
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[12],  6));

        swap(hash1[0], hash2[0]);

        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 7],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 6],  9));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 4],  6));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[11], 13));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[13],  8));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 3], 15));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 1], 13));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 7],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[10], 11));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 0], 12));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 6],  9));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[13],  8));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[15],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 5],  9));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 3], 15));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[10], 11));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[12],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[14],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 0], 12));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[15],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 9], 15));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 8], 12));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 5],  9));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[12],  7));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 2], 11));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 4],  6));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[14],  7));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 9], 15));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[11], 13));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 1], 13));
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 8], 12));
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 2], 11));

        swap(hash1[1], hash2[1]);

        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 3], 11));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[15],  9));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[10], 13));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 5],  7));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[14],  6));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 1], 15));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 4],  7));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 3], 11));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 9], 14));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 7],  8));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[15],  9));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[14],  6));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 8], 13));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 6],  6));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 1], 15));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 9], 14));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 2], 14));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[11], 12));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 7],  8));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 8], 13));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 0], 13));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[12],  5));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 6],  6));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 2], 14));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[13],  5));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[10], 13));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[11], 12));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 0], 13));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 5],  7));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 4],  7));
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[12],  5));
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[13],  5));

        swap(hash1[2], hash2[2]);

        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 1], 11));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 8], 15));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 9], 12));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 6],  5));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[11], 14));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 4],  8));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[10], 15));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 1], 11));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 0], 14));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 3], 14));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 8], 15));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[11], 14));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[12],  9));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[15],  6));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 4],  8));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 0], 14));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[13],  9));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 5],  6));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 3], 14));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[12],  9));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 7],  5));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 2], 12));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[15],  6));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[13],  9));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[14],  8));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 9], 12));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 5],  6));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 7],  5));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 6],  5));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[10], 15));
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 2], 12));
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[14],  8));

        swap(hash1[3], hash2[3]);

        for (auto i = 0U; i < state.size(); ++i) {
            m_state[i] += state[i];
        }
    }

    // 320

    template<> constexpr
    RMD<320>::RMD() noexcept : m_state{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
        0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567, 0x3C2D1E0F} {
    }

    template<> constexpr void
    RMD<320>::unshift(state_type &state, word_type value) noexcept {

        state[0] = state[4];
        state[4] = state[3];
        state[3] = rotl(state[2], 10);
        state[2] = state[1];
        state[1] = value;
    }

    template<> constexpr void
    RMD<320>::compress(const block_type &block) noexcept {

        state_type state = m_state, &hash1 = state, &hash2 = *static_cast<state_type*>(static_cast<void*>(&state[5]));

        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 0], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 5],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 1], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[14],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 2], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 7],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 3], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 0], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 4],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 9], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 5],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 2], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 6],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[11], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 7],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 4],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 8], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[13],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[ 9], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 6],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[10], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[15],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[11], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 8], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[12],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 1], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[13],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[10], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[14],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[ 3], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop150(hash1[1], hash1[2], hash1[3]) + 0x00000000 + block[15],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop045(hash2[1], hash2[2], hash2[3]) + 0x50A28BE6 + block[12],  6) + hash2[4]);

        swap(hash1[1], hash2[1]);

        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 7],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 6],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 4],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[11], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[13],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 3], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 1], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 7],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[10], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 0], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 6],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[13],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[15],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 5],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 3], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[10], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[12],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[14],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 0], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[15],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 9], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 8], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 5],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[12],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 2], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 4],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[14],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 9], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[11], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 1], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop202(hash1[1], hash1[2], hash1[3]) + 0x5A827999 + block[ 8], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop228(hash2[1], hash2[2], hash2[3]) + 0x5C4DD124 + block[ 2], 11) + hash2[4]);

        swap(hash1[3], hash2[3]);

        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 3], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[15],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[10], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 5],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[14],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 1], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 4],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 3], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 9], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 7],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[15],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[14],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 8], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 6],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 1], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 9], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 2], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[11], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 7],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 8], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 0], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[12],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 6],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 2], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[13],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[10], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[11], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 0], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[ 5],  7) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[ 4],  7) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop089(hash1[1], hash1[2], hash1[3]) + 0x6ED9EBA1 + block[12],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop089(hash2[1], hash2[2], hash2[3]) + 0x6D703EF3 + block[13],  5) + hash2[4]);

        swap(hash1[0], hash2[0]);

        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 1], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 8], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 9], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 6],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[11], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 4],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[10], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 1], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 0], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 3], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 8], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[11], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[12],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[15],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 4],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 0], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[13],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 5],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 3], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[12],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 7],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 2], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[15],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[13],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[14],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 9], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 5],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[ 7],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 6],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[10], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop228(hash1[1], hash1[2], hash1[3]) + 0x8F1BBCDC + block[ 2], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop202(hash2[1], hash2[2], hash2[3]) + 0x7A6D76E9 + block[14],  8) + hash2[4]);

        swap(hash1[2], hash2[2]);

        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 4],  9) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[12],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 0], 15) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[15],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 5],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[10], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 9], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 4],  9) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 7],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 1], 12) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[12],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 5],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 2], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 8], 14) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[10], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 7],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[14],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 6],  8) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 1], 12) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 2], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 3], 13) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[13],  6) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 8], 14) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[14],  5) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[11], 11) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 0], 15) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[ 6],  8) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 3], 13) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[15],  5) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[ 9], 11) + hash2[4]);
        unshift(hash1, rotl(hash1[0] + bop045(hash1[1], hash1[2], hash1[3]) + 0xA953FD4E + block[13],  6) + hash1[4]);
        unshift(hash2, rotl(hash2[0] + bop150(hash2[1], hash2[2], hash2[3]) + 0x00000000 + block[11], 11) + hash2[4]);

        swap(hash1[4], hash2[4]);

        for (auto i = 0U; i < state.size(); ++i) {
            m_state[i] += state[i];
        }
    }

    template<unsigned state_bits, typename ...input_type> constexpr decltype(auto)
    rmd(input_type &&...input) noexcept {
        return RMD<state_bits>().update(static_cast<input_type&&>(input)...).digest();
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

        assert("\xcd\xf2\x62\x13\xa1\x50\xdc\x3e\xcb\x61\x0f\x18\xf6\xb3\x8b\x46" == rmd<128>(""));
        assert("\x86\xbe\x7a\xfa\x33\x9d\x0f\xc7\xcf\xc7\x85\xe7\x2f\x57\x8d\x33" == rmd<128>("a"));
        assert("\xc1\x4a\x12\x19\x9c\x66\xe4\xba\x84\x63\x6b\x0f\x69\x14\x4c\x77" == rmd<128>("abc"));
        assert("\x9e\x32\x7b\x3d\x6e\x52\x30\x62\xaf\xc1\x13\x2d\x7d\xf9\xd1\xb8" == rmd<128>("message digest"));
        assert("\xfd\x2a\xa6\x07\xf7\x1d\xc8\xf5\x10\x71\x49\x22\xb3\x71\x83\x4e" == rmd<128>("abcdefghijklmnopqrstuvwxyz"));
        assert("\xa1\xaa\x06\x89\xd0\xfa\xfa\x2d\xdc\x22\xe8\x8b\x49\x13\x3a\x06" == rmd<128>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\xd1\xe9\x59\xeb\x17\x9c\x91\x1f\xae\xa4\x62\x4c\x60\xc5\xc7\x02" == rmd<128>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
        assert("\x3f\x45\xef\x19\x47\x32\xc2\xdb\xb2\xc4\xa2\xc7\x69\x79\x5f\xa3" == rmd<128>("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
        assert("\x4a\x7f\x57\x23\xf9\x54\xeb\xa1\x21\x6c\x9d\x8f\x63\x20\x43\x1f" == rmd<128>(1000000, 'a'));

        assert("\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31" == rmd<160>(""));
        assert("\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe" == rmd<160>("a"));
        assert("\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc" == rmd<160>("abc"));
        assert("\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36" == rmd<160>("message digest"));
        assert("\xf7\x1c\x27\x10\x9c\x69\x2c\x1b\x56\xbb\xdc\xeb\x5b\x9d\x28\x65\xb3\x70\x8d\xbc" == rmd<160>("abcdefghijklmnopqrstuvwxyz"));
        assert("\x12\xa0\x53\x38\x4a\x9c\x0c\x88\xe4\x05\xa0\x6c\x27\xdc\xf4\x9a\xda\x62\xeb\x2b" == rmd<160>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\xb0\xe2\x0b\x6e\x31\x16\x64\x02\x86\xed\x3a\x87\xa5\x71\x30\x79\xb2\x1f\x51\x89" == rmd<160>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
        assert("\x9b\x75\x2e\x45\x57\x3d\x4b\x39\xf4\xdb\xd3\x32\x3c\xab\x82\xbf\x63\x32\x6b\xfb" == rmd<160>("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
        assert("\x52\x78\x32\x43\xc1\x69\x7b\xdb\xe1\x6d\x37\xf9\x7f\x68\xf0\x83\x25\xdc\x15\x28" == rmd<160>(1000000, 'a'));

        assert("\x02\xba\x4c\x4e\x5f\x8e\xcd\x18\x77\xfc\x52\xd6\x4d\x30\xe3\x7a\x2d\x97\x74\xfb\x1e\x5d\x02\x63\x80\xae\x01\x68\xe3\xc5\x52\x2d" == rmd<256>(""));
        assert("\xf9\x33\x3e\x45\xd8\x57\xf5\xd9\x0a\x91\xba\xb7\x0a\x1e\xba\x0c\xfb\x1b\xe4\xb0\x78\x3c\x9a\xcf\xcd\x88\x3a\x91\x34\x69\x29\x25" == rmd<256>("a"));
        assert("\xaf\xbd\x6e\x22\x8b\x9d\x8c\xbb\xce\xf5\xca\x2d\x03\xe6\xdb\xa1\x0a\xc0\xbc\x7d\xcb\xe4\x68\x0e\x1e\x42\xd2\xe9\x75\x45\x9b\x65" == rmd<256>("abc"));
        assert("\x87\xe9\x71\x75\x9a\x1c\xe4\x7a\x51\x4d\x5c\x91\x4c\x39\x2c\x90\x18\xc7\xc4\x6b\xc1\x44\x65\x55\x4a\xfc\xdf\x54\xa5\x07\x0c\x0e" == rmd<256>("message digest"));
        assert("\x64\x9d\x30\x34\x75\x1e\xa2\x16\x77\x6b\xf9\xa1\x8a\xcc\x81\xbc\x78\x96\x11\x8a\x51\x97\x96\x87\x82\xdd\x1f\xd9\x7d\x8d\x51\x33" == rmd<256>("abcdefghijklmnopqrstuvwxyz"));
        assert("\x38\x43\x04\x55\x83\xaa\xc6\xc8\xc8\xd9\x12\x85\x73\xe7\xa9\x80\x9a\xfb\x2a\x0f\x34\xcc\xc3\x6e\xa9\xe7\x2f\x16\xf6\x36\x8e\x3f" == rmd<256>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\x57\x40\xa4\x08\xac\x16\xb7\x20\xb8\x44\x24\xae\x93\x1c\xbb\x1f\xe3\x63\xd1\xd0\xbf\x40\x17\xf1\xa8\x9f\x7e\xa6\xde\x77\xa0\xb8" == rmd<256>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
        assert("\x06\xfd\xcc\x7a\x40\x95\x48\xaa\xf9\x13\x68\xc0\x6a\x62\x75\xb5\x53\xe3\xf0\x99\xbf\x0e\xa4\xed\xfd\x67\x78\xdf\x89\xa8\x90\xdd" == rmd<256>("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
        assert("\xac\x95\x37\x44\xe1\x0e\x31\x51\x4c\x15\x0d\x4d\x8d\x7b\x67\x73\x42\xe3\x33\x99\x78\x82\x96\xe4\x3a\xe4\x85\x0c\xe4\xf9\x79\x78" == rmd<256>(1000000, 'a'));

        assert("\x22\xd6\x5d\x56\x61\x53\x6c\xdc\x75\xc1\xfd\xf5\xc6\xde\x7b\x41\xb9\xf2\x73\x25\xeb\xc6\x1e\x85\x57\x17\x7d\x70\x5a\x0e\xc8\x80\x15\x1c\x3a\x32\xa0\x08\x99\xb8" == rmd<320>(""));
        assert("\xce\x78\x85\x06\x38\xf9\x26\x58\xa5\xa5\x85\x09\x75\x79\x92\x6d\xda\x66\x7a\x57\x16\x56\x2c\xfc\xf6\xfb\xe7\x7f\x63\x54\x2f\x99\xb0\x47\x05\xd6\x97\x0d\xff\x5d" == rmd<320>("a"));
        assert("\xde\x4c\x01\xb3\x05\x4f\x89\x30\xa7\x9d\x09\xae\x73\x8e\x92\x30\x1e\x5a\x17\x08\x5b\xef\xfd\xc1\xb8\xd1\x16\x71\x3e\x74\xf8\x2f\xa9\x42\xd6\x4c\xdb\xc4\x68\x2d" == rmd<320>("abc"));
        assert("\x3a\x8e\x28\x50\x2e\xd4\x5d\x42\x2f\x68\x84\x4f\x9d\xd3\x16\xe7\xb9\x85\x33\xfa\x3f\x2a\x91\xd2\x9f\x84\xd4\x25\xc8\x8d\x6b\x4e\xff\x72\x7d\xf6\x6a\x7c\x01\x97" == rmd<320>("message digest"));
        assert("\xca\xbd\xb1\x81\x0b\x92\x47\x0a\x20\x93\xaa\x6b\xce\x05\x95\x2c\x28\x34\x8c\xf4\x3f\xf6\x08\x41\x97\x51\x66\xbb\x40\xed\x23\x40\x04\xb8\x82\x44\x63\xe6\xb0\x09" == rmd<320>("abcdefghijklmnopqrstuvwxyz"));
        assert("\xd0\x34\xa7\x95\x0c\xf7\x22\x02\x1b\xa4\xb8\x4d\xf7\x69\xa5\xde\x20\x60\xe2\x59\xdf\x4c\x9b\xb4\xa4\x26\x8c\x0e\x93\x5b\xbc\x74\x70\xa9\x69\xc9\xd0\x72\xa1\xac" == rmd<320>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert("\xed\x54\x49\x40\xc8\x6d\x67\xf2\x50\xd2\x32\xc3\x0b\x7b\x3e\x57\x70\xe0\xc6\x0c\x8c\xb9\xa4\xca\xfe\x3b\x11\x38\x8a\xf9\x92\x0e\x1b\x99\x23\x0b\x84\x3c\x86\xa4" == rmd<320>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
        assert("\x55\x78\x88\xaf\x5f\x6d\x8e\xd6\x2a\xb6\x69\x45\xc6\xd2\xa0\xa4\x7e\xcd\x53\x41\xe9\x15\xeb\x8f\xea\x1d\x05\x24\x95\x5f\x82\x5d\xc7\x17\xe4\xa0\x08\xab\x2d\x42" == rmd<320>("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
        assert("\xbd\xee\x37\xf4\x37\x1e\x20\x64\x6b\x8b\x0d\x86\x2d\xda\x16\x29\x2a\xe3\x6f\x40\x96\x5e\x8c\x85\x09\xe6\x3d\x1d\xbd\xde\xcc\x50\x3e\x2b\x63\xeb\x92\x45\xbb\x66" == rmd<320>(1000000, 'a'));

        return 0;
    }

#endif
