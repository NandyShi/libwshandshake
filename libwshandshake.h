#ifndef LIBWSHANDSHAKE_H
#define LIBWSHANDSHAKE_H

#include <cstdint>
#include <cstddef>

inline uint32_t lwsh_private_rol(uint32_t value, size_t bits) {return (value << bits) | (value >> (32 - bits));}
inline uint32_t lwsh_private_blk(uint32_t block[16], size_t i) {
    return lwsh_private_rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
}

struct L1 {
    template <int i>
    static inline void f(uint32_t *vec, uint32_t *block) {
        vec[i % 5] += ((vec[(3 + i) % 5] & (vec[(2 + i) % 5] ^ vec[(1 + i) % 5])) ^ vec[(1 + i) % 5]) + block[i] + 0x5a827999 + lwsh_private_rol(vec[(4 + i) % 5], 5);
        vec[(3 + i) % 5] = lwsh_private_rol(vec[(3 + i) % 5], 30);
    }
};

struct L2 {
    template <int in>
    static inline void f(uint32_t *vec, uint32_t *block) {
        int i = in + 1;
        block[i - 1] = lwsh_private_blk(block, i - 1);
        vec[i % 5] += ((vec[(3 + i) % 5] & (vec[(2 + i) % 5] ^ vec[(1 + i) % 5])) ^ vec[(1 + i) % 5]) + block[i - 1] + 0x5a827999 + lwsh_private_rol(vec[(4 + i) % 5], 5);
        vec[(3 + i) % 5] = lwsh_private_rol(vec[(3 + i) % 5], 30);
    }
};

struct L3 {
    template <int i>
    static inline void f(uint32_t *vec, uint32_t *block) {
        block[(i + 4) % 16] = lwsh_private_blk(block, (i + 4) % 16);
        vec[i % 5] += (vec[(3 + i) % 5] ^ vec[(2 + i) % 5] ^ vec[(1 + i) % 5]) + block[(i + 4) % 16] + 0x6ed9eba1 + lwsh_private_rol(vec[(4 + i) % 5], 5);
        vec[(3 + i) % 5] = lwsh_private_rol(vec[(3 + i) % 5], 30);
    }
};

struct L4 {
    template <int i>
    static inline void f(uint32_t *vec, uint32_t *block) {
        block[(i + 8) % 16] = lwsh_private_blk(block, (i + 8) % 16);
        vec[i % 5] += (((vec[(3 + i) % 5] | vec[(2 + i) % 5]) & vec[(1 + i) % 5]) | (vec[(3 + i) % 5] & vec[(2 + i) % 5])) + block[(i + 8) % 16] + 0x8f1bbcdc + lwsh_private_rol(vec[(4 + i) % 5], 5);
        vec[(3 + i) % 5] = lwsh_private_rol(vec[(3 + i) % 5], 30);
    }
};

struct L5 {
    template <int i>
    static inline void f(uint32_t *vec, uint32_t *block) {
        block[(i + 12) % 16] = lwsh_private_blk(block, (i + 12) % 16);
        vec[i % 5] += (vec[(3 + i) % 5] ^ vec[(2 + i) % 5] ^ vec[(1 + i) % 5]) + block[(i + 12) % 16] + 0xca62c1d6 + lwsh_private_rol(vec[(4 + i) % 5], 5);
        vec[(3 + i) % 5] = lwsh_private_rol(vec[(3 + i) % 5], 30);
    }
};

struct L6 {
    template <int i>
    static inline void f(uint32_t *vec, uint32_t *digest) {
        digest[i] += vec[4 - i];
    }
};

template <int N, typename T>
struct static_for {
    void operator()(uint32_t *vec, uint32_t *digest) {
        static_for<N - 1, T>()(vec, digest);
        T::template f<N - 1>(vec, digest);
    }
};

template <typename T>
struct static_for<0, T> {
    void operator()(uint32_t *vec, uint32_t *digest) {}
};

inline void lwsh_private_sha1(uint32_t digest[5], uint32_t block[16]) {
    uint32_t vec[5] = {digest[4], digest[3], digest[2], digest[1], digest[0]};
    static_for<16, L1>()(vec, block);
    static_for<4, L2>()(vec, block);
    static_for<20, L3>()(vec, block);
    static_for<20, L4>()(vec, block);
    static_for<20, L5>()(vec, block);
    static_for<5, L6>()(vec, digest);
}

inline void lwsh_private_base64(unsigned char *src, char *dst)
{
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 18; i += 3) {
        *dst++ = b64[(src[i] >> 2) & 63];
        *dst++ = b64[((src[i] & 3) << 4) | ((src[i + 1] & 240) >> 4)];
        *dst++ = b64[((src[i + 1] & 15) << 2) | ((src[i + 2] & 192) >> 6)];
        *dst++ = b64[src[i + 2] & 63];
    }
    *dst++ = b64[(src[18] >> 2) & 63];
    *dst++ = b64[((src[18] & 3) << 4) | ((src[19] & 240) >> 4)];
    *dst++ = b64[((src[19] & 15) << 2)];
    *dst++ = '=';
}

inline void lwsh_generate(const char input[24], char output[28]) {
    uint32_t block_output[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    uint32_t block_input[16] = {
        0, 0, 0, 0, 0, 0, 0x32353845, 0x41464135, 0x2d453931, 0x342d3437, 0x44412d39,
        0x3543412d, 0x43354142, 0x30444338, 0x35423131, 0x80000000
    };

    for (int i = 0; i < 6; i++) {
        block_input[i] = (input[4 * i + 3] & 0xff) | (input[4 * i + 2] & 0xff) << 8 | (input[4 * i + 1] & 0xff) << 16 | (input[4 * i + 0] & 0xff) << 24;
    }
    lwsh_private_sha1(block_output, block_input);
    uint32_t last_block[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 480};
    lwsh_private_sha1(block_output, last_block);
    for (int i = 0; i < 5; i++) {
        uint32_t tmp = block_output[i];
        char *bytes = (char *) &block_output[i];
        bytes[3] = tmp & 0xff;
        bytes[2] = (tmp >> 8) & 0xff;
        bytes[1] = (tmp >> 16) & 0xff;
        bytes[0] = (tmp >> 24) & 0xff;
    }
    lwsh_private_base64((unsigned char *) block_output, output);
}

#endif // LIBWSHANDSHAKE_H
