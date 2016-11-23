#ifndef WEB_SOCKET_HANDSHAKE_HASH_H_
#define WEB_SOCKET_HANDSHAKE_HASH_H_

#include <cstdint>
#include <cstddef>
#include <algorithm>

struct WebSocketHandshakeHash {
    uint32_t digest[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    uint32_t block[16] = {
        0, 0, 0, 0, 0, 0, 0x32353845, 0x41464135, 0x2d453931, 0x342d3437, 0x44412d39,
        0x3543412d, 0x43354142, 0x30444338, 0x35423131, 0x80000000
    };

    WebSocketHandshakeHash(char input[24], char *output) {
        for (size_t i = 0; i < 6; i++) {
            block[i] = (input[4 * i + 3] & 0xff) | (input[4 * i + 2] & 0xff) << 8 | (input[4 * i + 1] & 0xff) << 16 | (input[4 * i + 0] & 0xff) << 24;
        }
        transform(digest, block);
        static uint32_t lastBlock[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 480 >> 32, 480};
        transform(digest, lastBlock);

        unsigned char *byte = (unsigned char *) digest;
        for (int i = 0; i < 20; ) {
            std::swap(byte[i], byte[i + 3]);
            std::swap(byte[i + 1], byte[i + 2]);
            i += 4;
        }
        base64((unsigned char *) digest, output);
    }

    uint32_t rol(uint32_t value, size_t bits) {return (value << bits) | (value >> (32 - bits));}
    uint32_t blk(uint32_t block[16], size_t i) {
        return rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
    }

    void transform(uint32_t digest[], uint32_t block[16]) {
        uint32_t vec[5] = {digest[4], digest[3], digest[2], digest[1], digest[0]};

        for (int i = 0; i < 16; i++) {
            uint32_t &w = vec[(3 + i) % 5];
            uint32_t y = vec[(1 + i) % 5];
            vec[i % 5] += ((w & (vec[(2 + i) % 5] ^ y)) ^ y) + block[i] + 0x5a827999 + rol(vec[(4 + i) % 5], 5);
            w = rol(w, 30);
        }

        for (int i = 1; i < 5; i++) {
            uint32_t &w = vec[(3 + i) % 5];
            uint32_t y = vec[(1 + i) % 5];
            block[i - 1] = blk(block, i - 1);
            vec[i % 5] += ((w & (vec[(2 + i) % 5] ^ y)) ^ y) + block[i - 1] + 0x5a827999 + rol(vec[(4 + i) % 5], 5);
            w = rol(w, 30);
        }

        for (int i = 0; i < 20; i++) {
            uint32_t &w = vec[(3 + i) % 5];
            uint32_t y = vec[(1 + i) % 5];
            block[(i + 4) % 16] = blk(block, (i + 4) % 16);
            vec[i % 5] += (w ^ vec[(2 + i) % 5] ^ y) + block[(i + 4) % 16] + 0x6ed9eba1 + rol(vec[(4 + i) % 5], 5);
            w = rol(w, 30);
        }

        for (int i = 0; i < 20; i++) {
            uint32_t &w = vec[(3 + i) % 5];
            uint32_t y = vec[(1 + i) % 5];
            uint32_t x = vec[(2 + i) % 5];
            block[(i + 8) % 16] = blk(block, (i + 8) % 16);
            vec[i % 5] += (((w | x) & y) | (w & x)) + block[(i + 8) % 16] + 0x8f1bbcdc + rol(vec[(4 + i) % 5], 5);
            w = rol(w, 30);
        }

        for (int i = 0; i < 20; i++) {
            uint32_t &w = vec[(3 + i) % 5];
            uint32_t y = vec[(1 + i) % 5];
            block[(i + 12) % 16] = blk(block, (i + 12) % 16);
            vec[i % 5] += (w ^ vec[(2 + i) % 5] ^ y) + block[(i + 12) % 16] + 0xca62c1d6 + rol(vec[(4 + i) % 5], 5);
            w = rol(w, 30);
        }

        digest[0] += vec[4];
        digest[1] += vec[3];
        digest[2] += vec[2];
        digest[3] += vec[1];
        digest[4] += vec[0];
    }

    void base64(unsigned char *src, char *dst)
    {
        static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
};

#endif
