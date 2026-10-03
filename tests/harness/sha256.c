#include "sha256.h"

#include <string.h>

static uint32_t rotr(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (32U - bits));
}

static uint32_t load_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

void harness_sha256(const uint8_t *data, size_t length, uint8_t out[32])
{
    static const uint32_t k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
        0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
        0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
        0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
        0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
        0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
        0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
        0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
        0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
        0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    uint8_t block[64];
    size_t offset = 0;
    uint64_t bits = (uint64_t)length * 8U;

    while (offset + 64U <= length) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h;
        size_t i;
        for (i = 0; i < 16U; i++) {
            w[i] = load_be(data + offset + i * 4U);
        }
        for (i = 16; i < 64U; i++) {
            uint32_t s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3);
            uint32_t s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10);
            w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
        }
        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];
        for (i = 0; i < 64U; i++) {
            uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        offset += 64U;
    }

    {
        size_t rem = length - offset;
        size_t i;
        memset(block, 0, sizeof block);
        if (rem != 0U) {
            memcpy(block, data + offset, rem);
        }
        block[rem] = 0x80U;
        if (rem >= 56U) {
            uint32_t w[64];
            uint32_t a, b, c, d, e, f, g, h;
            for (i = 0; i < 16U; i++) {
                w[i] = load_be(block + i * 4U);
            }
            for (i = 16; i < 64U; i++) {
                uint32_t s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3);
                uint32_t s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10);
                w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
            }
            a = state[0]; b = state[1]; c = state[2]; d = state[3];
            e = state[4]; f = state[5]; g = state[6]; h = state[7];
            for (i = 0; i < 64U; i++) {
                uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + s1 + ch + k[i] + w[i];
                uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = s0 + maj;
                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
            memset(block, 0, sizeof block);
        }
        store_be(block + 56, (uint32_t)(bits >> 32));
        store_be(block + 60, (uint32_t)bits);
        {
            uint32_t w[64];
            uint32_t a, b, c, d, e, f, g, h;
            for (i = 0; i < 16U; i++) {
                w[i] = load_be(block + i * 4U);
            }
            for (i = 16; i < 64U; i++) {
                uint32_t s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3);
                uint32_t s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10);
                w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
            }
            a = state[0]; b = state[1]; c = state[2]; d = state[3];
            e = state[4]; f = state[5]; g = state[6]; h = state[7];
            for (i = 0; i < 64U; i++) {
                uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + s1 + ch + k[i] + w[i];
                uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = s0 + maj;
                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }
    }

    for (offset = 0; offset < 8U; offset++) {
        store_be(out + offset * 4U, state[offset]);
    }
}

void harness_sha256_hex(const uint8_t *data, size_t length, char out[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t raw[32];
    size_t i;
    harness_sha256(data, length, raw);
    for (i = 0; i < 32U; i++) {
        out[i * 2U] = hex[raw[i] >> 4];
        out[i * 2U + 1U] = hex[raw[i] & 0x0fU];
    }
    out[64] = '\0';
}
