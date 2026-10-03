#include "dmp/identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static uint32_t rotr(uint32_t value, unsigned bits)
{
    return (value >> bits) | (value << (32U - bits));
}

static void sha256_block(uint32_t state[8], const uint8_t block[64])
{
    static const uint32_t k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
        0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
        0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
        0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
        0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
        0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned i;
    for (i = 0U; i < 16U; i++) {
        w[i] = ((uint32_t)block[i * 4U] << 24) | ((uint32_t)block[i * 4U + 1U] << 16) |
               ((uint32_t)block[i * 4U + 2U] << 8) | (uint32_t)block[i * 4U + 3U];
    }
    for (i = 16U; i < 64U; i++) {
        uint32_t s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
        uint32_t s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    for (i = 0U; i < 64U; i++) {
        uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + s0 + maj;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static dmp_status sha256_of(void *context, dmp_bytes input, uint8_t output[32])
{
    uint32_t state[8] = { 0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                          0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U };
    uint8_t block[64];
    size_t filled = 0U;
    size_t offset = 0U;
    uint64_t bits;
    unsigned i;
    (void)context;
    if (output == NULL || (input.size != 0U && input.data == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    while (offset < input.size) {
        size_t space = 64U - filled;
        size_t take = input.size - offset;
        if (take > space) {
            take = space;
        }
        memcpy(block + filled, input.data + offset, take);
        filled += take;
        offset += take;
        if (filled == 64U) {
            sha256_block(state, block);
            filled = 0U;
        }
    }
    block[filled++] = 0x80U;
    if (filled > 56U) {
        while (filled < 64U) {
            block[filled++] = 0U;
        }
        sha256_block(state, block);
        filled = 0U;
    }
    while (filled < 56U) {
        block[filled++] = 0U;
    }
    bits = (uint64_t)input.size * 8U;
    for (i = 0U; i < 8U; i++) {
        block[56U + i] = (uint8_t)(bits >> (56U - 8U * i));
    }
    sha256_block(state, block);
    for (i = 0U; i < 8U; i++) {
        output[i * 4U] = (uint8_t)(state[i] >> 24);
        output[i * 4U + 1U] = (uint8_t)(state[i] >> 16);
        output[i * 4U + 2U] = (uint8_t)(state[i] >> 8);
        output[i * 4U + 3U] = (uint8_t)state[i];
    }
    return DMP_OK;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex(const char *text, uint8_t out[32])
{
    unsigned i;
    if (text == NULL) {
        return 0;
    }
    for (i = 0U; i < 32U; i++) {
        int hi = hex_nibble(text[i * 2U]);
        int lo = hex_nibble(text[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return text[64] == '\0';
}

static void print_hex(const uint8_t raw[32])
{
    unsigned i;
    for (i = 0U; i < 32U; i++) {
        (void)printf("%02x", raw[i]);
    }
}

static int gate(int argc, char **argv)
{
    static uint8_t raw_mem[DMP_PROFILE_MAX_BYTES + 2U];
    static uint8_t scratch_mem[DMP_PROFILE_ADMIT_SCRATCH_BYTES];
    uint8_t expected_mem[32];
    const uint8_t *expected = NULL;
    dmp_bytes raw;
    dmp_buffer scratch;
    dmp_admitted_profile profile;
    dmp_profile_failure failure;
    dmp_status status;
    size_t n = 0U;
    FILE *in;
    memset(&profile, 0, sizeof profile);
    memset(&failure, 0, sizeof failure);
    if (argc >= 3 && argv[2][0] != '\0') {
        if (!parse_hex(argv[2], expected_mem)) {
            (void)fprintf(stderr, "expected digest must be 64 hex characters\n");
            return 2;
        }
        expected = expected_mem;
    }
    in = strcmp(argv[1], "-") == 0 ? stdin : fopen(argv[1], "rb");
    if (in == NULL) {
        (void)fprintf(stderr, "cannot read input\n");
        return 2;
    }
    while (n < sizeof raw_mem) {
        size_t got = fread(raw_mem + n, 1U, sizeof raw_mem - n, in);
        n += got;
        if (got == 0U) {
            break;
        }
    }
    if (in != stdin) {
        (void)fclose(in);
    }
    raw.data = n == 0U ? NULL : raw_mem;
    raw.size = n;
    scratch.data = scratch_mem;
    scratch.capacity = sizeof scratch_mem;
    status = dmp_profile_admit(raw, expected, sha256_of, NULL, scratch, &profile, &failure);
    (void)printf("{\"status\":\"%s\",\"code\":\"%s\",\"path\":\"%s\",\"sha256\":\"",
                 dmp_status_name(status), failure.code, failure.path);
    if (status == DMP_OK) {
        print_hex(profile.sha256);
    }
    (void)printf("\"}\n");
    return 0;
}

static int admit_file(const char *path, dmp_admitted_profile *out, dmp_profile_failure *failure,
                      const uint8_t *expected)
{
    FILE *in = fopen(path, "rb");
    static uint8_t raw_mem[DMP_PROFILE_MAX_BYTES + 2U];
    static uint8_t scratch_mem[DMP_PROFILE_ADMIT_SCRATCH_BYTES];
    dmp_bytes raw;
    dmp_buffer scratch;
    size_t n = 0U;
    CHECK(in != NULL);
    while (n < sizeof raw_mem) {
        size_t got = fread(raw_mem + n, 1U, sizeof raw_mem - n, in);
        n += got;
        if (got == 0U) {
            break;
        }
    }
    (void)fclose(in);
    raw.data = raw_mem;
    raw.size = n;
    scratch.data = scratch_mem;
    scratch.capacity = sizeof scratch_mem;
    return dmp_profile_admit(raw, expected, sha256_of, NULL, scratch, out, failure) == DMP_OK ? 0 : 1;
}

static int test_edges(void)
{
    static uint8_t scratch_mem[DMP_PROFILE_ADMIT_SCRATCH_BYTES];
    uint8_t tiny[8];
    dmp_buffer scratch = { scratch_mem, sizeof scratch_mem };
    dmp_buffer small = { tiny, sizeof tiny };
    dmp_admitted_profile profile;
    dmp_profile_failure failure;
    dmp_bytes raw;
    dmp_status status;
    const uint8_t bom[] = { 0xefU, 0xbbU, 0xbfU, '{' };
    const uint8_t brace[] = { '{' };
    char path[512];
    uint8_t wrong[32];

    memset(&profile, 0xa5, sizeof profile);
    memset(&failure, 0xa5, sizeof failure);
    raw.data = NULL;
    raw.size = 0U;
    CHECK(dmp_profile_admit(raw, NULL, NULL, NULL, scratch, &profile, &failure) == DMP_INVALID_ARGUMENT);
    CHECK(((uint8_t *)&profile)[0] == 0xa5U);
    CHECK(dmp_profile_admit(raw, NULL, sha256_of, NULL, scratch, NULL, &failure) == DMP_INVALID_ARGUMENT);
    status = dmp_profile_admit(raw, NULL, sha256_of, NULL, scratch, &profile, &failure);
    CHECK(status == DMP_MALFORMED);
    CHECK(strcmp(failure.code, "encoding") == 0);
    CHECK(strcmp(failure.path, "$") == 0);
    CHECK(((uint8_t *)&profile)[0] == 0xa5U);

    raw.data = brace;
    raw.size = 1U;
    status = dmp_profile_admit(raw, NULL, sha256_of, NULL, scratch, &profile, &failure);
    CHECK(status == DMP_MALFORMED);
    CHECK(strcmp(failure.code, "json") == 0);
    CHECK(strcmp(failure.path, "$") == 0);

    raw.data = bom;
    raw.size = sizeof bom;
    status = dmp_profile_admit(raw, NULL, sha256_of, NULL, scratch, &profile, &failure);
    CHECK(status == DMP_MALFORMED);
    CHECK(strcmp(failure.code, "encoding") == 0);

    raw.data = (const uint8_t *)"{}";
    raw.size = 2U;
    status = dmp_profile_admit(raw, NULL, sha256_of, NULL, small, &profile, &failure);
    CHECK(status == DMP_INVALID_ARGUMENT);
    CHECK(((uint8_t *)&profile)[0] == 0xa5U);
    CHECK(failure.code[0] == 'e' || failure.code[0] == 'j' || failure.code[0] == 0xa5);

    (void)snprintf(path, sizeof path, "%s/tests/profiles/fixtures/direct.json", DMP_SOURCE_DIR);
    memset(&profile, 0, sizeof profile);
    memset(&failure, 0xa5, sizeof failure);
    CHECK(admit_file(path, &profile, &failure, NULL) == 0);
    CHECK(profile.namespace_id == 1U);
    CHECK(profile.node_id[0] == 10U);
    CHECK(profile.node_id[1] == 20U);
    CHECK(profile.default_service == 1U);
    CHECK(profile.service_id[0] == 1U || profile.service_id[1] == 1U);
    CHECK(profile.message_bytes == 64U);
    CHECK(profile.fragments == 4U);
    CHECK(profile.encoded_mtu == 263U);
    CHECK(profile.tx_borrow);
    CHECK(profile.synchronous_completion);
    CHECK(profile.recovery[0] == DMP_PROFILE_RECOVERY_RETRY_ALL);
    CHECK(profile.recovery[1] == DMP_PROFILE_RECOVERY_RETRY_ALL);
    memset(wrong, 0x11, sizeof wrong);
    memset(&profile, 0xa5, sizeof profile);
    {
        FILE *in = fopen(path, "rb");
        static uint8_t raw_mem[DMP_PROFILE_MAX_BYTES];
        size_t n = 0U;
        dmp_bytes body;
        dmp_buffer full = { scratch_mem, sizeof scratch_mem };
        CHECK(in != NULL);
        n = fread(raw_mem, 1U, sizeof raw_mem, in);
        (void)fclose(in);
        body.data = raw_mem;
        body.size = n;
        status = dmp_profile_admit(body, wrong, sha256_of, NULL, full, &profile, &failure);
        CHECK(status == DMP_INTEGRITY_FAILURE);
        CHECK(strcmp(failure.code, "digest") == 0);
        CHECK(strcmp(failure.path, "$") == 0);
        CHECK(((uint8_t *)&profile)[0] == 0xa5U);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        return gate(argc, argv);
    }
    return test_edges();
}
