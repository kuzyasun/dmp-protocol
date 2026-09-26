/*
 * Standalone baseline characterization for the unmodified Noise-C API.
 *
 * All keys and plaintexts below are fixed public test data. This executable
 * characterizes provider limitations; it does not test DMP conformance.
 */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#error "noise_baseline_probe requires strict C11 or newer"
#endif

#include <noise/protocol/cipherstate.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/util.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PACKET_CAPACITY 128U

/* Public test-only key material. Do not use these values in a product. */
static const uint8_t test_key[32] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
    0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
};

static const uint8_t test_aad[] = {
    'D', 'M', 'P', ' ', 'N', 'o', 'i', 's', 'e', ' ', 'p', 'r', 'o', 'b', 'e', 0
};

static int expect_result(const char *label, int observed, int expected)
{
    if (observed != expected) {
        (void)fprintf(stderr,
                      "FAIL: %s: expected error code %d, observed %d\n",
                      label, expected, observed);
        return 0;
    }
    (void)printf("PASS: %s (error code %d)\n", label, observed);
    return 1;
}

static int create_cipher(NoiseCipherState **state)
{
    int err;

    *state = NULL;
    err = noise_cipherstate_new_by_name(state, "ChaChaPoly");
    if (!expect_result("create ChaChaPoly state", err, NOISE_ERROR_NONE))
        return 0;
    if (*state == NULL) {
        (void)fprintf(stderr, "FAIL: ChaChaPoly constructor returned a null state\n");
        return 0;
    }
    if (noise_cipherstate_get_key_length(*state) != sizeof(test_key)) {
        (void)fprintf(stderr, "FAIL: ChaChaPoly key length is not 32 bytes\n");
        return 0;
    }
    err = noise_cipherstate_init_key(*state, test_key, sizeof(test_key));
    return expect_result("initialize ChaChaPoly test key", err, NOISE_ERROR_NONE);
}

static int encrypt_packet(NoiseCipherState *state,
                          uint64_t nonce,
                          const uint8_t *plaintext,
                          size_t plaintext_len,
                          uint8_t packet[PACKET_CAPACITY],
                          size_t *packet_len,
                          const char *label)
{
    NoiseBuffer buffer;
    int err;

    if (plaintext_len > PACKET_CAPACITY ||
        noise_cipherstate_get_mac_length(state) > PACKET_CAPACITY - plaintext_len) {
        (void)fprintf(stderr,
                      "FAIL: plaintext length %zu plus MAC exceeds packet capacity %u\n",
                      plaintext_len, PACKET_CAPACITY);
        return 0;
    }
    (void)memset(packet, 0, PACKET_CAPACITY);
    (void)memcpy(packet, plaintext, plaintext_len);
    err = noise_cipherstate_set_nonce(state, nonce);
    if (!expect_result("set sender nonce", err, NOISE_ERROR_NONE))
        return 0;

    noise_buffer_set_inout(buffer, packet, plaintext_len, PACKET_CAPACITY);
    err = noise_cipherstate_encrypt_with_ad(state, test_aad, sizeof(test_aad), &buffer);
    if (!expect_result(label, err, NOISE_ERROR_NONE))
        return 0;
    if (buffer.size != plaintext_len + noise_cipherstate_get_mac_length(state)) {
        (void)fprintf(stderr,
                      "FAIL: %s: ciphertext length %zu does not equal plaintext plus MAC length\n",
                      label, buffer.size);
        return 0;
    }
    *packet_len = buffer.size;
    return 1;
}

static int encrypt_at_nonce(uint64_t nonce,
                            const uint8_t *plaintext,
                            size_t plaintext_len,
                            uint8_t packet[PACKET_CAPACITY],
                            size_t *packet_len)
{
    NoiseCipherState *state = NULL;
    int ok = 0;

    if (!create_cipher(&state))
        goto done;
    if (!encrypt_packet(state, nonce, plaintext, plaintext_len,
                        packet, packet_len, "encrypt standalone packet"))
        goto done;
    ok = 1;

done:
    if (state != NULL &&
        !expect_result("free standalone sender state",
                       noise_cipherstate_free(state), NOISE_ERROR_NONE))
        ok = 0;
    return ok;
}

static int decrypt_and_check(NoiseCipherState *state,
                             const uint8_t *packet,
                             size_t packet_len,
                             const uint8_t *plaintext,
                             size_t plaintext_len,
                             const char *label)
{
    uint8_t received[PACKET_CAPACITY];
    NoiseBuffer buffer;
    int err;

    if (packet_len > sizeof(received)) {
        (void)fprintf(stderr, "FAIL: %s: packet exceeds local buffer\n", label);
        return 0;
    }
    (void)memcpy(received, packet, packet_len);
    noise_buffer_set_inout(buffer, received, packet_len, packet_len);
    err = noise_cipherstate_decrypt_with_ad(state, test_aad, sizeof(test_aad), &buffer);
    if (!expect_result(label, err, NOISE_ERROR_NONE))
        return 0;
    if (buffer.size != plaintext_len ||
        memcmp(received, plaintext, plaintext_len) != 0) {
        (void)fprintf(stderr,
                      "FAIL: %s: authenticated plaintext length or bytes differ\n",
                      label);
        return 0;
    }
    return 1;
}

static int decrypt_expect_error(NoiseCipherState *state,
                                const uint8_t *packet,
                                size_t packet_len,
                                int expected,
                                const char *label)
{
    uint8_t received[PACKET_CAPACITY];
    NoiseBuffer buffer;
    int err;

    if (packet_len > sizeof(received)) {
        (void)fprintf(stderr, "FAIL: %s: packet exceeds local buffer\n", label);
        return 0;
    }
    (void)memcpy(received, packet, packet_len);
    noise_buffer_set_inout(buffer, received, packet_len, packet_len);
    err = noise_cipherstate_decrypt_with_ad(state, test_aad, sizeof(test_aad), &buffer);
    return expect_result(label, err, expected);
}

static int test_sequential_aead(void)
{
    static const uint8_t plaintext0[] = "public test plaintext, nonce zero";
    static const uint8_t plaintext1[] = "public test plaintext, nonce one";
    uint8_t packet0[PACKET_CAPACITY];
    uint8_t packet1[PACKET_CAPACITY];
    size_t packet0_len = 0;
    size_t packet1_len = 0;
    NoiseCipherState *sender = NULL;
    NoiseCipherState *receiver = NULL;
    int ok = 0;

    if (!create_cipher(&sender) || !create_cipher(&receiver))
        goto done;
    if (!encrypt_packet(sender, 0, plaintext0, sizeof(plaintext0) - 1,
                        packet0, &packet0_len, "encrypt nonce-zero packet with AAD"))
        goto done;
    if (!decrypt_and_check(receiver, packet0, packet0_len,
                           plaintext0, sizeof(plaintext0) - 1,
                           "decrypt nonce-zero packet with AAD"))
        goto done;
    if (!encrypt_packet(sender, 1, plaintext1, sizeof(plaintext1) - 1,
                        packet1, &packet1_len, "encrypt nonce-one packet with AAD"))
        goto done;
    if (!decrypt_and_check(receiver, packet1, packet1_len,
                           plaintext1, sizeof(plaintext1) - 1,
                           "decrypt nonce-one packet with AAD"))
        goto done;
    (void)printf("PASS: sequential ChaChaPoly ciphertext/AAD exchange authenticated both plaintexts\n");
    ok = 1;

done:
    if (sender != NULL &&
        !expect_result("free sequential sender state",
                       noise_cipherstate_free(sender), NOISE_ERROR_NONE))
        ok = 0;
    if (receiver != NULL &&
        !expect_result("free sequential receiver state",
                       noise_cipherstate_free(receiver), NOISE_ERROR_NONE))
        ok = 0;
    return ok;
}

static int test_lower_packet_number(void)
{
    static const uint8_t plaintext2[] = "authentic packet at PN two";
    static const uint8_t plaintext1[] = "authentic packet at PN one";
    uint8_t packet2[PACKET_CAPACITY];
    uint8_t packet1[PACKET_CAPACITY];
    size_t packet2_len = 0;
    size_t packet1_len = 0;
    NoiseCipherState *receiver = NULL;
    NoiseCipherState *lower_receiver = NULL;
    int err;
    int ok = 0;

    if (!encrypt_at_nonce(2, plaintext2, sizeof(plaintext2) - 1,
                          packet2, &packet2_len) ||
        !encrypt_at_nonce(1, plaintext1, sizeof(plaintext1) - 1,
                          packet1, &packet1_len))
        goto done;

    if (!create_cipher(&lower_receiver))
        goto done;
    err = noise_cipherstate_set_nonce(lower_receiver, 1);
    if (!expect_result("select PN one on independent fresh receiver",
                       err, NOISE_ERROR_NONE))
        goto done;
    if (!decrypt_and_check(lower_receiver, packet1, packet1_len,
                           plaintext1, sizeof(plaintext1) - 1,
                           "independently authenticate lower packet PN one"))
        goto done;

    if (!create_cipher(&receiver))
        goto done;
    err = noise_cipherstate_set_nonce(receiver, 2);
    if (!expect_result("select PN two on receiver", err, NOISE_ERROR_NONE))
        goto done;
    if (!decrypt_and_check(receiver, packet2, packet2_len,
                           plaintext2, sizeof(plaintext2) - 1,
                           "authenticate packet PN two"))
        goto done;

    err = noise_cipherstate_set_nonce(receiver, 1);
    if (!expect_result("select lower PN one after authentic PN two",
                       err, NOISE_ERROR_INVALID_NONCE))
        goto done;
    if (!decrypt_expect_error(receiver, packet1, packet1_len,
                              NOISE_ERROR_MAC_FAILURE,
                              "attempt authentic PN one while receiver nonce cannot move backward"))
        goto done;

    (void)printf("NOT SEC-1 CONFORMANT: the public monotonic nonce setter cannot select valid lower PN one after PN two.\n");
    ok = 1;

done:
    if (receiver != NULL &&
        !expect_result("free reordered-PN receiver state",
                       noise_cipherstate_free(receiver), NOISE_ERROR_NONE))
        ok = 0;
    if (lower_receiver != NULL &&
        !expect_result("free independent lower-PN receiver state",
                       noise_cipherstate_free(lower_receiver), NOISE_ERROR_NONE))
        ok = 0;
    return ok;
}

static int test_invalid_high_packet_number(void)
{
    static const uint8_t high_plaintext[] = "authentic packet at PN one hundred";
    static const uint8_t low_plaintext[] = "authentic packet at PN three";
    uint8_t authentic_high[PACKET_CAPACITY];
    uint8_t invalid_high[PACKET_CAPACITY];
    uint8_t lower_packet[PACKET_CAPACITY];
    size_t invalid_high_len = 0;
    size_t lower_packet_len = 0;
    NoiseCipherState *receiver = NULL;
    NoiseCipherState *lower_receiver = NULL;
    int err;
    int ok = 0;

    if (!encrypt_at_nonce(100, high_plaintext, sizeof(high_plaintext) - 1,
                          authentic_high, &invalid_high_len) ||
        !encrypt_at_nonce(3, low_plaintext, sizeof(low_plaintext) - 1,
                          lower_packet, &lower_packet_len))
        goto done;
    if (invalid_high_len == 0) {
        (void)fprintf(stderr, "FAIL: high-PN ciphertext is unexpectedly empty\n");
        goto done;
    }
    (void)memcpy(invalid_high, authentic_high, invalid_high_len);
    invalid_high[invalid_high_len - 1] ^= 0x01U;

    if (!create_cipher(&lower_receiver))
        goto done;
    err = noise_cipherstate_set_nonce(lower_receiver, 3);
    if (!expect_result("select PN three on independent fresh receiver",
                       err, NOISE_ERROR_NONE))
        goto done;
    if (!decrypt_and_check(lower_receiver, lower_packet, lower_packet_len,
                           low_plaintext, sizeof(low_plaintext) - 1,
                           "independently authenticate lower packet PN three"))
        goto done;

    if (!create_cipher(&receiver))
        goto done;
    err = noise_cipherstate_set_nonce(receiver, 100);
    if (!expect_result("install candidate high PN 100", err, NOISE_ERROR_NONE))
        goto done;
    if (!decrypt_expect_error(receiver, invalid_high, invalid_high_len,
                              NOISE_ERROR_MAC_FAILURE,
                              "reject corrupted MAC at candidate PN 100"))
        goto done;
    err = noise_cipherstate_set_nonce(receiver, 3);
    if (!expect_result("select lower PN three after failed PN 100 authentication",
                       err, NOISE_ERROR_INVALID_NONCE))
        goto done;
    if (!decrypt_expect_error(receiver, lower_packet, lower_packet_len,
                              NOISE_ERROR_MAC_FAILURE,
                              "attempt authentic PN three while nonce remains at high PN"))
        goto done;

    if (!decrypt_and_check(receiver, authentic_high, invalid_high_len,
                           high_plaintext, sizeof(high_plaintext) - 1,
                           "authenticate original PN 100 after failed MAC without resetting nonce"))
        goto done;

    (void)printf("NOT SEC-1 CONFORMANT: after failed high-PN authentication, the monotonic setter still cannot select valid lower PN three.\n");
    ok = 1;

done:
    if (receiver != NULL &&
        !expect_result("free invalid-high receiver state",
                       noise_cipherstate_free(receiver), NOISE_ERROR_NONE))
        ok = 0;
    if (lower_receiver != NULL &&
        !expect_result("free independent lower-PN receiver state",
                       noise_cipherstate_free(lower_receiver), NOISE_ERROR_NONE))
        ok = 0;
    return ok;
}

static int all_zero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

static int test_x25519_public_key_edges(void)
{
    static const uint8_t private_key[32] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
    };
    uint8_t zero_public[32] = {0};
    uint8_t low_order_one[32] = {1};
    uint8_t zero_shared[32];
    uint8_t low_order_shared[32];
    NoiseDHState *private_state = NULL;
    NoiseDHState *public_state = NULL;
    int err;
    int ok = 0;

    err = noise_dhstate_new_by_name(&private_state, "25519");
    if (!expect_result("create X25519 private state", err, NOISE_ERROR_NONE) ||
        private_state == NULL)
        goto done;
    err = noise_dhstate_new_by_name(&public_state, "25519");
    if (!expect_result("create X25519 public state", err, NOISE_ERROR_NONE) ||
        public_state == NULL)
        goto done;
    err = noise_dhstate_set_keypair_private(private_state,
                                            private_key, sizeof(private_key));
    if (!expect_result("install X25519 test private key", err, NOISE_ERROR_NONE))
        goto done;

    err = noise_dhstate_set_public_key(public_state,
                                       zero_public, sizeof(zero_public));
    if (!expect_result("install literal-zero X25519 public key",
                       err, NOISE_ERROR_NONE))
        goto done;
    (void)memset(zero_shared, 0xA5, sizeof(zero_shared));
    err = noise_dhstate_calculate(private_state, public_state,
                                  zero_shared, sizeof(zero_shared));
    if (!expect_result("calculate with literal-zero X25519 public key",
                       err, NOISE_ERROR_NONE))
        goto done;
    if (!all_zero(zero_shared, sizeof(zero_shared))) {
        (void)fprintf(stderr,
                      "FAIL: literal-zero X25519 public key did not yield an all-zero shared secret\n");
        goto done;
    }

    err = noise_dhstate_set_public_key(public_state,
                                       low_order_one, sizeof(low_order_one));
    if (!expect_result("install X25519 low-order u=1 public key",
                       err, NOISE_ERROR_NONE))
        goto done;
    (void)memset(low_order_shared, 0xA5, sizeof(low_order_shared));
    err = noise_dhstate_calculate(private_state, public_state,
                                  low_order_shared, sizeof(low_order_shared));
    if (!expect_result("calculate with X25519 low-order u=1 public key",
                       err, NOISE_ERROR_INVALID_PARAM))
        goto done;

    (void)printf("NOT SEC-1 CONFORMANT: SEC-1 requires rejecting all-zero X25519 shared results; literal zero maps to Noise null-key success, while libsodium rejects low-order u=1.\n");
    ok = 1;

done:
    if (private_state != NULL &&
        !expect_result("free X25519 private state",
                       noise_dhstate_free(private_state), NOISE_ERROR_NONE))
        ok = 0;
    if (public_state != NULL &&
        !expect_result("free X25519 public state",
                       noise_dhstate_free(public_state), NOISE_ERROR_NONE))
        ok = 0;
    return ok;
}

int main(void)
{
    if (!expect_result("initialize Noise framework",
                       noise_init_framework(), NOISE_ERROR_NONE))
        return 1;

    (void)printf("EXPECTED-LIMITATION BASELINE ONLY; NOT A DMP CONFORMANCE TEST.\n");
    if (!test_sequential_aead() ||
        !test_lower_packet_number() ||
        !test_invalid_high_packet_number() ||
        !test_x25519_public_key_edges())
        return 1;

    (void)printf("Baseline characterization completed with expected results.\n");
    return 0;
}
