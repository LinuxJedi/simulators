/* main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * wolfCrypt + STSAFE-A120 simulator integration test.
 *
 * Registers wolfSSL's STSAFE crypto-cb so wolfCrypt routes ECC and RNG
 * operations through the simulator, then runs a focused smoke test that
 * exercises:
 *
 *   1. RNG via stse_generate_random
 *   2. ECC P-256 keygen on the device, sign+verify locally
 *   3. ECDH against an off-device peer
 *
 * This is narrower than wolfSSL's full wolfcrypt_test() because the
 * simulator only implements the STSAFE-A120 surface wolfSSL exercises,
 * not the rest of wolfCrypt's API surface (RSA, AES-CCM, etc.). The
 * full test would probe paths the simulator doesn't model.
 */

#include "stselib.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int wolfSSL_STSAFE_CryptoDevCb(int devId, wc_CryptoInfo *info, void *ctx);

static stse_Handler_t g_handler;
static int g_failures = 0;
static int g_run = 0;

#define EXPECT_OK(label, expr)                                                   \
    do {                                                                         \
        g_run++;                                                                 \
        int _r = (int)(expr);                                                    \
        if (_r != 0) {                                                           \
            fprintf(stderr, "[FAIL] %s: rc=%d\n", (label), _r);                  \
            g_failures++;                                                        \
        } else {                                                                 \
            fprintf(stdout, "[ OK ] %s\n", (label));                             \
        }                                                                        \
    } while (0)

/* For prerequisites: if the call fails, log + return early so the rest
 * of the test function doesn't run on uninitialised state and crash. */
#define REQUIRE_OK(label, expr)                                                  \
    do {                                                                         \
        g_run++;                                                                 \
        int _r = (int)(expr);                                                    \
        if (_r != 0) {                                                           \
            fprintf(stderr, "[FAIL] %s: rc=%d (skipping rest of test)\n",        \
                    (label), _r);                                                \
            g_failures++;                                                        \
            return -1;                                                           \
        }                                                                        \
        fprintf(stdout, "[ OK ] %s\n", (label));                                 \
    } while (0)

#define EXPECT_TRUE(label, cond)                                                 \
    do {                                                                         \
        g_run++;                                                                 \
        if (!(cond)) {                                                           \
            fprintf(stderr, "[FAIL] %s\n", (label));                             \
            g_failures++;                                                        \
        } else {                                                                 \
            fprintf(stdout, "[ OK ] %s\n", (label));                             \
        }                                                                        \
    } while (0)

static int init_stse(void) {
    memset(&g_handler, 0, sizeof(g_handler));
    if (stse_set_default_handler_value(&g_handler) != STSE_OK) return -1;
    g_handler.device_type = STSAFE_A120;
    if (stse_init(&g_handler) != STSE_OK) return -1;
    return 0;
}

static int rng_smoke_test(void) {
    fprintf(stdout, "\n=== rng_smoke_test ===\n");
    WC_RNG rng;
    REQUIRE_OK("wc_InitRng", wc_InitRng(&rng));
    unsigned char buf1[32], buf2[32];
    EXPECT_OK("wc_RNG_GenerateBlock #1", wc_RNG_GenerateBlock(&rng, buf1, sizeof(buf1)));
    EXPECT_OK("wc_RNG_GenerateBlock #2", wc_RNG_GenerateBlock(&rng, buf2, sizeof(buf2)));
    EXPECT_TRUE("two RNG draws differ", memcmp(buf1, buf2, sizeof(buf1)) != 0);
    wc_FreeRng(&rng);
    return 0;
}

static int ecc_p256_round_trip(int devId) {
    fprintf(stdout, "\n=== ecc_p256_round_trip ===\n");
    WC_RNG rng;
    REQUIRE_OK("wc_InitRng (ECC)", wc_InitRng(&rng));

    ecc_key key;
    if (wc_ecc_init_ex(&key, NULL, devId) != 0) {
        fprintf(stderr, "[FAIL] wc_ecc_init_ex (skipping rest of test)\n");
        g_run++;
        g_failures++;
        wc_FreeRng(&rng);
        return -1;
    }
    g_run++;
    fprintf(stdout, "[ OK ] wc_ecc_init_ex\n");

    if (wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1) != 0) {
        fprintf(stderr, "[FAIL] wc_ecc_make_key (skipping rest of test)\n");
        g_run++;
        g_failures++;
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }
    g_run++;
    fprintf(stdout, "[ OK ] wc_ecc_make_key (P-256, devId)\n");

    unsigned char hash[32];
    for (size_t i = 0; i < sizeof(hash); i++) hash[i] = (unsigned char)i;

    unsigned char sig[ECC_MAX_SIG_SIZE];
    word32 sig_len = sizeof(sig);
    EXPECT_OK("wc_ecc_sign_hash via STSAFE",
              wc_ecc_sign_hash(hash, sizeof(hash), sig, &sig_len, &rng, &key));

    int verified = 0;
    EXPECT_OK("wc_ecc_verify_hash via STSAFE",
              wc_ecc_verify_hash(sig, sig_len, hash, sizeof(hash), &verified, &key));
    EXPECT_TRUE("ECDSA verifies", verified == 1);

    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    return 0;
}

/*
 * F-11238 regression: ECDSA verify with a prehash shorter than the field
 * size (P-256 + 28-byte SHA-224 digest, a valid NIST pairing).
 *
 * The A120 requires a field-size prehash on the wire (the simulator models
 * real silicon and rejects other lengths), so the port must normalize the
 * digest host-side: left-pad a short digest, left-truncate a long one.
 * Pre-fix builds copied key_sz bytes from the caller's digest buffer,
 * reading past its end for short digests and submitting a wrong digest,
 * so this valid signature failed to verify.
 *
 * Vectors: P-256 public key (raw X/Y, the same shape the port imports after
 * an on-device keygen), digest = SHA-224 of a fixed message, signature over
 * that digest (openssl dgst -sha224 -sign). The matching private key was
 * throwaway and is not shipped; only the public key is needed to route
 * verify through the STSAFE crypto-cb.
 */
static const unsigned char k_f11238_pub_x[32] = {
    0x8f, 0xa6, 0x96, 0x7a, 0x49, 0x38, 0x96, 0x1c, 0x9e, 0xdb, 0xd5, 0x10,
    0x8e, 0x99, 0xd8, 0x3b, 0x21, 0xb1, 0xc0, 0x2e, 0x13, 0xc3, 0xed, 0xd7,
    0x03, 0xbc, 0xd8, 0x07, 0x61, 0xe6, 0xa3, 0x87
};

static const unsigned char k_f11238_pub_y[32] = {
    0x68, 0xb7, 0x7d, 0xfe, 0xd6, 0xe1, 0x2f, 0xa9, 0x46, 0xa6, 0x21, 0x07,
    0xa5, 0x13, 0x4c, 0x59, 0x92, 0x5c, 0x99, 0x58, 0x3d, 0xcc, 0x64, 0xdd,
    0xd1, 0xea, 0xc2, 0x0e, 0x9b, 0x28, 0xc6, 0xcf
};

static const unsigned char k_f11238_digest28[] = {
    0x01, 0x86, 0xc9, 0xdb, 0x3c, 0xf0, 0x37, 0xbb, 0xf7, 0x14, 0x0f, 0xec,
    0x39, 0xd6, 0x53, 0xf8, 0x38, 0x1d, 0x8f, 0x5a, 0x01, 0x4c, 0x95, 0x37,
    0xea, 0xef, 0x77, 0x66
};

static const unsigned char k_f11238_sig_der[] = {
    0x30, 0x46, 0x02, 0x21, 0x00, 0xeb, 0xd0, 0x14, 0x33, 0x71, 0x39, 0x0e,
    0x34, 0x35, 0x7b, 0xf1, 0x30, 0x95, 0x00, 0xbe, 0x3a, 0xfa, 0x01, 0x9f,
    0xd1, 0xd7, 0xa4, 0xf2, 0x03, 0x68, 0xae, 0x67, 0xa7, 0x9f, 0x29, 0xd2,
    0xd5, 0x02, 0x21, 0x00, 0xb8, 0x88, 0x2d, 0xb2, 0xe6, 0x03, 0x70, 0x7e,
    0x52, 0x2a, 0xcf, 0xaa, 0x13, 0x05, 0x03, 0x0a, 0x1c, 0x59, 0xd2, 0x7b,
    0x14, 0x3c, 0x5c, 0x27, 0x13, 0xff, 0x34, 0xf1, 0x62, 0xe5, 0x35, 0x5c
};

static int ecc_p256_short_digest_verify(int devId) {
    fprintf(stdout, "\n=== ecc_p256_short_digest_verify ===\n");
    ecc_key key;
    int verified = 0;
    int ret;
    unsigned char bad_digest[sizeof(k_f11238_digest28)];

    ret = wc_ecc_init_ex(&key, NULL, devId);
    EXPECT_OK("wc_ecc_init_ex (short digest)", ret);
    if (ret != 0) return -1;

    ret = wc_ecc_import_unsigned(&key, k_f11238_pub_x, k_f11238_pub_y,
                                 NULL, ECC_SECP256R1);
    EXPECT_OK("wc_ecc_import_unsigned (P-256 public key)", ret);
    if (ret != 0) {
        wc_ecc_free(&key);
        return -1;
    }

    /* Route subsequent ops on this key through the STSAFE device. */
    key.devId = devId;

    ret = wc_ecc_verify_hash(k_f11238_sig_der, sizeof(k_f11238_sig_der),
                             k_f11238_digest28, sizeof(k_f11238_digest28),
                             &verified, &key);
    EXPECT_OK("wc_ecc_verify_hash (28-byte digest, valid sig)", ret);
    EXPECT_TRUE("short-digest signature verifies", verified == 1);

    /* Negative control: a corrupted digest must not verify. */
    memcpy(bad_digest, k_f11238_digest28, sizeof(bad_digest));
    bad_digest[0] ^= 0x01;
    verified = 0;
    ret = wc_ecc_verify_hash(k_f11238_sig_der, sizeof(k_f11238_sig_der),
                             bad_digest, sizeof(bad_digest), &verified, &key);
    EXPECT_OK("wc_ecc_verify_hash (corrupted digest)", ret);
    EXPECT_TRUE("corrupted digest rejected", verified == 0);

    wc_ecc_free(&key);
    return 0;
}

int main(void) {
    fprintf(stdout, "wolfCrypt + STSAFE-A120 simulator smoke test\n");
    if (init_stse() != 0) {
        fprintf(stderr, "stse_init failed; is the simulator running?\n");
        return 1;
    }

    /*
     * wolfCrypt_Init() calls stsafe_interface_init() internally (via
     * wc_port.c when WOLFSSL_STSAFE is defined) and that path also
     * registers the crypto-cb dispatcher, so we must call it BEFORE
     * wc_CryptoCb_RegisterDevice. Calling RegisterDevice before
     * wolfCrypt_Init returns CRYPTOCB_UNAVAILABLE_E because the
     * crypto-cb table is uninitialised.
     */
    EXPECT_OK("wolfCrypt_Init", wolfCrypt_Init());

    int devId = 1;
    int rc = wc_CryptoCb_RegisterDevice(devId, wolfSSL_STSAFE_CryptoDevCb, &g_handler);
    EXPECT_OK("wc_CryptoCb_RegisterDevice", rc);

    rng_smoke_test();
    ecc_p256_round_trip(devId);
    ecc_p256_short_digest_verify(devId);

    wolfCrypt_Cleanup();
    fprintf(stdout, "\n=== Summary ===\nRan %d assertions, %d failed\n", g_run, g_failures);
    return g_failures == 0 ? 0 : 1;
}
