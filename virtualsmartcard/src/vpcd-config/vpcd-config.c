/*
 * Copyright (C) 2014 Frank Morgner
 *
 * This file is part of virtualsmartcard.
 *
 * virtualsmartcard is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * virtualsmartcard is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * virtualsmartcard.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "vpcd.h"

static int read_file_line(const char *path, char *out, size_t cap);
static int write_file_line(const char *path, const char *value);

static int persist_pairing_id(const char *id);
static int load_pairing_id(char *out, size_t cap);
static int persist_device_id(const char *id);
static int delete_key_file(const char *filename);
static int clear_session_state(void);

#ifdef _WIN32
#define VICC_MAX_SLOTS 1
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define VICC_MAX_SLOTS VPCDSLOTS
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#endif

#define ERROR_STRING            "Unable to guess local IP address"
#define DEFAULT_HANDSHAKE_HOST  "middlepoint.test"
#define DEFAULT_HANDSHAKE_PORT  "80"
#define DEFAULT_KEY_DIR         ".config/vpcd"
#define PRIVATE_KEY_FILE        "vpcd_x25519_private.pem"
#define PUBLIC_KEY_FILE         "vpcd_x25519_public.hex"
#define QR_SECRET_FILE          "vpcd_qr_secret.hex"
#define SHARED_SECRET_FILE      "vpcd_shared_secret.hex"
#define PAIRING_ID_FILE         "vpcd_pairing_id.hex"
#define DEVICE_ID_FILE          "vpcd_device_id.hex"
#define ENV_FILE                "vpcd_env.sh"

static char device_id[64];
static char pairing_id[64];
static char public_key_hex[128];
static char qr_secret[64];
static char shared_secret_hex[128];

#define SPAKE2PLUS_CONTEXT               "vsmartcard-spake2plus-v1"
#define SPAKE2PLUS_CIPHERSUITE           "P-256-SHA256-HKDF-HMAC-SHA256"
#define SPAKE2PLUS_REGISTRATION_INFO     "vsmartcard-spake2plus-registration-v1"
#define SPAKE2PLUS_CONFIRMATION_INFO     "ConfirmationKeys"
#define SPAKE2PLUS_SHARED_KEY_INFO       "SharedKey"
#define SPAKE2PLUS_POINT_LEN             33
#define SPAKE2PLUS_SCALAR_LEN            32
#define SPAKE2PLUS_REG_HALF_LEN          40
#define SPAKE2PLUS_REG_OUTPUT_LEN        (SPAKE2PLUS_REG_HALF_LEN * 2)
#define SPAKE2PLUS_TRANSCRIPT_CAP        1024
#define SPAKE2PLUS_P256_M_HEX            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
#define SPAKE2PLUS_P256_N_HEX            "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

#ifdef _WIN32
static int wsa_started = 0;
#endif



#ifdef HAVE_QRENCODE

#include "qransi.c"


void print_qrcode(const char *uri)
{
    qransi (uri);
}

#else

#define QR_SERVICE_URL "https://api.qrserver.com/v1/create-qr-code/?data="

#ifdef _WIN32

#define IE_PATH "\"C:\\Program Files\\Internet Explorer\\IExplore.exe\" "
void print_qrcode(const char *uri)
{
    char command[512];
    if (snprintf(command, sizeof command, "%s%s%s", IE_PATH, QR_SERVICE_URL, uri) < 0)
        return;
    command[(sizeof command) - 1] = '\0';
    system(command);
}

#else

void print_qrcode(const char *uri)
{
    printf("%s%s\n", QR_SERVICE_URL, uri);
}

#endif

#endif

static void trim_newline(char *s)
{
    size_t n;
    if (!s)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_cap, size_t *out_len)
{
    size_t len;
    if (!hex || !out)
        return -1;
    len = strlen(hex);
    if ((len % 2) != 0)
        return -1;
    if ((len / 2) > out_cap)
        return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_nibble((unsigned char) hex[i * 2]);
        int lo = hex_nibble((unsigned char) hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char) ((hi << 4) | lo);
    }
    if (out_len)
        *out_len = len / 2;
    return 0;
}

static int bytes_to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_cap)
{
    static const char hex[] = "0123456789abcdef";
    if (!in || !out)
        return -1;
    if (out_cap < (in_len * 2 + 1))
        return -1;
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
    return 0;
}

static int extract_json_string(const char *json, const char *key, char *out, size_t cap)
{
    char pattern[64];
    const char *p = NULL;
    const char *end = NULL;
    size_t len;

    if (!json || !key || !out || cap == 0)
        return -1;

    if (snprintf(pattern, sizeof pattern, "\"%s\"", key) < 0)
        return -1;
    p = strstr(json, pattern);
    if (!p)
        return -1;
    p += strlen(pattern);
    while (*p && *p != ':')
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p && isspace((unsigned char) *p))
        p++;
    if (*p != '"')
        return -1;
    p++;
    end = strchr(p, '"');
    if (!end)
        return -1;
    len = (size_t) (end - p);
    if (len + 1 > cap)
        return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static int extract_kv_string(const char *s, const char *key, char *out, size_t cap)
{
    size_t key_len;
    const char *p;

    if (!s || !key || !out || cap == 0)
        return -1;
    key_len = strlen(key);
    if (key_len == 0)
        return -1;

    p = s;
    while (*p) {
        const char *k = strstr(p, key);
        if (!k)
            return -1;
        if (k != s) {
            char prev = k[-1];
            if (prev != '&' && prev != ';' && prev != ',' && prev != ' ' && prev != '{')
                goto next;
        }
        k += key_len;
        if (*k != '=')
            goto next;
        k++;
        const char *end = k;
        while (*end && *end != '&' && *end != ';' && *end != ',')
            end++;
        size_t len = (size_t) (end - k);
        if (len + 1 > cap)
            return -1;
        memcpy(out, k, len);
        out[len] = '\0';
        return 0;
next:
        p = k;
    }
    return -1;
}

static int extract_pairing_fields(const char *json,
                                  char *mac_hex, size_t mac_cap,
                                  char *pubkey_hex, size_t pubkey_cap)
{
    char payload[512];

    if (extract_json_string(json, "mac", mac_hex, mac_cap) == 0 &&
        extract_json_string(json, "pubKeyApp", pubkey_hex, pubkey_cap) == 0) {
        return 0;
    }

    if (extract_json_string(json, "payload", payload, sizeof payload) == 0) {
        if (extract_kv_string(payload, "mac", mac_hex, mac_cap) == 0 &&
            extract_kv_string(payload, "pubKeyApp", pubkey_hex, pubkey_cap) == 0) {
            return 0;
        }
    }

    return -1;
}

static int random_u64(uint64_t *out)
{
    if (!out)
        return -1;

    /* Cryptographic RNG. Do not fall back to time/pid. */
    if (RAND_bytes((unsigned char *) out, (int) sizeof(*out)) != 1)
        return -1;
    return 0;
}

static int generate_random_id(char *out, size_t cap)
{
    uint64_t r1 = 0, r2 = 0;
    if (random_u64(&r1) != 0 || random_u64(&r2) != 0)
        return -1;
    if (snprintf(out, cap, "%016llx%016llx",
                 (unsigned long long) r1, (unsigned long long) r2) < 0)
        return -1;
    return 0;
}

static const char *key_dir_path(char *buf, size_t cap)
{
    const char *env = getenv("VPCD_KEY_DIR");
    if (env && *env)
        return env;

#ifndef _WIN32
    if (geteuid() == 0) {
        return "/etc/vpcd";
    }
#endif

    const char *base = getenv("HOME");
    if (base && *base && buf && cap > 0) {
        snprintf(buf, cap, "%s/%s", base, DEFAULT_KEY_DIR);
        return buf;
    }
    return DEFAULT_KEY_DIR;
}

static int persist_shared_secret(const char *hex)
{
    char dir_buf[512];
    char secret_path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    FILE *f = NULL;

#ifndef _WIN32
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create key dir: %s\n", dir);
        return -1;
    }
#endif

    if (snprintf(secret_path, sizeof secret_path, "%s/%s", dir, SHARED_SECRET_FILE) < 0)
        return -1;

    f = fopen(secret_path, "w");
    if (!f) {
        fprintf(stderr, "Failed to write shared secret: %s\n", secret_path);
        return -1;
    }
    fprintf(f, "%s\n", hex);
    fclose(f);
#ifndef _WIN32
    chmod(secret_path, 0600);
#endif
    return 0;
}

static int load_private_key(EVP_PKEY **out)
{
    char dir_buf[512];
    char priv_path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    FILE *f = NULL;
    EVP_PKEY *pkey = NULL;

    if (!out)
        return -1;
    *out = NULL;

    if (snprintf(priv_path, sizeof priv_path, "%s/%s", dir, PRIVATE_KEY_FILE) < 0)
        return -1;

    f = fopen(priv_path, "r");
    if (!f) {
        fprintf(stderr, "Failed to open private key: %s\n", priv_path);
        return -1;
    }
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "Failed to read private key: %s\n", priv_path);
        return -1;
    }
    *out = pkey;
    return 0;
}

static int derive_shared_secret_hex(const unsigned char *peer_pub, size_t peer_pub_len,
                                    char *out_hex, size_t out_cap)
{
    EVP_PKEY *priv = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[64];
    size_t secret_len = 0;
    int rc = -1;

    if (!peer_pub || !out_hex)
        return -1;
    if (peer_pub_len != 32) {
        fprintf(stderr, "pubKeyApp length invalid (expected 32 bytes)\n");
        return -1;
    }

    if (load_private_key(&priv) != 0)
        return -1;

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, peer_pub_len);
    if (!peer) {
        fprintf(stderr, "Failed to load pubKeyApp\n");
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        fprintf(stderr, "Failed to init key derivation\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0 || secret_len > sizeof secret) {
        fprintf(stderr, "Failed to size shared secret\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
        fprintf(stderr, "Failed to derive shared secret\n");
        goto cleanup;
    }

    if (bytes_to_hex(secret, secret_len, out_hex, out_cap) != 0) {
        fprintf(stderr, "Shared secret buffer too small\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (peer)
        EVP_PKEY_free(peer);
    if (priv)
        EVP_PKEY_free(priv);
    OPENSSL_cleanse(secret, sizeof secret);
    return rc;
}

static int mac_matches(const unsigned char *mac, size_t mac_len,
                       const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len)
{
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    if (!mac || !key || !data)
        return -1;

    if (!HMAC(EVP_sha256(), key, (int) key_len, data, data_len, hmac, &hmac_len)) {
        fprintf(stderr, "Failed to compute HMAC\n");
        return -1;
    }

    if (mac_len != (size_t) hmac_len || CRYPTO_memcmp(mac, hmac, hmac_len) != 0)
        return -1;

    return 0;
}

static int verify_mac_hex(const char *mac_hex,
                          const char *qr_secret_str,
                          const unsigned char *pubkey,
                          size_t pubkey_len,
                          const char *pubkey_hex)
{
    unsigned char mac_bytes[EVP_MAX_MD_SIZE];
    size_t mac_len = 0;
    unsigned char key_bytes[64];
    size_t key_len = 0;
    const unsigned char *key_raw = (const unsigned char *) qr_secret_str;
    size_t key_raw_len = qr_secret_str ? strlen(qr_secret_str) : 0;
    int key_is_hex = 0;

    if (!mac_hex || !qr_secret_str || !pubkey || !pubkey_hex)
        return -1;

    if (hex_to_bytes(mac_hex, mac_bytes, sizeof mac_bytes, &mac_len) != 0) {
        fprintf(stderr, "MAC is not valid hex\n");
        return -1;
    }

    if (hex_to_bytes(qr_secret_str, key_bytes, sizeof key_bytes, &key_len) == 0 && key_len > 0)
        key_is_hex = 1;

    /* Try MAC with hex-decoded key (preferred) and raw key as fallback.
     * Try data as raw pubkey bytes first, then hex string if needed. */
    if (key_is_hex) {
        if (mac_matches(mac_bytes, mac_len, key_bytes, key_len, pubkey, pubkey_len) == 0)
            return 0;
        if (mac_matches(mac_bytes, mac_len, key_bytes, key_len,
                        (const unsigned char *) pubkey_hex, strlen(pubkey_hex)) == 0)
            return 0;
    }

    if (key_raw_len > 0) {
        if (mac_matches(mac_bytes, mac_len, key_raw, key_raw_len, pubkey, pubkey_len) == 0)
            return 0;
        if (mac_matches(mac_bytes, mac_len, key_raw, key_raw_len,
                        (const unsigned char *) pubkey_hex, strlen(pubkey_hex)) == 0)
            return 0;
    }

    fprintf(stderr, "MAC verification failed\n");
    return -1;
}

static int recv_json_line(SOCKET sock, char *out, size_t cap)
{
    size_t used = 0;
    if (!out || cap == 0)
        return -1;

    while (used < cap - 1) {
        char c = 0;
        int n = recv(sock, &c, 1, 0);
        if (n <= 0)
            break;
        if (c == '\n')
            break;
        out[used++] = c;
    }

    out[used] = '\0';
    if (used == 0)
        return -1;
    return 0;
}

static int append_bytes(unsigned char *buf, size_t cap, size_t *used,
                        const unsigned char *data, size_t data_len)
{
    if (!buf || !used)
        return -1;
    if (*used > cap || data_len > (cap - *used))
        return -1;
    if (data_len > 0 && data)
        memcpy(buf + *used, data, data_len);
    *used += data_len;
    return 0;
}

static int append_u64_le(unsigned char *buf, size_t cap, size_t *used, size_t value)
{
    unsigned char le[8];
    for (size_t i = 0; i < sizeof le; i++) {
        le[i] = (unsigned char) (value & 0xff);
        value >>= 8;
    }
    return append_bytes(buf, cap, used, le, sizeof le);
}

static int append_len_prefixed(unsigned char *buf, size_t cap, size_t *used,
                               const unsigned char *data, size_t data_len)
{
    if (append_u64_le(buf, cap, used, data_len) != 0)
        return -1;
    return append_bytes(buf, cap, used, data, data_len);
}

static int hmac_sha256_bytes(const unsigned char *key, size_t key_len,
                             const unsigned char *data, size_t data_len,
                             unsigned char *out, size_t out_cap, size_t *out_len)
{
    unsigned int hmac_len = 0;

    if (!key || !out)
        return -1;
    if (!HMAC(EVP_sha256(), key, (int) key_len, data, data_len, out, &hmac_len))
        return -1;
    if (out_cap < hmac_len)
        return -1;
    if (out_len)
        *out_len = hmac_len;
    return 0;
}

static int hkdf_sha256(const unsigned char *salt, size_t salt_len,
                       const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len)
{
    unsigned char zero_salt[SHA256_DIGEST_LENGTH];
    unsigned char prk[SHA256_DIGEST_LENGTH];
    unsigned char prev[SHA256_DIGEST_LENGTH];
    size_t prk_len = 0, prev_len = 0, used = 0;
    unsigned char counter = 1;
    int rc = -1;

    memset(zero_salt, 0, sizeof zero_salt);
    memset(prk, 0, sizeof prk);
    memset(prev, 0, sizeof prev);

    if (!ikm || !out)
        return -1;

    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof zero_salt;
    }

    if (hmac_sha256_bytes(salt, salt_len, ikm, ikm_len, prk, sizeof prk, &prk_len) != 0)
        goto cleanup;

    while (used < out_len) {
        unsigned char input[SHA256_DIGEST_LENGTH + 128];
        unsigned char block[SHA256_DIGEST_LENGTH];
        size_t input_len = 0;
        size_t block_len = 0;
        size_t chunk = 0;

        if (prev_len > 0) {
            memcpy(input + input_len, prev, prev_len);
            input_len += prev_len;
        }
        if (info && info_len > 0) {
            if (input_len + info_len > sizeof input)
                goto cleanup;
            memcpy(input + input_len, info, info_len);
            input_len += info_len;
        }
        if (input_len + 1 > sizeof input)
            goto cleanup;
        input[input_len++] = counter++;

        if (hmac_sha256_bytes(prk, prk_len, input, input_len, block, sizeof block, &block_len) != 0)
            goto cleanup;

        chunk = block_len;
        if (chunk > (out_len - used))
            chunk = out_len - used;
        memcpy(out + used, block, chunk);
        used += chunk;

        memcpy(prev, block, block_len);
        prev_len = block_len;
        OPENSSL_cleanse(block, sizeof block);
        OPENSSL_cleanse(input, sizeof input);
    }

    rc = 0;

cleanup:
    OPENSSL_cleanse(zero_salt, sizeof zero_salt);
    OPENSSL_cleanse(prk, sizeof prk);
    OPENSSL_cleanse(prev, sizeof prev);
    return rc;
}

static int digest_sha256(const unsigned char *data, size_t data_len,
                         unsigned char *out, size_t out_cap)
{
    unsigned int md_len = 0;

    if (!out || out_cap < SHA256_DIGEST_LENGTH)
        return -1;
    if (EVP_Digest(data, data_len, out, &md_len, EVP_sha256(), NULL) != 1)
        return -1;
    return md_len == SHA256_DIGEST_LENGTH ? 0 : -1;
}

static int reduce_scalar_mod_order(const BIGNUM *order,
                                   const unsigned char *in, size_t in_len,
                                   unsigned char *out, size_t out_len)
{
    BIGNUM *src = NULL;
    BIGNUM *reduced = NULL;
    BN_CTX *bn_ctx = NULL;
    int rc = -1;

    if (!order || !in || !out || out_len != SPAKE2PLUS_SCALAR_LEN)
        return -1;

    src = BN_bin2bn(in, (int) in_len, NULL);
    reduced = BN_new();
    bn_ctx = BN_CTX_new();
    if (!src || !reduced || !bn_ctx)
        goto cleanup;

    if (BN_mod(reduced, src, order, bn_ctx) != 1)
        goto cleanup;
    if (BN_bn2binpad(reduced, out, (int) out_len) != (int) out_len)
        goto cleanup;

    rc = 0;

cleanup:
    BN_clear_free(src);
    BN_clear_free(reduced);
    BN_CTX_free(bn_ctx);
    return rc;
}

static int ec_point_from_hex(const EC_GROUP *group, const char *hex, EC_POINT *point, BN_CTX *bn_ctx)
{
    unsigned char buf[SPAKE2PLUS_POINT_LEN];
    size_t len = 0;

    if (!group || !hex || !point)
        return -1;
    if (hex_to_bytes(hex, buf, sizeof buf, &len) != 0 || len != SPAKE2PLUS_POINT_LEN)
        return -1;
    if (EC_POINT_oct2point(group, point, buf, len, bn_ctx) != 1)
        return -1;
    if (EC_POINT_is_at_infinity(group, point) == 1)
        return -1;
    if (EC_POINT_is_on_curve(group, point, bn_ctx) != 1)
        return -1;
    return 0;
}

static int ec_point_from_octets(const EC_GROUP *group,
                                const unsigned char *octets, size_t octets_len,
                                EC_POINT *point, BN_CTX *bn_ctx)
{
    if (!group || !octets || !point)
        return -1;
    if (EC_POINT_oct2point(group, point, octets, octets_len, bn_ctx) != 1)
        return -1;
    if (EC_POINT_is_at_infinity(group, point) == 1)
        return -1;
    if (EC_POINT_is_on_curve(group, point, bn_ctx) != 1)
        return -1;
    return 0;
}

static int ec_point_to_octets(const EC_GROUP *group, const EC_POINT *point,
                              unsigned char *out, size_t out_cap, size_t *out_len,
                              BN_CTX *bn_ctx)
{
    size_t len = 0;

    if (!group || !point || !out || out_cap < SPAKE2PLUS_POINT_LEN)
        return -1;
    if (EC_POINT_is_at_infinity(group, point) == 1)
        return -1;

    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, out, out_cap, bn_ctx);
    if (len != SPAKE2PLUS_POINT_LEN)
        return -1;
    if (out_len)
        *out_len = len;
    return 0;
}

static int spake2plus_send_json_line(SOCKET sock, const char *json)
{
    size_t total = 0;
    size_t len = 0;

    if (!json)
        return -1;
    len = strlen(json);
    while (total < len) {
        int n = send(sock, json + total, (int) (len - total), 0);
        if (n <= 0)
            return -1;
        total += (size_t) n;
    }
    return 0;
}

static int spake2plus_wait_status_ok(SOCKET sock)
{
    char response[512];
    const char *p = NULL;

    while (recv_json_line(sock, response, sizeof response) == 0) {
        p = strstr(response, "\"status_code\"");
        if (!p)
            continue;
        p = strchr(p, ':');
        if (!p)
            return -1;
        p++;
        while (*p && isspace((unsigned char) *p))
            p++;
        errno = 0;
        long code = strtol(p, NULL, 10);
        if (errno != 0 || code != 200)
            return -1;
        return 0;
    }
    return -1;
}

static int extract_spake2plus_fields(const char *json,
                                     char *source_id, size_t source_cap,
                                     char *sharep_hex, size_t sharep_cap)
{
    char payload[512];

    if (!json || !source_id || !sharep_hex)
        return -1;

    if (extract_json_string(json, "source_id", source_id, source_cap) != 0)
        return -1;

    if (extract_json_string(json, "shareP", sharep_hex, sharep_cap) == 0)
        return 0;

    if (extract_json_string(json, "payload", payload, sizeof payload) == 0) {
        if (extract_kv_string(payload, "shareP", sharep_hex, sharep_cap) == 0)
            return 0;
    }

    return -1;
}

static int handle_pairing_message(SOCKET sock, const char *json, const char *qr_secret_str,
                                  char *out_shared_hex, size_t out_cap)
{
    unsigned char qr_secret_bytes[64];
    unsigned char registration_input[256];
    unsigned char registration_salt[256];
    unsigned char expanded[SPAKE2PLUS_REG_OUTPUT_LEN];
    unsigned char w0[SPAKE2PLUS_SCALAR_LEN];
    unsigned char w1[SPAKE2PLUS_SCALAR_LEN];
    unsigned char sharep_octets[SPAKE2PLUS_POINT_LEN];
    unsigned char sharev_octets[SPAKE2PLUS_POINT_LEN];
    unsigned char z_octets[SPAKE2PLUS_POINT_LEN];
    unsigned char v_octets[SPAKE2PLUS_POINT_LEN];
    unsigned char transcript[SPAKE2PLUS_TRANSCRIPT_CAP];
    unsigned char k_main[SHA256_DIGEST_LENGTH];
    unsigned char confirmation_keys[SHA256_DIGEST_LENGTH * 2];
    unsigned char k_shared[SHA256_DIGEST_LENGTH];
    unsigned char confirm_v[SHA256_DIGEST_LENGTH];
    unsigned char confirm_p[SHA256_DIGEST_LENGTH];
    unsigned char confirm_p_expected[SHA256_DIGEST_LENGTH];
    size_t qr_secret_len = 0;
    size_t sharep_len = 0, sharev_len = 0, z_len = 0, v_len = 0;
    size_t reg_input_used = 0, reg_salt_used = 0, transcript_used = 0;
    size_t confirm_v_len = 0;
    size_t confirm_p_len = 0;
    char id_prover[128];
    char id_prover_confirm[128];
    char sharep_hex[256];
    char sharev_hex[256];
    char confirmv_hex[256];
    char confirmp_hex[256];
    char payload[768];
    char request[1024];
    char response[512];
    char kshared_hex[128];
    EC_GROUP *group = NULL;
    EC_POINT *m_point = NULL;
    EC_POINT *n_point = NULL;
    EC_POINT *sharep_point = NULL;
    EC_POINT *l_point = NULL;
    EC_POINT *sharev_point = NULL;
    EC_POINT *w0m_point = NULL;
    EC_POINT *tmp_point = NULL;
    EC_POINT *z_point = NULL;
    EC_POINT *v_point = NULL;
    BIGNUM *order = NULL;
    BIGNUM *w0_bn = NULL;
    BIGNUM *w1_bn = NULL;
    BIGNUM *y_bn = NULL;
    BN_CTX *bn_ctx = NULL;
    int rc = -1;

    if (sock == INVALID_SOCKET || !json || !qr_secret_str)
        return -1;
    if (out_shared_hex && out_cap > 0)
        out_shared_hex[0] = '\0';

    if (extract_spake2plus_fields(json, id_prover, sizeof id_prover,
                                  sharep_hex, sizeof sharep_hex) != 0) {
        fprintf(stderr, "Pairing message missing source_id/shareP\n");
        goto cleanup;
    }

    if (hex_to_bytes(qr_secret_str, qr_secret_bytes, sizeof qr_secret_bytes, &qr_secret_len) != 0 ||
        qr_secret_len == 0) {
        fprintf(stderr, "qr_secret is not valid hex\n");
        goto cleanup;
    }

    if (hex_to_bytes(sharep_hex, sharep_octets, sizeof sharep_octets, &sharep_len) != 0 ||
        sharep_len != SPAKE2PLUS_POINT_LEN) {
        fprintf(stderr, "shareP is not valid compressed P-256 hex\n");
        goto cleanup;
    }

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bn_ctx = BN_CTX_new();
    order = BN_new();
    m_point = EC_POINT_new(group);
    n_point = EC_POINT_new(group);
    sharep_point = EC_POINT_new(group);
    l_point = EC_POINT_new(group);
    sharev_point = EC_POINT_new(group);
    w0m_point = EC_POINT_new(group);
    tmp_point = EC_POINT_new(group);
    z_point = EC_POINT_new(group);
    v_point = EC_POINT_new(group);
    w0_bn = BN_new();
    w1_bn = BN_new();
    y_bn = BN_new();
    if (!group || !bn_ctx || !order || !m_point || !n_point || !sharep_point ||
        !l_point || !sharev_point || !w0m_point || !tmp_point || !z_point ||
        !v_point || !w0_bn || !w1_bn || !y_bn) {
        fprintf(stderr, "Failed to initialize SPAKE2+ verifier state\n");
        goto cleanup;
    }

    if (EC_GROUP_get_order(group, order, bn_ctx) != 1)
        goto cleanup;
    if (ec_point_from_hex(group, SPAKE2PLUS_P256_M_HEX, m_point, bn_ctx) != 0)
        goto cleanup;
    if (ec_point_from_hex(group, SPAKE2PLUS_P256_N_HEX, n_point, bn_ctx) != 0)
        goto cleanup;
    if (ec_point_from_octets(group, sharep_octets, sharep_len, sharep_point, bn_ctx) != 0) {
        fprintf(stderr, "shareP failed group membership checks\n");
        goto cleanup;
    }

    if (append_len_prefixed(registration_input, sizeof registration_input, &reg_input_used,
                            qr_secret_bytes, qr_secret_len) != 0 ||
        append_len_prefixed(registration_input, sizeof registration_input, &reg_input_used,
                            (const unsigned char *) id_prover, strlen(id_prover)) != 0 ||
        append_len_prefixed(registration_input, sizeof registration_input, &reg_input_used,
                            (const unsigned char *) pairing_id, strlen(pairing_id)) != 0) {
        fprintf(stderr, "SPAKE2+ registration input overflow\n");
        goto cleanup;
    }

    if (append_len_prefixed(registration_salt, sizeof registration_salt, &reg_salt_used,
                            (const unsigned char *) SPAKE2PLUS_CONTEXT, strlen(SPAKE2PLUS_CONTEXT)) != 0 ||
        append_len_prefixed(registration_salt, sizeof registration_salt, &reg_salt_used,
                            (const unsigned char *) SPAKE2PLUS_CIPHERSUITE, strlen(SPAKE2PLUS_CIPHERSUITE)) != 0) {
        fprintf(stderr, "SPAKE2+ registration salt overflow\n");
        goto cleanup;
    }

    if (hkdf_sha256(registration_salt, reg_salt_used,
                    registration_input, reg_input_used,
                    (const unsigned char *) SPAKE2PLUS_REGISTRATION_INFO,
                    strlen(SPAKE2PLUS_REGISTRATION_INFO),
                    expanded, sizeof expanded) != 0) {
        fprintf(stderr, "Failed to derive SPAKE2+ registration material\n");
        goto cleanup;
    }

    if (reduce_scalar_mod_order(order, expanded, SPAKE2PLUS_REG_HALF_LEN, w0, sizeof w0) != 0 ||
        reduce_scalar_mod_order(order, expanded + SPAKE2PLUS_REG_HALF_LEN, SPAKE2PLUS_REG_HALF_LEN, w1, sizeof w1) != 0) {
        fprintf(stderr, "Failed to reduce SPAKE2+ verifier scalars\n");
        goto cleanup;
    }

    if (BN_bin2bn(w0, (int) sizeof w0, w0_bn) == NULL ||
        BN_bin2bn(w1, (int) sizeof w1, w1_bn) == NULL) {
        goto cleanup;
    }

    if (EC_POINT_mul(group, l_point, w1_bn, NULL, NULL, bn_ctx) != 1)
        goto cleanup;

    do {
        if (BN_rand_range(y_bn, order) != 1)
            goto cleanup;
    } while (BN_is_zero(y_bn));

    if (EC_POINT_mul(group, sharev_point, y_bn, n_point, w0_bn, bn_ctx) != 1)
        goto cleanup;
    if (EC_POINT_mul(group, w0m_point, NULL, m_point, w0_bn, bn_ctx) != 1)
        goto cleanup;
    if (EC_POINT_copy(tmp_point, sharep_point) != 1)
        goto cleanup;
    if (EC_POINT_invert(group, w0m_point, bn_ctx) != 1)
        goto cleanup;
    if (EC_POINT_add(group, tmp_point, tmp_point, w0m_point, bn_ctx) != 1)
        goto cleanup;
    if (EC_POINT_mul(group, z_point, NULL, tmp_point, y_bn, bn_ctx) != 1)
        goto cleanup;
    if (EC_POINT_mul(group, v_point, NULL, l_point, y_bn, bn_ctx) != 1)
        goto cleanup;

    if (ec_point_to_octets(group, sharev_point, sharev_octets, sizeof sharev_octets, &sharev_len, bn_ctx) != 0 ||
        ec_point_to_octets(group, z_point, z_octets, sizeof z_octets, &z_len, bn_ctx) != 0 ||
        ec_point_to_octets(group, v_point, v_octets, sizeof v_octets, &v_len, bn_ctx) != 0) {
        fprintf(stderr, "Failed to encode SPAKE2+ verifier points\n");
        goto cleanup;
    }

    if (append_len_prefixed(transcript, sizeof transcript, &transcript_used,
                            (const unsigned char *) SPAKE2PLUS_CONTEXT, strlen(SPAKE2PLUS_CONTEXT)) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used,
                            (const unsigned char *) id_prover, strlen(id_prover)) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used,
                            (const unsigned char *) pairing_id, strlen(pairing_id)) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used,
                            (const unsigned char *) "\x02\x88\x6e\x2f\x97\xac\xe4\x6e\x55\xba\x9d\xd7\x24\x25\x79\xf2\x99\x3b\x64\xe1\x6e\xf3\xdc\xab\x95\xaf\xd4\x97\x33\x3d\x8f\xa1\x2f",
                            SPAKE2PLUS_POINT_LEN) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used,
                            (const unsigned char *) "\x03\xd8\xbb\xd6\xc6\x39\xc6\x29\x37\xb0\x4d\x99\x7f\x38\xc3\x77\x07\x19\xc6\x29\xd7\x01\x4d\x49\xa2\x4b\x4f\x98\xba\xa1\x29\x2b\x49",
                            SPAKE2PLUS_POINT_LEN) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used, sharep_octets, sharep_len) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used, sharev_octets, sharev_len) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used, z_octets, z_len) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used, v_octets, v_len) != 0 ||
        append_len_prefixed(transcript, sizeof transcript, &transcript_used, w0, sizeof w0) != 0) {
        fprintf(stderr, "SPAKE2+ transcript overflow\n");
        goto cleanup;
    }

    if (digest_sha256(transcript, transcript_used, k_main, sizeof k_main) != 0)
        goto cleanup;
    if (hkdf_sha256(NULL, 0, k_main, sizeof k_main,
                    (const unsigned char *) SPAKE2PLUS_CONFIRMATION_INFO,
                    strlen(SPAKE2PLUS_CONFIRMATION_INFO),
                    confirmation_keys, sizeof confirmation_keys) != 0)
        goto cleanup;
    if (hkdf_sha256(NULL, 0, k_main, sizeof k_main,
                    (const unsigned char *) SPAKE2PLUS_SHARED_KEY_INFO,
                    strlen(SPAKE2PLUS_SHARED_KEY_INFO),
                    k_shared, sizeof k_shared) != 0)
        goto cleanup;
    if (hmac_sha256_bytes(confirmation_keys + SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH,
                          sharep_octets, sharep_len,
                          confirm_v, sizeof confirm_v, &confirm_v_len) != 0 ||
        confirm_v_len != SHA256_DIGEST_LENGTH) {
        goto cleanup;
    }

    if (bytes_to_hex(sharev_octets, sharev_len, sharev_hex, sizeof sharev_hex) != 0 ||
        bytes_to_hex(confirm_v, confirm_v_len, confirmv_hex, sizeof confirmv_hex) != 0) {
        goto cleanup;
    }

    if (snprintf(payload, sizeof payload, "shareV=%s&confirmV=%s", sharev_hex, confirmv_hex) < 0)
        goto cleanup;
    if (snprintf(request, sizeof request,
                 "{\"message_type\":\"communication\",\"source_id\":\"%s\",\"payload\":\"%s\"}\n",
                 device_id, payload) < 0)
        goto cleanup;

    if (spake2plus_send_json_line(sock, request) != 0) {
        fprintf(stderr, "Failed to send SPAKE2+ verifier response\n");
        goto cleanup;
    }
    if (spake2plus_wait_status_ok(sock) != 0) {
        fprintf(stderr, "Middlepoint rejected SPAKE2+ verifier response\n");
        goto cleanup;
    }

    /* Round 2: wait for confirmP from the Prover, verify, then persist K_shared. */
    confirmp_hex[0] = '\0';
    id_prover_confirm[0] = '\0';
    payload[0] = '\0';

    while (recv_json_line(sock, response, sizeof response) == 0) {
        /* Ignore status responses (shouldn't happen as we're the destination). */
        if (strstr(response, "\"status_code\"") != NULL) {
            continue;
        }

        if (extract_json_string(response, "source_id", id_prover_confirm, sizeof id_prover_confirm) != 0)
            continue;
        if (id_prover_confirm[0] == '\0' || strcmp(id_prover_confirm, id_prover) != 0)
            continue;

        if (extract_json_string(response, "confirmP", confirmp_hex, sizeof confirmp_hex) == 0)
            break;

        if (extract_json_string(response, "payload", payload, sizeof payload) == 0) {
            if (extract_kv_string(payload, "confirmP", confirmp_hex, sizeof confirmp_hex) == 0)
                break;
        }
    }

    if (confirmp_hex[0] == '\0') {
        fprintf(stderr, "Did not receive SPAKE2+ confirmP\n");
        goto cleanup;
    }

    if (hex_to_bytes(confirmp_hex, confirm_p, sizeof confirm_p, &confirm_p_len) != 0 ||
        confirm_p_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "confirmP is not valid hex\n");
        goto cleanup;
    }

    if (hmac_sha256_bytes(confirmation_keys, SHA256_DIGEST_LENGTH,
                          sharev_octets, sharev_len,
                          confirm_p_expected, sizeof confirm_p_expected, NULL) != 0) {
        goto cleanup;
    }

    if (CRYPTO_memcmp(confirm_p, confirm_p_expected, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "SPAKE2+ confirmP verification failed\n");
        goto cleanup;
    }

    if (bytes_to_hex(k_shared, sizeof k_shared, kshared_hex, sizeof kshared_hex) != 0)
        goto cleanup;

    if (persist_shared_secret(kshared_hex) != 0) {
        fprintf(stderr, "Failed to persist shared secret\n");
        goto cleanup;
    }

    if (out_shared_hex && out_cap > 0) {
        if (snprintf(out_shared_hex, out_cap, "%s", kshared_hex) < 0)
            goto cleanup;
    }

    rc = 0;

cleanup:
    OPENSSL_cleanse(qr_secret_bytes, sizeof qr_secret_bytes);
    OPENSSL_cleanse(registration_input, sizeof registration_input);
    OPENSSL_cleanse(registration_salt, sizeof registration_salt);
    OPENSSL_cleanse(expanded, sizeof expanded);
    OPENSSL_cleanse(w0, sizeof w0);
    OPENSSL_cleanse(w1, sizeof w1);
    OPENSSL_cleanse(sharep_octets, sizeof sharep_octets);
    OPENSSL_cleanse(sharev_octets, sizeof sharev_octets);
    OPENSSL_cleanse(z_octets, sizeof z_octets);
    OPENSSL_cleanse(v_octets, sizeof v_octets);
    OPENSSL_cleanse(transcript, sizeof transcript);
    OPENSSL_cleanse(k_main, sizeof k_main);
    OPENSSL_cleanse(confirmation_keys, sizeof confirmation_keys);
    OPENSSL_cleanse(k_shared, sizeof k_shared);
    OPENSSL_cleanse(confirm_v, sizeof confirm_v);
    OPENSSL_cleanse(confirm_p, sizeof confirm_p);
    OPENSSL_cleanse(confirm_p_expected, sizeof confirm_p_expected);
    BN_clear_free(order);
    BN_clear_free(w0_bn);
    BN_clear_free(w1_bn);
    BN_clear_free(y_bn);
    EC_POINT_free(m_point);
    EC_POINT_free(n_point);
    EC_POINT_free(sharep_point);
    EC_POINT_free(l_point);
    EC_POINT_free(sharev_point);
    EC_POINT_free(w0m_point);
    EC_POINT_free(tmp_point);
    EC_POINT_free(z_point);
    EC_POINT_free(v_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    return rc;
}

static int ensure_keypair(char *pub_hex, size_t cap)
{
    char dir_buf[512];
    char priv_path[600];
    char pub_path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    EVP_PKEY *pkey = NULL;
    FILE *f = NULL;

#ifndef _WIN32
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create key dir: %s\n", dir);
        return -1;
    }
#endif

    if (snprintf(priv_path, sizeof priv_path, "%s/%s", dir, PRIVATE_KEY_FILE) < 0)
        return -1;
    if (snprintf(pub_path, sizeof pub_path, "%s/%s", dir, PUBLIC_KEY_FILE) < 0)
        return -1;

    f = fopen(priv_path, "r");
    if (f) {
        pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
    }

    if (!pkey) {
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        if (!pkey) {
            fprintf(stderr, "Failed to generate X25519 keypair\n");
            return -1;
        }
        f = fopen(priv_path, "w");
        if (!f) {
            fprintf(stderr, "Failed to write private key: %s\n", priv_path);
            EVP_PKEY_free(pkey);
            return -1;
        }
        if (PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
            fclose(f);
            EVP_PKEY_free(pkey);
            fprintf(stderr, "Failed to persist private key\n");
            return -1;
        }
        fclose(f);
#ifndef _WIN32
        chmod(priv_path, 0600);
#endif
    }

    unsigned char pub[64];
    size_t pub_len = sizeof pub;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        fprintf(stderr, "Failed to get public key\n");
        return -1;
    }
    if (cap < (pub_len * 2 + 1)) {
        EVP_PKEY_free(pkey);
        fprintf(stderr, "Public key buffer too small\n");
        return -1;
    }
    for (size_t i = 0; i < pub_len; i++) {
        snprintf(pub_hex + (i * 2), cap - (i * 2), "%02x", pub[i]);
    }
    pub_hex[pub_len * 2] = '\0';

    f = fopen(pub_path, "w");
    if (f) {
        fprintf(f, "%s\n", pub_hex);
        fclose(f);
#ifndef _WIN32
        chmod(pub_path, 0644);
#endif
    }

    EVP_PKEY_free(pkey);
    return 0;
}

static int ensure_qr_secret(char *out, size_t cap)
{
    char dir_buf[512];
    char secret_path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    FILE *f = NULL;

    if (cap < 33) {
        fprintf(stderr, "QR secret buffer too small\n");
        return -1;
    }

#ifndef _WIN32
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create key dir: %s\n", dir);
        return -1;
    }
#endif

    if (snprintf(secret_path, sizeof secret_path, "%s/%s", dir, QR_SECRET_FILE) < 0)
        return -1;

    /* Always generate a fresh QR secret for each new pairing session. */
    out[0] = '\0';

    if (generate_random_id(out, cap) != 0) {
        fprintf(stderr, "Failed to generate qr_secret\n");
        return -1;
    }

    f = fopen(secret_path, "w");
    if (!f) {
        fprintf(stderr, "Failed to write qr_secret: %s\n", secret_path);
        return -1;
    }
    fprintf(f, "%s\n", out);
    fclose(f);
#ifndef _WIN32
    chmod(secret_path, 0600);
#endif

    return 0;
}

static int read_machine_id(char *out, size_t cap)
{
    const char *env = getenv("VPCD_MACHINE_ID");
    if (env && *env) {
        snprintf(out, cap, "%s", env);
        trim_newline(out);
        return out[0] ? 0 : -1;
    }

#ifndef _WIN32
    {
        const char *paths[] = {"/etc/machine-id", "/var/lib/dbus/machine-id", NULL};
        for (int i = 0; paths[i]; i++) {
            FILE *f = fopen(paths[i], "r");
            if (!f)
                continue;
            if (fgets(out, (int) cap, f) != NULL) {
                trim_newline(out);
                fclose(f);
                if (out[0] != '\0')
                    return 0;
            } else {
                fclose(f);
            }
        }
    }
#endif

    return -1;
}

static void hash_to_128(const unsigned char *data, size_t len, uint64_t *hi, uint64_t *lo)
{
#if defined(__SIZEOF_INT128__)
    typedef unsigned __int128 u128;
    const u128 fnv_offset = (((u128) 0x6c62272e07bb0142ULL) << 64) | 0x62b821756295c58dULL;
    const u128 fnv_prime = (((u128) 0x0000000001000000ULL) << 64) | 0x000000000000013BULL;
    u128 hash = fnv_offset;
    for (size_t i = 0; i < len; i++) {
        hash ^= (u128) data[i];
        hash *= fnv_prime;
    }
    *hi = (uint64_t) (hash >> 64);
    *lo = (uint64_t) hash;
#else
    uint64_t h1 = 1469598103934665603ULL;
    uint64_t h2 = 1099511628211ULL ^ 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < len; i++) {
        h1 ^= (uint64_t) data[i];
        h1 *= 1099511628211ULL;
        h2 ^= (uint64_t) data[i];
        h2 *= 14029467366897019727ULL;
    }
    *hi = h1;
    *lo = h2;
#endif
}

static int get_device_id(char *out, size_t cap)
{
    char mid[128];
    uint64_t hi = 0, lo = 0;

    if (read_machine_id(mid, sizeof mid) != 0) {
        fprintf(stderr, "Failed to read machine-id. Set VPCD_MACHINE_ID if needed.\n");
        return -1;
    }

    hash_to_128((const unsigned char *) mid, strlen(mid), &hi, &lo);
    if (snprintf(out, cap, "%016llx%016llx",
                 (unsigned long long) hi, (unsigned long long) lo) < 0)
        return -1;
    return 0;
}

static int do_handshake(SOCKET *out_sock)
{
    const char *role = "pc";
    const char *host = DEFAULT_HANDSHAKE_HOST;
    const char *port = DEFAULT_HANDSHAKE_PORT;
    char request[256];
    char response[512];
    int rc = -1;
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *cur = NULL;

    if (out_sock)
        *out_sock = INVALID_SOCKET;

    if (clear_session_state() != 0) {
        fprintf(stderr, "Failed to reset previous pairing state.\n");
        return -1;
    }

    if (generate_random_id(pairing_id, sizeof pairing_id) != 0) {
        fprintf(stderr, "Failed to generate pairing_id.\n");
        return -1;
    }
    persist_pairing_id(pairing_id);

    if (get_device_id(device_id, sizeof device_id) != 0) {
        fprintf(stderr, "Failed to load or create device_id.\n");
        return -1;
    }
    persist_device_id(device_id);

    if (ensure_keypair(public_key_hex, sizeof public_key_hex) != 0) {
        fprintf(stderr, "Failed to create or load keypair.\n");
        return -1;
    }

    if (snprintf(request, sizeof request,
                "{\"message_type\":\"handshake\",\"pairing_id\":\"%s\",\"device_id\":\"%s\",\"role\":\"%s\"}\n",
                pairing_id, device_id, role) < 0) {
        fprintf(stderr, "Failed to build handshake request.\n");
        return -1;
    }

#ifdef _WIN32
    if (!wsa_started) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            fprintf(stderr, "WSAStartup failed.\n");
            return -1;
        }
        wsa_started = 1;
    }
#endif

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "Handshake: getaddrinfo failed for %s:%s\n", host, port);
        goto cleanup;
    }

    for (cur = res; cur; cur = cur->ai_next) {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sock == INVALID_SOCKET)
            continue;
        if (connect(sock, cur->ai_addr, (socklen_t) cur->ai_addrlen) == 0)
            break;
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        sock = INVALID_SOCKET;
    }

    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Handshake: could not connect to %s:%s\n", host, port);
        goto cleanup;
    }

    if (send(sock, request, (int) strlen(request), 0) < 0) {
        fprintf(stderr, "Handshake: send failed: %s\n", strerror(errno));
        goto cleanup;
    }

    if (recv_json_line(sock, response, sizeof response) != 0) {
        fprintf(stderr, "Handshake failed: empty response\n");
        goto cleanup;
    }

    const char *p = strstr(response, "\"status_code\"");
    if (!p) {
        fprintf(stderr, "Handshake failed: missing status_code\n");
        goto cleanup;
    }
    p = strchr(p, ':');
    if (!p) {
        fprintf(stderr, "Handshake failed: invalid status_code\n");
        goto cleanup;
    }
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    errno = 0;
    long code = strtol(p, NULL, 10);
    if (errno != 0) {
        fprintf(stderr, "Handshake failed: invalid status_code\n");
        goto cleanup;
    }
    if (code != 200) {
        fprintf(stderr, "Handshake failed: status_code=%ld\n", code);
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (rc == 0 && out_sock) {
        *out_sock = sock;
        sock = INVALID_SOCKET;
    }

    if (sock != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
    if (res)
        freeaddrinfo(res);
#ifdef _WIN32
    if (rc != 0 && wsa_started) {
        WSACleanup();
        wsa_started = 0;
    }
#endif
    return rc;
}

static int read_file_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int) cap, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    trim_newline(out);
    return out[0] ? 0 : -1;
}

static int write_file_line(const char *path, const char *value)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", value);
    fclose(f);
#ifndef _WIN32
    chmod(path, 0600);
#endif
    return 0;
}

static int persist_pairing_id(const char *id)
{
    char dir_buf[512];
    char path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    if (snprintf(path, sizeof path, "%s/%s", dir, PAIRING_ID_FILE) < 0)
        return -1;
    return write_file_line(path, id);
}

static int load_pairing_id(char *out, size_t cap)
{
    char dir_buf[512];
    char path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    if (snprintf(path, sizeof path, "%s/%s", dir, PAIRING_ID_FILE) < 0)
        return -1;
    return read_file_line(path, out, cap);
}

static int persist_device_id(const char *id)
{
    char dir_buf[512];
    char path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    if (snprintf(path, sizeof path, "%s/%s", dir, DEVICE_ID_FILE) < 0)
        return -1;
    return write_file_line(path, id);
}

static int delete_key_file(const char *filename)
{
    char dir_buf[512];
    char path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);

    if (snprintf(path, sizeof path, "%s/%s", dir, filename) < 0)
        return -1;

    if (remove(path) == 0 || errno == ENOENT)
        return 0;

    fprintf(stderr, "Failed to delete stale state file: %s\n", path);
    return -1;
}

static int clear_session_state(void)
{
    if (delete_key_file(PAIRING_ID_FILE) != 0)
        return -1;
    if (delete_key_file(SHARED_SECRET_FILE) != 0)
        return -1;
    return 0;
}


int main ( int argc , char *argv[] )
{
    char slot;
    char uri[256];
    int fail = 0;
    SOCKET handshake_sock = INVALID_SOCKET;

    if (do_handshake(&handshake_sock) != 0) {
        fail = 1;
        goto err;
    }


    if (ensure_qr_secret(qr_secret, sizeof qr_secret) != 0) {
        fprintf(stderr, "Failed to load or create qr_secret.\n");
        fail = 1;
        goto err;
    }


    for (slot = 0; slot < VICC_MAX_SLOTS; slot++) {
        printf("Pairing ID:     %s\n", pairing_id);
        printf("Public Key:     %s\n", public_key_hex);
        printf("QR Secret:      %s\n", qr_secret);
        printf("On your NFC phone with the Remote Smart Card Reader app scan this code:\n");
        int n = snprintf(uri, sizeof uri,
                         "vpcd://pairing_id=%s&pubkey=%s&qr_secret=%s",
                         pairing_id, public_key_hex, qr_secret);
        if (n < 0) {
            fprintf(stderr, "Failed to build QR URI\n");
            continue;
        }
        if (n >= (int) sizeof uri) {
            fprintf(stderr, "QR URI too long\n");
            continue;
        }
        print_qrcode(uri);
        if (slot < VICC_MAX_SLOTS-1)
            puts("");
    }

    if (handshake_sock != INVALID_SOCKET) {
        char msg[512];
        printf("Waiting for pairing message...\n");
        if (recv_json_line(handshake_sock, msg, sizeof msg) == 0) {
            if (handle_pairing_message(handshake_sock, msg, qr_secret,
                                       shared_secret_hex, sizeof shared_secret_hex) == 0) {
                printf("SPAKE2+ pairing confirmed; shared secret persisted.\n");
            }
        }
#ifdef _WIN32
        closesocket(handshake_sock);
#else
        close(handshake_sock);
#endif
        handshake_sock = INVALID_SOCKET;
    }
#ifdef _WIN32
    if (wsa_started) {
        WSACleanup();
        wsa_started = 0;
    }
#endif

err:
    if (handshake_sock != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(handshake_sock);
#else
        close(handshake_sock);
#endif
    }
#ifdef _WIN32
    if (wsa_started) {
        WSACleanup();
        wsa_started = 0;
    }
#endif
    return fail;
}
