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
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include "vpcd.h"

extern const char *local_ip (void);
static int read_file_line(const char *path, char *out, size_t cap);
static int write_file_line(const char *path, const char *value);

static int persist_pairing_id(const char *id);
static int load_pairing_id(char *out, size_t cap);
static int persist_device_id(const char *id);

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
#ifdef _WIN32
    unsigned int r1 = 0, r2 = 0;
    if (rand_s(&r1) != 0 || rand_s(&r2) != 0)
        return -1;
    *out = ((uint64_t) r1 << 32) | r2;
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, out, sizeof(*out));
        close(fd);
        if (n == (ssize_t) sizeof(*out))
            return 0;
    }
    *out = ((uint64_t) time(NULL) << 32) ^ (uint64_t) getpid();
    return 0;
#endif
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

static int handle_pairing_message(const char *json, const char *qr_secret_str,
                                  char *out_shared_hex, size_t out_cap)
{
    char mac_hex[256];
    char pubkey_hex[256];
    unsigned char pubkey[64];
    size_t pubkey_len = 0;

    if (extract_pairing_fields(json, mac_hex, sizeof mac_hex,
                               pubkey_hex, sizeof pubkey_hex) != 0) {
        fprintf(stderr, "Pairing message missing mac/pubKeyApp\n");
        return -1;
    }

    if (hex_to_bytes(pubkey_hex, pubkey, sizeof pubkey, &pubkey_len) != 0) {
        fprintf(stderr, "pubKeyApp is not valid hex\n");
        return -1;
    }

    if (verify_mac_hex(mac_hex, qr_secret_str, pubkey, pubkey_len, pubkey_hex) != 0)
        return -1;

    if (derive_shared_secret_hex(pubkey, pubkey_len, out_shared_hex, out_cap) != 0)
        return -1;

    if (persist_shared_secret(out_shared_hex) != 0)
        return -1;

    return 0;
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

    f = fopen(secret_path, "r");
    if (f) {
        if (fgets(out, (int) cap, f) != NULL) {
            trim_newline(out);
            fclose(f);
            if (out[0] != '\0')
                return 0;
        } else {
            fclose(f);
        }
    }

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

    if (generate_random_id(pairing_id, sizeof pairing_id) != 0) {
        fprintf(stderr, "Failed to generate pairing_id.\n");
        return -1;
    }

    if (load_pairing_id(pairing_id, sizeof pairing_id) != 0) {
        if (generate_random_id(pairing_id, sizeof pairing_id) != 0) {
            fprintf(stderr, "Failed to generate pairing_id.\n");
            return -1;
        }
        persist_pairing_id(pairing_id);
    }

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


int main ( int argc , char *argv[] )
{
    char slot;
    char uri[512];
    const char *ip = NULL;
    int fail = 0, port;
    SOCKET handshake_sock = INVALID_SOCKET;

    if (do_handshake(&handshake_sock) != 0) {
        fail = 1;
        goto err;
    }

    ip = local_ip();
    if (!ip) {
        fail = 1;
        goto err;
    }

    if (ensure_qr_secret(qr_secret, sizeof qr_secret) != 0) {
        fprintf(stderr, "Failed to load or create qr_secret.\n");
        fail = 1;
        goto err;
    }


    for (slot = 0; slot < VICC_MAX_SLOTS; slot++) {
        port = VPCDPORT+slot;
        printf("VPCD hostname:  %s\n", ip);
        printf("VPCD port:      %d\n", port);
        printf("Pairing ID:     %s\n", pairing_id);
        printf("Device ID:      %s\n", device_id);
        printf("Public Key:     %s\n", public_key_hex);
        printf("QR Secret:      %s\n", qr_secret);
        printf("On your NFC phone with the Remote Smart Card Reader app scan this code:\n");
        int n = snprintf(uri, sizeof uri,
                         "vpcd://pairing_id=%s&pc_id=%s&pubkey=%s&qr_secret=%s",
                         pairing_id, device_id, public_key_hex, qr_secret);
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
            if (handle_pairing_message(msg, qr_secret,
                                       shared_secret_hex, sizeof shared_secret_hex) == 0) {
                printf("Shared Secret saved.\n");
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
