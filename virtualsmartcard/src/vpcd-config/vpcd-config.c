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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "vpcd.h"

extern const char *local_ip (void);

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

#define ERROR_STRING "Unable to guess local IP address"
#define DEFAULT_HANDSHAKE_HOST "middlepoint.test"
#define DEFAULT_HANDSHAKE_PORT "80"
#define DEFAULT_KEY_DIR ".config/vpcd"
#define PRIVATE_KEY_FILE "vpcd_x25519_private.pem"
#define PUBLIC_KEY_FILE "vpcd_x25519_public.hex"
#define QR_SECRET_FILE "vpcd_qr_secret.hex"

static char device_id[64];
static char pairing_id[64];
static char public_key_hex[128];
static char qr_secret[64];



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
#ifdef _WIN32
    const char *base = getenv("APPDATA");
    if (base && *base && buf && cap > 0) {
        snprintf(buf, cap, "%s\\%s", base, DEFAULT_KEY_DIR);
        return buf;
    }
#else
    const char *base = getenv("HOME");
    if (base && *base && buf && cap > 0) {
        snprintf(buf, cap, "%s/%s", base, DEFAULT_KEY_DIR);
        return buf;
    }
#endif
    return DEFAULT_KEY_DIR;
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

static int do_handshake(void)
{
    const char *role = "pc";
    const char *host = DEFAULT_HANDSHAKE_HOST;
    const char *port = DEFAULT_HANDSHAKE_PORT;
    char request[256];
    char response[512];
    size_t used = 0;
    int rc = -1;

    if (generate_random_id(pairing_id, sizeof pairing_id) != 0) {
        fprintf(stderr, "Failed to generate pairing_id.\n");
        return -1;
    }

    if (get_device_id(device_id, sizeof device_id) != 0) {
        fprintf(stderr, "Failed to load or create device_id.\n");
        return -1;
    }

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
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return -1;
    }
#endif

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *cur = NULL;
    SOCKET sock = INVALID_SOCKET;

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

    while (used < sizeof response - 1) {
        int n = recv(sock, response + used, (int) (sizeof response - 1 - used), 0);
        if (n <= 0)
            break;
        used += (size_t) n;
        if (memchr(response, '\n', used))
            break;
    }
    response[used] = '\0';
    if (used > 0) {
        char *newline = strchr(response, '\n');
        if (newline)
            *newline = '\0';

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
    } else {
        fprintf(stderr, "Handshake failed: empty response\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
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
    WSACleanup();
#endif
    return rc;
}

int main ( int argc , char *argv[] )
{
    char slot;
    char uri[512];
    const char *ip = NULL;
    int fail = 0, port;

    if (do_handshake() != 0) {
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

err:
    return fail;
}
