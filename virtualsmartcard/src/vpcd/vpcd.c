/*
 * Copyright (C) 2009-2014 Frank Morgner
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
#include "vpcd.h"
#include "lock.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if (!defined HAVE_DECL_MSG_NOSIGNAL) || !HAVE_DECL_MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close(s) closesocket(s)
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif
typedef WORD uint16_t;
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h> /* for TCP_NODELAY */
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif


#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define NONCE_LEN 12
#define TAG_LEN 16

#define DEFAULT_KEY_DIR ".config/vpcd"
#define SHARED_SECRET_FILE "vpcd_shared_secret.hex"
#define PAIRING_ID_FILE "vpcd_pairing_id.hex"
#define DEVICE_ID_FILE  "vpcd_device_id.hex"

static int read_key_file_any(const char *filename, char *out, size_t cap);

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
    if (geteuid() == 0) {
        return "/etc/vpcd";
    }
    const char *base = getenv("HOME");
    if (base && *base && buf && cap > 0) {
        snprintf(buf, cap, "%s/%s", base, DEFAULT_KEY_DIR);
        return buf;
    }
#endif
    return DEFAULT_KEY_DIR;
}

static int load_shared_secret(struct vicc_ctx *ctx)
{
    char line[256];
    size_t shared_secret_length = 0;

    if (!ctx)
        return -1;

    OPENSSL_cleanse(ctx->shared_secret, sizeof ctx->shared_secret);
    ctx->shared_secret_length = 0;

    if (read_key_file_any(SHARED_SECRET_FILE, line, sizeof line) != 0) {
        return -1;
    }

    trim_newline(line);
    if (hex_to_bytes(line, ctx->shared_secret, sizeof ctx->shared_secret, &shared_secret_length) != 0) {
        OPENSSL_cleanse(ctx->shared_secret, sizeof ctx->shared_secret);
        fprintf(stderr, "Invalid shared secret hex\n");
        return -1;
    }
    if (shared_secret_length != 32) {
        OPENSSL_cleanse(ctx->shared_secret, sizeof ctx->shared_secret);
        fprintf(stderr, "Shared secret length invalid (expected 32 bytes)\n");
        return -1;
    }

    ctx->shared_secret_length = shared_secret_length;

    return 0;
}

static int load_ids_from_env(struct vicc_ctx *ctx)
{
    const char *pairing = getenv("VPCD_PAIRING_ID");
    const char *device = getenv("VPCD_DEVICE_ID");

    if (!pairing || !*pairing || !device || !*device) {
        return -1;
    }

    snprintf(ctx->pairing_id, sizeof ctx->pairing_id, "%s", pairing);
    snprintf(ctx->device_id, sizeof ctx->device_id, "%s", device);
    return 0;
}

static int delete_state_file_at(const char *path)
{
    if (!path || !*path)
        return -1;

    if (remove(path) == 0 || errno == ENOENT)
        return 0;

    fprintf(stderr, "Failed to delete stale state file: %s\n", path);
    return -1;
}

static int clear_state_file_any(const char *filename)
{
    char dir_buf[512];
    char path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    int failed = 0;

    if (snprintf(path, sizeof path, "%s/%s", dir, filename) < 0)
        return -1;
    if (delete_state_file_at(path) != 0)
        failed = -1;

#ifndef _WIN32
    if (geteuid() == 0) {
        if (snprintf(path, sizeof path, "/root/%s/%s", DEFAULT_KEY_DIR, filename) >= 0) {
            if (delete_state_file_at(path) != 0)
                failed = -1;
        }

        DIR *d = opendir("/home");
        if (d) {
            struct dirent *ent = NULL;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.')
                    continue;
                if (snprintf(path, sizeof path, "/home/%s/%s/%s",
                             ent->d_name, DEFAULT_KEY_DIR, filename) < 0)
                    continue;
                if (delete_state_file_at(path) != 0)
                    failed = -1;
            }
            closedir(d);
        }
    }
#endif

    return failed;
}

static int clear_session_state(void)
{
    int failed = 0;

    if (clear_state_file_any(PAIRING_ID_FILE) != 0)
        failed = -1;
    if (clear_state_file_any(SHARED_SECRET_FILE) != 0)
        failed = -1;

    return failed;
}

static int response_indicates_stale_pairing(const char *json)
{
    if (!json)
        return 0;

    return strstr(json, "is not complete yet") != NULL ||
           strstr(json, "No such pairing with ID") != NULL;
}

static void invalidate_stale_session(struct vicc_ctx *ctx)
{
    if (clear_session_state() == 0)
        fprintf(stderr, "Cleared persisted stale pairing state.\n");

    if (!ctx)
        return;

    ctx->pairing_id[0] = '\0';
    ctx->device_id[0] = '\0';
    OPENSSL_cleanse(ctx->shared_secret, sizeof ctx->shared_secret);
    ctx->shared_secret_length = 0;
}

static int recv_line(SOCKET sock, char *out, size_t cap)
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

static int send_line(SOCKET sock, const char *s)
{
    size_t len = strlen(s);
    if (send(sock, s, (int) len, 0) < 0)
        return -1;
    if (send(sock, "\n", 1, 0) < 0)
        return -1;
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

static int parse_status_code(const char *json)
{
    const char *p = strstr(json, "\"status_code\"");
    if (!p)
        return -1;
    p = strchr(p, ':');
    if (!p)
        return -1;
    p++;
    while (*p && isspace((unsigned char) *p))
        p++;
    errno = 0;
    long code = strtol(p, NULL, 10);
    if (errno != 0)
        return -1;
    return (int) code;
}

static int b64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_cap)
{
    size_t need = 4 * ((in_len + 2) / 3) + 1;
    if (out_cap < need)
        return -1;
    int n = EVP_EncodeBlock((unsigned char *) out, in, (int) in_len);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    return 0;
}

static int b64_decode(const char *in, unsigned char *out, size_t out_cap, size_t *out_len)
{
    size_t len = strlen(in);
    int pad = 0;
    if (len >= 1 && in[len - 1] == '=') pad++;
    if (len >= 2 && in[len - 2] == '=') pad++;
    size_t need = (len / 4) * 3;
    if (out_cap < need)
        return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char *) in, (int) len);
    if (n < 0)
        return -1;
    n -= pad;
    if (n < 0)
        return -1;
    if (out_len)
        *out_len = (size_t) n;
    return 0;
}

static int encrypt_frame(struct vicc_ctx *ctx,
                         const unsigned char *pt, size_t pt_len,
                         char *out_b64, size_t out_cap)
{
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char *ct = NULL;
    unsigned char *blob = NULL;
    int len = 0, ct_len = 0;
    int rc = -1;

    if (!ctx || !pt || !out_b64)
        return -1;

    if (RAND_bytes(nonce, sizeof nonce) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    ct = (unsigned char *) malloc(pt_len);
    if (!ct)
        return -1;

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        goto cleanup;

    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(c, NULL, NULL, ctx->shared_secret, nonce) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(c, ct, &len, pt, (int) pt_len) != 1)
        goto cleanup;
    ct_len = len;

    if (EVP_EncryptFinal_ex(c, ct + ct_len, &len) != 1)
        goto cleanup;
    ct_len += len;

    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;

    size_t total = NONCE_LEN + (size_t) ct_len + TAG_LEN;
    blob = (unsigned char *) malloc(total);
    if (!blob)
        goto cleanup;

    memcpy(blob, nonce, NONCE_LEN);
    memcpy(blob + NONCE_LEN, ct, ct_len);
    memcpy(blob + NONCE_LEN + ct_len, tag, TAG_LEN);

    if (b64_encode(blob, total, out_b64, out_cap) != 0)
        goto cleanup;

    rc = 0;

cleanup:
    if (c)
        EVP_CIPHER_CTX_free(c);
    if (ct) {
        OPENSSL_cleanse(ct, pt_len);
        free(ct);
    }
    if (blob) {
        OPENSSL_cleanse(blob, NONCE_LEN + pt_len + TAG_LEN);
        free(blob);
    }
    return rc;
}

static int decrypt_frame(struct vicc_ctx *ctx,
                         const char *b64,
                         unsigned char **out, size_t *out_len)
{
    unsigned char *blob = NULL;
    size_t blob_len = 0;
    unsigned char *pt = NULL;
    int len = 0, pt_len = 0;
    int rc = -1;

    if (!ctx || !b64 || !out || !out_len)
        return -1;

    size_t max_blob = (strlen(b64) / 4 + 1) * 3;
    blob = (unsigned char *) malloc(max_blob);
    if (!blob)
        return -1;

    if (b64_decode(b64, blob, max_blob, &blob_len) != 0)
        goto cleanup;

    if (blob_len < NONCE_LEN + TAG_LEN)
        goto cleanup;

    size_t ct_len = blob_len - NONCE_LEN - TAG_LEN;
    unsigned char *nonce = blob;
    unsigned char *ct = blob + NONCE_LEN;
    unsigned char *tag = blob + NONCE_LEN + ct_len;

    pt = (unsigned char *) malloc(ct_len);
    if (!pt)
        goto cleanup;

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        goto cleanup;

    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
        goto cleanup;
    if (EVP_DecryptInit_ex(c, NULL, NULL, ctx->shared_secret, nonce) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(c, pt, &len, ct, (int) ct_len) != 1)
        goto cleanup;
    pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;
    if (EVP_DecryptFinal_ex(c, pt + pt_len, &len) != 1) {
        EVP_CIPHER_CTX_free(c);
        goto cleanup;
    }
    pt_len += len;
    EVP_CIPHER_CTX_free(c);

    *out = pt;
    *out_len = (size_t) pt_len;
    pt = NULL;

    rc = 0;

cleanup:
    if (pt) {
        OPENSSL_cleanse(pt, pt_len);
        free(pt);
    }
    if (blob) {
        OPENSSL_cleanse(blob, blob_len);
        free(blob);
    }
    return rc;
}

static int mp_handshake(struct vicc_ctx *ctx)
{
    char msg[512];
    char resp[512];

    if (snprintf(msg, sizeof msg,
            "{\"message_type\":\"handshake\",\"pairing_id\":\"%s\",\"device_id\":\"%s\",\"role\":\"pc\"}",
            ctx->pairing_id, ctx->device_id) < 0) {
        return -1;
    }

    if (send_line(ctx->client_sock, msg) != 0)
        return -1;

    if (recv_line(ctx->client_sock, resp, sizeof resp) != 0)
        return -1;

    int code = parse_status_code(resp);
    if (code != 200) {
        fprintf(stderr, "Handshake failed: %s\n", resp);
        return -1;
    }
    return 0;
}

static int mp_send_comm(struct vicc_ctx *ctx, const char *payload_b64)
{
    char msg[4096];
    if (snprintf(msg, sizeof msg,
            "{\"message_type\":\"communication\",\"source_id\":\"%s\",\"payload\":\"%s\"}",
            ctx->device_id, payload_b64) < 0) {
        return -1;
    }
    return send_line(ctx->client_sock, msg);
}

static int mp_wait_status(struct vicc_ctx *ctx)
{
    char line[512];
    for (;;) {
        if (recv_line(ctx->client_sock, line, sizeof line) != 0)
            return -1;
        int code = parse_status_code(line);
        if (code < 0)
            continue;
        if (code != 200) {
            if (response_indicates_stale_pairing(line))
                invalidate_stale_session(ctx);
            fprintf(stderr, "Communication failed: %s\n", line);
            return -1;
        }
        return 0;
    }
}

static int mp_recv_payload(struct vicc_ctx *ctx, char *out, size_t cap)
{
    char line[4096];
    for (;;) {
        if (recv_line(ctx->client_sock, line, sizeof line) != 0)
            return -1;

        if (strstr(line, "\"status_code\"")) {
            int code = parse_status_code(line);
            if (code != 200) {
                if (response_indicates_stale_pairing(line))
                    invalidate_stale_session(ctx);
                return -1;
            }
            continue;
        }

        if (extract_json_string(line, "payload", out, cap) == 0)
            return 0;
    }
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

static int read_key_file_any(const char *filename, char *out, size_t cap)
{
    char dir_buf[512];
    char path[600];
    const char *dir = key_dir_path(dir_buf, sizeof dir_buf);
    if (snprintf(path, sizeof path, "%s/%s", dir, filename) >= 0) {
        if (read_file_line(path, out, cap) == 0)
            return 0;
    }

#ifndef _WIN32
    if (geteuid() == 0) {
        if (snprintf(path, sizeof path, "/root/%s/%s", DEFAULT_KEY_DIR, filename) >= 0) {
            if (read_file_line(path, out, cap) == 0)
                return 0;
        }

        DIR *d = opendir("/home");
        if (d) {
            struct dirent *ent = NULL;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.')
                    continue;
                if (snprintf(path, sizeof path, "/home/%s/%s/%s",
                             ent->d_name, DEFAULT_KEY_DIR, filename) < 0)
                    continue;
                if (read_file_line(path, out, cap) == 0) {
                    closedir(d);
                    return 0;
                }
            }
            closedir(d);
        }
    }
#endif

    return -1;
}

static int load_pairing_id_file(char *out, size_t cap)
{
    return read_key_file_any(PAIRING_ID_FILE, out, cap);
}

static int load_device_id_file(char *out, size_t cap)
{
    return read_key_file_any(DEVICE_ID_FILE, out, cap);
}

static int load_ids(struct vicc_ctx *ctx)
{
    if (!ctx)
        return -1;

    ctx->pairing_id[0] = '\0';
    ctx->device_id[0] = '\0';

    if (load_ids_from_env(ctx) == 0) {
        return 0;
    }

    if (load_pairing_id_file(ctx->pairing_id, sizeof ctx->pairing_id) != 0) {
        return -1;
    }

    if (load_device_id_file(ctx->device_id, sizeof ctx->device_id) != 0) {
        ctx->pairing_id[0] = '\0';
        ctx->device_id[0] = '\0';
        return -1;
    }

    return 0;
}

static int vicc_prepare(struct vicc_ctx *ctx)
{
    if (!ctx)
        return 0;

    if (!ctx->pairing_id[0] || !ctx->device_id[0]) {
        if (load_ids(ctx) != 0)
            return 0;
    }

    if (ctx->shared_secret_length != 32) {
        if (load_shared_secret(ctx) != 0)
            return 0;
    }

    return 1;
}

static ssize_t sendToVICC(struct vicc_ctx *ctx, size_t size, const unsigned char *buffer);
static ssize_t recvFromVICC(struct vicc_ctx *ctx, unsigned char **buffer);

static ssize_t sendall(SOCKET sock, const void *buffer, size_t size);
static ssize_t recvall(SOCKET sock, void *buffer, size_t size);

static SOCKET opensock(unsigned short port);
static SOCKET connectsock(const char *hostname, unsigned short port);

ssize_t sendall(SOCKET sock, const void *buffer, size_t size)
{
    size_t sent = 0;
    ssize_t r;

    /* FIXME we should actually check the length instead of simply casting from
     * size_t to ssize_t (or int), which have both the same width! */
    while (sent < size) {
        r = send(sock, (void *) (((unsigned char *) buffer)+sent),
#ifdef _WIN32
                (int)
#endif
                (size-sent), MSG_NOSIGNAL);

        if (r < 0)
            return r;

        sent += r;
    }

    return (ssize_t) sent;
}

ssize_t recvall(SOCKET sock, void *buffer, size_t size) {
    return recv(sock, buffer,
#ifdef _WIN32
            (int)
#endif
            size, MSG_WAITALL|MSG_NOSIGNAL);
}

static SOCKET opensock(unsigned short port)
{
    SOCKET sock;
    socklen_t yes = 1;
    struct sockaddr_in server_sockaddr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &yes, sizeof yes) != 0) 
        goto err;

#if HAVE_DECL_SO_NOSIGPIPE
    if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &yes, sizeof yes) != 0)
        goto err;
#endif
#ifdef TCP_NODELAY
    if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *) &yes, sizeof yes) != 0)
        goto err;
#endif

    memset(&server_sockaddr, 0, sizeof server_sockaddr);
    server_sockaddr.sin_family      = PF_INET;
    server_sockaddr.sin_port        = htons(port);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *) &server_sockaddr,
                sizeof server_sockaddr) != 0)  {
        perror(NULL);
        goto err;
    }

    if (listen(sock, 0) != 0) {
        perror(NULL);
        goto err;
    }

    return sock;

err:
    close(sock);

    return INVALID_SOCKET;
}

static SOCKET connectsock(const char *hostname, unsigned short port)
{
	struct addrinfo hints, *res = NULL, *cur;
	SOCKET sock = INVALID_SOCKET;
    char _port[10];

    if (snprintf(_port, sizeof _port, "%hu", port) < 0)
        goto err;
    _port[(sizeof _port) -1] = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

	if (getaddrinfo(hostname, _port, &hints, &res) != 0)
		goto err;

	for (cur = res; cur; cur = cur->ai_next) {
		sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
		if (sock == INVALID_SOCKET)
			continue;

		if (connect(sock, cur->ai_addr,
#ifdef _WIN32
                    (int)
#endif
                    cur->ai_addrlen) != -1)
			break;

		close(sock);
	}

err:
	freeaddrinfo(res);
	return sock;
}

SOCKET waitforclient(SOCKET server, long secs, long usecs)
{
    struct sockaddr_in client_sockaddr;
    socklen_t client_socklen = sizeof client_sockaddr;

#if _WIN32
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
#pragma warning(disable:4127)
    FD_SET(server, &rfds);
#pragma warning(default:4127)

    tv.tv_sec = secs;
    tv.tv_usec = usecs;

    if (select((int) server+1, &rfds, NULL, NULL, &tv) == -1)
        return INVALID_SOCKET;

    if (FD_ISSET(server, &rfds))
    /* work around clumsy define of FD_SET in winsock2.h */

#else
    int timeout;
    struct pollfd pfd;

    pfd.fd = server;
    pfd.events = POLLIN;
    pfd.revents = 0;

    timeout = (secs * 1000 + usecs / 1000);

    if (poll(&pfd, 1, timeout) == -1)
        return INVALID_SOCKET;

    if(pfd.revents & POLLIN)
#endif
        return accept(server, (struct sockaddr *) &client_sockaddr,
                &client_socklen);

    return INVALID_SOCKET;
}

static ssize_t sendToVICC(struct vicc_ctx *ctx, size_t length, const unsigned char* buffer)
{
    uint16_t size;
    unsigned char *plain = NULL;
    char payload[4096];

    if (!ctx || length > 0xFFFF) {
        errno = EINVAL;
        return -1;
    }

    if (!vicc_connect(ctx, 0, 0)) {
        errno = ENOTCONN;
        return -1;
    }

    plain = (unsigned char *) malloc(length + 2);
    if (!plain) {
        errno = ENOMEM;
        return -1;
    }

    size = htons((uint16_t) length);
    memcpy(plain, &size, 2);
    memcpy(plain + 2, buffer, length);

    if (encrypt_frame(ctx, plain, length + 2, payload, sizeof payload) != 0) {
        free(plain);
        return -1;
    }
    free(plain);

    if (mp_send_comm(ctx, payload) != 0)
        return -1;

    if (mp_wait_status(ctx) != 0)
        return -1;

    return (ssize_t) (length + 2);
}

static ssize_t recvFromVICC(struct vicc_ctx *ctx, unsigned char **buffer)
{
    char payload[4096];
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    uint16_t size = 0;
    unsigned char *p = NULL;

    if (!ctx || !buffer) {
        errno = EINVAL;
        return -1;
    }

    if (mp_recv_payload(ctx, payload, sizeof payload) != 0)
        return -1;

    if (decrypt_frame(ctx, payload, &plain, &plain_len) != 0)
        return -1;

    if (plain_len < 2) {
        free(plain);
        return -1;
    }

    memcpy(&size, plain, 2);
    size = ntohs(size);

    if (size > 0) {
        p = realloc(*buffer, size);
        if (p == NULL) {
            free(plain);
            errno = ENOMEM;
            return -1;
        }
        *buffer = p;
        memcpy(*buffer, plain + 2, size);
    }

    free(plain);
    return (ssize_t) size;
}

int vicc_eject(struct vicc_ctx *ctx)
{
    if (ctx && ctx->client_sock != INVALID_SOCKET) {
        close(ctx->client_sock);
        ctx->client_sock = INVALID_SOCKET;
    }
    return 0;
}

struct vicc_ctx * vicc_init(const char *hostname, unsigned short port)
{
    struct vicc_ctx *r = NULL;

    struct vicc_ctx *ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        goto err;
    }

    ctx->server_sock = INVALID_SOCKET;
    ctx->client_sock = INVALID_SOCKET;
    ctx->port = port;

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    ctx->io_lock = create_lock();
    if (!ctx->io_lock) {
        goto err;
    }

    if (!hostname)
        hostname = "middlepoint.test";

    ctx->hostname = strdup(hostname);
    if (!ctx->hostname) {
        goto err;
    }

    r = ctx;

err:
    if (!r) {
        vicc_exit(ctx);
    }

    return r;
}

int vicc_exit(struct vicc_ctx *ctx)
{
    int r = 0;
    if (ctx) {
        free_lock(ctx->io_lock);
        free(ctx->hostname);
        if (ctx->client_sock != INVALID_SOCKET) {
            ctx->client_sock = close(ctx->client_sock);
        }
        OPENSSL_cleanse(ctx->shared_secret, sizeof ctx->shared_secret);
        free(ctx);
#ifdef _WIN32
        WSACleanup();
#endif
    }
    return r;
}

ssize_t vicc_transmit(struct vicc_ctx *ctx,
        size_t apdu_len, const unsigned char *apdu,
        unsigned char **rapdu)
{
    ssize_t r = -1;

    if (ctx && lock(ctx->io_lock)) {
        if (apdu_len && apdu)
            r = sendToVICC(ctx, apdu_len, apdu);
        else
            r = 1;

        if (r > 0 && rapdu)
            r = recvFromVICC(ctx, rapdu);

        unlock(ctx->io_lock);
    }

    if (r <= 0)
        vicc_eject(ctx);

    return r;
}


int vicc_connect(struct vicc_ctx *ctx, long secs, long usecs)
{
    (void) secs;
    (void) usecs;

    if (!ctx)
        return 0;

    if (!vicc_prepare(ctx))
        return 0;

    if (ctx->client_sock == INVALID_SOCKET) {
        ctx->client_sock = connectsock(ctx->hostname, ctx->port);
        if (ctx->client_sock == INVALID_SOCKET)
            return 0;
        if (mp_handshake(ctx) != 0) {
            close(ctx->client_sock);
            ctx->client_sock = INVALID_SOCKET;
            return 0;
        }
    }

    return 1;
}

int vicc_present(struct vicc_ctx *ctx) {
    unsigned char *atr = NULL;

    /* get the atr to check if the card is still alive */
    if (!vicc_connect(ctx, 0, 0) || vicc_getatr(ctx, &atr) <= 0)
        return 0;

    free(atr);

    return 1;
}

ssize_t vicc_getatr(struct vicc_ctx *ctx, unsigned char **atr) {
    unsigned char i = VPCD_CTRL_ATR;
    return vicc_transmit(ctx, VPCD_CTRL_LEN, &i, atr);
}

int vicc_poweron(struct vicc_ctx *ctx) {
    unsigned char i = VPCD_CTRL_ON;
    int r = 0;

    if (ctx && lock(ctx->io_lock)) {
        r = sendToVICC(ctx, VPCD_CTRL_LEN, &i);
        unlock(ctx->io_lock);
    }

    return r;
}

int vicc_poweroff(struct vicc_ctx *ctx) {
    unsigned char i = VPCD_CTRL_OFF;
    int r = 0;

    if (ctx && lock(ctx->io_lock)) {
        r = sendToVICC(ctx, VPCD_CTRL_LEN, &i);
        unlock(ctx->io_lock);
    }

    return r;
}

int vicc_reset(struct vicc_ctx *ctx) {
    unsigned char i = VPCD_CTRL_RESET;
    int r = 0;

    if (ctx && lock(ctx->io_lock)) {
        r = sendToVICC(ctx, VPCD_CTRL_LEN, &i);
        unlock(ctx->io_lock);
    }

    return r;
}
