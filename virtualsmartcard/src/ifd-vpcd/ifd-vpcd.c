/*
 * Copyright (C) 2010-2013 Frank Morgner
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

#include "ifd-vpcd.h"
#include "vpcd.h"
#include "lock.h"

#include <wintypes.h>

#include <errno.h>
#include <ifdhandler.h>
#include <reader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* pcscd allows at most 16 readers. Apple's SmartCardServices on OS X 10.10
 * freaks out if more than 8 slots are registered. We want only two slots... */
#define VICC_MAX_SLOTS (VPCDSLOTS <= PCSCLITE_MAX_READERS_CONTEXTS ? VPCDSLOTS : PCSCLITE_MAX_READERS_CONTEXTS)
// Manually changed to JUST ONE
const unsigned char vicc_max_slots = 1;

#ifdef HAVE_DEBUGLOG_H

#include <debuglog.h>

#else

enum {
	PCSC_LOG_DEBUG = 0,
	PCSC_LOG_INFO,
	PCSC_LOG_ERROR,
	PCSC_LOG_CRITICAL
};

#ifdef HAVE_SYSLOG_H

#include <stdarg.h>
#include <syslog.h>

void log_msg(const int priority, const char *fmt, ...)
{
	char debug_buffer[160]; /* up to 2 lines of 80 characters */
	va_list argptr;
	int syslog_level;

	switch(priority) {
		case PCSC_LOG_CRITICAL:
			syslog_level = LOG_CRIT;
			break;
		case PCSC_LOG_ERROR:
			syslog_level = LOG_ERR;
			break;
		case PCSC_LOG_INFO:
			syslog_level = LOG_INFO;
			break;
		default:
			syslog_level = LOG_DEBUG;
	}

	va_start(argptr, fmt);
	(void)vsnprintf(debug_buffer, sizeof debug_buffer, fmt, argptr);
	va_end(argptr);

	syslog(syslog_level, "%s", debug_buffer);
}
#define Log0(priority) log_msg(priority, "%s:%d:%s()", __FILE__, __LINE__, __FUNCTION__)
#define Log1(priority, fmt) log_msg(priority, "%s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__)
#define Log2(priority, fmt, data) log_msg(priority, "%s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__, data)
#define Log3(priority, fmt, data1, data2) log_msg(priority, "%s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__, data1, data2)
#define Log4(priority, fmt, data1, data2, data3) log_msg(priority, "%s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__, data1, data2, data3)
#define Log5(priority, fmt, data1, data2, data3, data4) log_msg(priority, "%s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__, data1, data2, data3, data4)
#define Log9(priority, fmt, data1, data2, data3, data4, data5, data6, data7, data8) log_msg(priority, "%s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__, data1, data2, data3, data4, data5, data6, data7, data8)

#else

#define Log0(priority) do { } while(0)
#define Log1(priority, fmt) do { } while(0)
#define Log2(priority, fmt, data) do { } while(0)
#define Log3(priority, fmt, data1, data2) do { } while(0)
#define Log4(priority, fmt, data1, data2, data3) do { } while(0)
#define Log5(priority, fmt, data1, data2, data3, data4) do { } while(0)
#define Log9(priority, fmt, data1, data2, data3, data4, data5, data6, data7, data8) do { } while(0)

#endif
#endif

/* Copied from libccid ccid_ifdhandler.h */
#define CLASS2_IOCTL_MAGIC 0x330000
#define IOCTL_FEATURE_GET_TLV_PROPERTIES \
    SCARD_CTL_CODE(FEATURE_GET_TLV_PROPERTIES + CLASS2_IOCTL_MAGIC)

static struct vicc_ctx *ctx[VICC_MAX_SLOTS];
const char *hostname = NULL;
static const char openport[] = "/dev/null";


// Globals
static struct vicc_ctx *g_ctx = NULL;
static int g_ctx_users = 0;
static const char *g_mp_host = NULL;
static unsigned short g_mp_port = 80;
static void *g_ctx_lock = NULL;

#ifdef HAVE_PTHREAD
static pthread_t g_ctx_thread;
static volatile int g_ctx_thread_stop = 0;
static int g_ctx_thread_started = 0;
#endif

// Helpers
static void vpcd_load_mp_defaults(void)
{
    const char *h = getenv("VPCD_MP_HOST");
    const char *p = getenv("VPCD_MP_PORT");

    g_mp_host = (h && *h) ? h : "middlepoint.test";
    g_mp_port = 80;

    if (p && *p) {
        unsigned long v = strtoul(p, NULL, 10);
        if (v > 0 && v < 65536)
            g_mp_port = (unsigned short) v;
    }
}

static void vpcd_refresh_ctx_locked(void)
{
    if (g_ctx) {
        if (g_ctx_users == 0 && g_ctx->client_sock == INVALID_SOCKET) {
            (void) vicc_connect(g_ctx, 0, 0);
        }
        return;
    }

    vpcd_load_mp_defaults();
    g_ctx = vicc_init(g_mp_host, g_mp_port);
}

static void vpcd_ensure_ctx(void)
{
    if (!g_ctx_lock) {
        g_ctx_lock = create_lock();
        if (!g_ctx_lock)
            return;
    }

    if (!lock(g_ctx_lock))
        return;

    vpcd_refresh_ctx_locked();
    unlock(g_ctx_lock);
}

static struct vicc_ctx *vpcd_get_slot_ctx(size_t slot)
{
    struct vicc_ctx *slot_ctx = NULL;

    if (slot >= vicc_max_slots) {
        return NULL;
    }

    vpcd_ensure_ctx();

    if (!g_ctx_lock || !lock(g_ctx_lock)) {
        return NULL;
    }

    if (ctx[slot] == NULL && g_ctx != NULL) {
        ctx[slot] = g_ctx;
        g_ctx_users++;
    }

    slot_ctx = ctx[slot];
    unlock(g_ctx_lock);
    return slot_ctx;
}

#ifdef HAVE_PTHREAD
static void *vpcd_keepalive_thread(void *unused)
{
    (void) unused;

    while (!g_ctx_thread_stop) {
        unsigned int delay = 1;
        vpcd_ensure_ctx();
        if (g_ctx_lock && lock(g_ctx_lock)) {
            if (!g_ctx) {
                delay = 5;
            }
            unlock(g_ctx_lock);
        }
        sleep(delay);
    }

    return NULL;
}
#endif

#if defined(__GNUC__)
__attribute__((constructor))
static void vpcd_driver_ctor(void)
{
    if (!g_ctx_lock) {
        g_ctx_lock = create_lock();
    }

    vpcd_ensure_ctx();

#ifdef HAVE_PTHREAD
    if (!g_ctx_thread_started) {
        g_ctx_thread_stop = 0;
        if (pthread_create(&g_ctx_thread, NULL, vpcd_keepalive_thread, NULL) == 0) {
            g_ctx_thread_started = 1;
        } else {
            Log1(PCSC_LOG_ERROR, "Could not start middlepoint keepalive thread");
        }
    }
#endif
}

__attribute__((destructor))
static void vpcd_driver_dtor(void)
{
#ifdef HAVE_PTHREAD
    if (g_ctx_thread_started) {
        g_ctx_thread_stop = 1;
        pthread_join(g_ctx_thread, NULL);
        g_ctx_thread_started = 0;
    }
#endif

    if (g_ctx_lock && lock(g_ctx_lock)) {
        if (g_ctx) {
            vicc_exit(g_ctx);
            g_ctx = NULL;
        }
        unlock(g_ctx_lock);
    }

    if (g_ctx_lock) {
        free_lock(g_ctx_lock);
        g_ctx_lock = NULL;
    }
}
#endif

RESPONSECODE
IFDHCreateChannel (DWORD Lun, DWORD Channel)
{
    size_t slot = Lun & 0xffff;
    (void) Channel;

    if (slot >= vicc_max_slots) {
        return IFD_COMMUNICATION_ERROR;
    }

    if (!vpcd_get_slot_ctx(slot)) {
        Log1(PCSC_LOG_INFO, "Middlepoint is not ready yet, reader will retry lazily");
    }

    return IFD_SUCCESS;
}

RESPONSECODE
IFDHCreateChannelByName (DWORD Lun, LPSTR DeviceName)
{
    RESPONSECODE r = IFD_NOT_SUPPORTED;
    char *dots;
    char _hostname[MAX_READERNAME];
    size_t hostname_len;
    unsigned long int port = VPCDPORT;

    dots = strchr(DeviceName, ':');
    if (dots) {
        /* a port has been specified behind the device name */

        hostname_len = dots - DeviceName;
        if (strlen(openport) != hostname_len
                || strncmp(DeviceName, openport, hostname_len) != 0) {
            /* a hostname other than /dev/null has been specified,
             * so we connect initialize hostname to connect to vicc */
            if (hostname_len < sizeof _hostname)
                memcpy(_hostname, DeviceName, hostname_len);
            else {
                Log3(PCSC_LOG_ERROR, "Not enough memory to hold hostname (have %zu, need %zu)", sizeof _hostname, hostname_len);
                goto err;
            }
            _hostname[hostname_len] = '\0';
            hostname = _hostname;
        }

        /* skip the ':' */
        dots++;

        errno = 0;
        port = strtoul(dots, NULL, 0);
        if (errno) {
            Log2(PCSC_LOG_ERROR, "Could not parse port: %s", dots);
            goto err;
        }
    } else {
        Log1(PCSC_LOG_INFO, "Using default port.");
    }

    r = IFDHCreateChannel (Lun, port);

err:
    /* set hostname back to default in case it has been changed */
    hostname = NULL;

    return r;
}

RESPONSECODE
IFDHControl (DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength,
        PUCHAR RxBuffer, DWORD RxLength, LPDWORD pdwBytesReturned)
{
    Log9(PCSC_LOG_DEBUG, "IFDHControl (Lun=%u ControlCode=%u TxBuffer=%p TxLength=%u RxBuffer=%p RxLength=%u pBytesReturned=%p)%s",
            (unsigned int) Lun, (unsigned int) dwControlCode,
            (unsigned char *) TxBuffer, (unsigned int) TxLength,
            (unsigned char *) RxBuffer, (unsigned int) RxLength,
            (unsigned int *) pdwBytesReturned, "");

    if (pdwBytesReturned == NULL)
        return IFD_COMMUNICATION_ERROR;

    if (dwControlCode == CM_IOCTL_GET_FEATURE_REQUEST) {
        if (RxLength < sizeof(PCSC_TLV_STRUCTURE))
            return IFD_ERROR_INSUFFICIENT_BUFFER;

        PCSC_TLV_STRUCTURE *pcsc_tlv = (PCSC_TLV_STRUCTURE *)RxBuffer;
        pcsc_tlv->tag = FEATURE_GET_TLV_PROPERTIES;
        pcsc_tlv->length = sizeof(uint32_t);
        uint32_t value = htonl(IOCTL_FEATURE_GET_TLV_PROPERTIES);
        memcpy(&pcsc_tlv->value, &value, sizeof(uint32_t));
        *pdwBytesReturned = sizeof(PCSC_TLV_STRUCTURE);
        return IFD_SUCCESS;
    }

    if (dwControlCode == IOCTL_FEATURE_GET_TLV_PROPERTIES) {
        if (RxLength < 6)
            return IFD_ERROR_INSUFFICIENT_BUFFER;

        // Support extended APDUs with 65536 bytes
        unsigned int MaxAPDUDataSize = 0x10000;
        unsigned int p = 0;
        RxBuffer[p++] = PCSCv2_PART10_PROPERTY_dwMaxAPDUDataSize;
        RxBuffer[p++] = 4;  /* length */
        RxBuffer[p++] = MaxAPDUDataSize & 0xFF;
        RxBuffer[p++] = (MaxAPDUDataSize >> 8) & 0xFF;
        RxBuffer[p++] = (MaxAPDUDataSize >> 16) & 0xFF;
        RxBuffer[p++] = (MaxAPDUDataSize >> 24) & 0xFF;
        *pdwBytesReturned = p;
        return IFD_SUCCESS;
    }

    *pdwBytesReturned = 0;
    return IFD_ERROR_NOT_SUPPORTED;
}

RESPONSECODE
IFDHCloseChannel (DWORD Lun)
{
    size_t slot = Lun & 0xffff;
    if (slot >= vicc_max_slots) {
        return IFD_COMMUNICATION_ERROR;
    }

    if (g_ctx_lock && lock(g_ctx_lock)) {
        if (ctx[slot]) {
            ctx[slot] = NULL;
            if (g_ctx_users > 0)
                g_ctx_users--;
        }
        unlock(g_ctx_lock);
    }

    return IFD_SUCCESS;
}

RESPONSECODE
IFDHGetCapabilities (DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value)
{
    unsigned char *atr = NULL;
    ssize_t size;
    size_t slot = Lun & 0xffff;
    struct vicc_ctx *slot_ctx = NULL;
    RESPONSECODE r = IFD_COMMUNICATION_ERROR;

    if (slot >= vicc_max_slots)
        goto err;

    if (!Length || !Value)
        goto err;

    switch (Tag) {
#ifdef SCARD_ATTR_ATR_STRING
        case SCARD_ATTR_ATR_STRING:
            /* fall through */
#else
        case 0x00090303:
            /* fall through */
#endif
        case TAG_IFD_ATR:
            slot_ctx = vpcd_get_slot_ctx(slot);
            if (!slot_ctx) {
                Log1(PCSC_LOG_INFO, "Middlepoint is not ready yet, ATR unavailable");
                goto err;
            }

            size = vicc_getatr(slot_ctx, &atr);
            if (size < 0) {
                Log1(PCSC_LOG_ERROR, "could not get ATR");
                goto err;
            }
            if (size == 0) {
                Log1(PCSC_LOG_ERROR, "Virtual ICC removed");
                goto err;
            }
            Log2(PCSC_LOG_DEBUG, "Got ATR (%zd bytes)", size);

#ifndef __APPLE__
            if (*Length < size) {
#else
            /* Apple's new SmartCardServices on OS X 10.10 doesn't set the
             * length correctly so we only check for the maximum  */
            if (MAX_ATR_SIZE < size) {
#endif
                free(atr);
                Log1(PCSC_LOG_ERROR, "Not enough memory for ATR");
                goto err;
            }

            memcpy(Value, atr, size);
            *Length = size;
            free(atr);
            break;

        case TAG_IFD_SLOTS_NUMBER:
            if (*Length < 1) {
                Log1(PCSC_LOG_ERROR, "Invalid input data");
                goto err;
            }

            *Value  = vicc_max_slots;
            *Length = 1;
            break;

        case TAG_IFD_THREAD_SAFE:
            if (*Length < 1) {
                Log1(PCSC_LOG_ERROR, "Invalid input data");
                goto err;
            }

            /* We are not thread safe due to
             * the global hostname and ctx */
            *Value  = 0;
            *Length = 1;
            break;

        case TAG_IFD_SLOT_THREAD_SAFE:
            if (*Length < 1) {
                Log1(PCSC_LOG_ERROR, "Invalid input data");
                goto err;
            }

            /* driver supports access to multiple slots of the same reader at
             * the same time */
            *Value  = 1;
            *Length = 1;
            break;

        default:
            Log2(PCSC_LOG_DEBUG, "unknown tag %d", (int)Tag);
            r = IFD_ERROR_TAG;
            goto err;
    }

    r = IFD_SUCCESS;

err:
    if (r != IFD_SUCCESS && Length)
        *Length = 0;

    return r;
}

RESPONSECODE
IFDHSetCapabilities (DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value)
{
    Log9(PCSC_LOG_DEBUG, "IFDHSetCapabilities not supported (Lun=%u Tag=%u Length=%u Value=%p)%s%s%s%s",
            (unsigned int) Lun, (unsigned int) Tag, (unsigned int) Length,
            (unsigned char *) Value, "", "", "", "");
    return IFD_NOT_SUPPORTED;
}

RESPONSECODE
IFDHSetProtocolParameters (DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1,
        UCHAR PTS2, UCHAR PTS3)
{
    Log9(PCSC_LOG_DEBUG, "Ignoring IFDHSetProtocolParameters (Lun=%u Protocol=%u Flags=%u PTS1=%u PTS2=%u PTS3=%u)%s%s",
            (unsigned int) Lun, (unsigned int) Protocol, (unsigned char) Flags,
            (unsigned char) PTS1, (unsigned char) PTS2, (unsigned char) PTS3, "", "");
    return IFD_SUCCESS;
}

RESPONSECODE
IFDHPowerICC (DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength)
{
    size_t slot = Lun & 0xffff;
    struct vicc_ctx *slot_ctx = NULL;
    RESPONSECODE r = IFD_COMMUNICATION_ERROR;

    if (slot >= vicc_max_slots) {
        goto err;
    }

    slot_ctx = vpcd_get_slot_ctx(slot);
    if (!slot_ctx) {
        Log1(PCSC_LOG_INFO, "Middlepoint is not ready yet, cannot power ICC");
        goto err;
    }

    switch (Action) {
        case IFD_POWER_DOWN:
            if (vicc_poweroff(slot_ctx) < 0) {
                Log1(PCSC_LOG_ERROR, "could not powerdown");
                goto err;
            }

            /* XXX see bug #312754 on https://alioth.debian.org/projects/pcsclite */
#if 0
            *AtrLength = 0;

#endif
            return IFD_SUCCESS;
        case IFD_POWER_UP:
            if (vicc_poweron(slot_ctx) < 0) {
                Log1(PCSC_LOG_ERROR, "could not powerup");
                goto err;
            }
            break;
        case IFD_RESET:
            if (vicc_reset(slot_ctx) < 0) {
                Log1(PCSC_LOG_ERROR, "could not reset");
                goto err;
            }
            break;
        default:
            Log2(PCSC_LOG_ERROR, "%0lX not supported", Action);
            r = IFD_NOT_SUPPORTED;
            goto err;
    }

    r = IFD_SUCCESS;

err:
    if (r != IFD_SUCCESS && AtrLength)
        *AtrLength = 0;
    else
        r = IFDHGetCapabilities (Lun, TAG_IFD_ATR, AtrLength, Atr);

    return r;
}

RESPONSECODE
IFDHTransmitToICC (DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer,
        DWORD TxLength, PUCHAR RxBuffer, PDWORD RxLength,
        PSCARD_IO_HEADER RecvPci)
{
    unsigned char *rapdu = NULL;
    ssize_t size;
    RESPONSECODE r = IFD_COMMUNICATION_ERROR;
    size_t slot = Lun & 0xffff;
    struct vicc_ctx *slot_ctx = NULL;

    if (slot >= vicc_max_slots) {
        goto err;
    }

    if (!RxLength || !RecvPci) {
        Log1(PCSC_LOG_ERROR, "Invalid input data");
        goto err;
    }

    slot_ctx = vpcd_get_slot_ctx(slot);
    if (!slot_ctx) {
        Log1(PCSC_LOG_INFO, "Middlepoint is not ready yet, cannot transmit APDU");
        goto err;
    }

    size = vicc_transmit(slot_ctx, TxLength, TxBuffer, &rapdu);

    if (size < 0) {
        Log1(PCSC_LOG_ERROR, "could not send apdu or receive rapdu");
        goto err;
    }

    if (*RxLength < size) {
        Log1(PCSC_LOG_ERROR, "Not enough memory for rapdu");
        goto err;
    }

    *RxLength = size;
    memcpy(RxBuffer, rapdu, size);
    RecvPci->Protocol = 1;

    r = IFD_SUCCESS;

err:
    if (r != IFD_SUCCESS && RxLength)
        *RxLength = 0;

    free(rapdu);

    return r;
}

RESPONSECODE
IFDHICCPresence (DWORD Lun)
{
    size_t slot = Lun & 0xffff;
    struct vicc_ctx *slot_ctx = NULL;
    if (slot >= vicc_max_slots) {
        return IFD_COMMUNICATION_ERROR;
    }

    slot_ctx = vpcd_get_slot_ctx(slot);
    if (!slot_ctx) {
        return IFD_ICC_NOT_PRESENT;
    }

    switch (vicc_present(slot_ctx)) {
        case 0:
            return IFD_ICC_NOT_PRESENT;
        case 1:
            return IFD_ICC_PRESENT;
        default:
            Log1(PCSC_LOG_ERROR, "Could not get ICC state");
            return IFD_COMMUNICATION_ERROR;
    }
}
