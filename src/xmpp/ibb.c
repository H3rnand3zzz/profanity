/*
 * ibb.c
 * vim: expandtab:ts=4:sts=4:sw=4
 *
 * Copyright (C) 2023 Michael Vetter <jubalh@iodoru.org>
 *
 * This file is part of Profanity.
 *
 * Profanity is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Profanity is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Profanity.  If not, see <https://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give permission to
 * link the code of portions of this program with the OpenSSL library under
 * certain conditions as described in each individual source file, and
 * distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all of the
 * code used other than OpenSSL. If you modify file(s) with this exception, you
 * may extend this exception to your version of the file(s), but you are not
 * obligated to do so. If you do not wish to do so, delete this exception
 * statement from your version. If you delete this exception statement from all
 * source files in the program, then also delete it here.
 *
 * @file
 *
 * @brief In-Band Bytestreams (XEP-0047) Implementation
 *
 * More details: https://xmpp.org/extensions/xep-0047.html
 */

#include "common.h"
#include "log.h"
#include "config/files.h"
#include "ui/ui.h"
#include "xmpp/connection.h"
#include "xmpp/ibb.h"
#include "xmpp/iq.h"
#include "xmpp/jingle.h"
#include "xmpp/stanza.h"

#include <assert.h>
#include <errno.h>
#include <strophe.h>
#include <sys/stat.h>

typedef struct
{
    const prof_jingle_file_info_t* file;
    uint16_t seq;
    FILE* stream;
} ibb_session_t;

static void _send_ack(const char* id, const char* target);
static void _send_error(const char* id, const char* target, const char* error_type, const char* error_name);
static void _send_close(const char* id, const char* target, const char* sid);

static void _on_bytestream_open(xmpp_stanza_t* stanza);
static void _on_bytestream_data(xmpp_stanza_t* stanza);
static void _on_bytestream_close();

static char* _get_file_location_by_file_name(char* file_name);
static gboolean _convert_str_to_uint16(const char* str, uint16_t* result);

static void _ibb_session_destroy(ibb_session_t* session);

GHashTable* ibb_sessions;

void
ibb_init(void)
{
    log_info("[IBB] initialising");
    assert(ibb_sessions == NULL);
    ibb_sessions = g_hash_table_new_full(g_str_hash, g_str_equal, free, (GDestroyNotify)_ibb_session_destroy); // TODO: do correct one
}

void
ibb_close(void)
{
    log_info("[IBB] closing");
    if (ibb_sessions) {
        g_hash_table_destroy(ibb_sessions);
        ibb_sessions = NULL;
    }
}

void
handle_ibb(xmpp_stanza_t* stanza)
{
    xmpp_stanza_t* ibb_stanza = xmpp_stanza_get_child_by_ns(stanza, STANZA_NS_IBB);
    if (!ibb_stanza) {
        return;
    }

    const char* tag_name = xmpp_stanza_get_name(ibb_stanza);
    if (!tag_name) {
        log_warning("IBB: empty tag name.");
        return;
    }

    if (g_strcmp0(tag_name, "open") == 0) {
        _on_bytestream_open(stanza);
    } else if (g_strcmp0(tag_name, "data") == 0) {
        _on_bytestream_data(stanza);
    } else if (g_strcmp0(tag_name, "close") == 0) {
        _on_bytestream_close(stanza);
    } else {
        log_warning("IBB: unknown tag name (%s)", tag_name);
    }

    return;
}

static void
_on_bytestream_open(xmpp_stanza_t* stanza)
{
    /*
        <iq from='romeo@montague.net/orchard'
                    id='jn3h8g65'
                    to='juliet@capulet.com/balcony'
                    type='set'>
                <open xmlns='http://jabber.org/protocol/ibb'
                      block-size='4096'
                      sid='i781hf64'
                      stanza='iq'/>
        </iq>

        accept/deny (based on sid)
        get size, file name, block size and other data from jingle
        check block size (jingle) == block size (stanza)

    */

    xmpp_stanza_t* ibb_stanza = xmpp_stanza_get_child_by_ns(stanza, STANZA_NS_IBB);

    const char* id = xmpp_stanza_get_id(stanza);
    const char* from = xmpp_stanza_get_from(stanza);

    const char* sid = xmpp_stanza_get_attribute(ibb_stanza, "sid");

    if (g_hash_table_contains(ibb_sessions, (gconstpointer)sid)) {
        _send_error(id, from, "cancel", "not-acceptable");
        log_error("IBB: double session initiation.");
        return;
    }

    const char* stanza_block_size = xmpp_stanza_get_attribute(ibb_stanza, "block-size");
    const prof_jingle_content_t* content = get_content_by_transport_id(sid);

    if (!content) {
        _send_error(id, from, "cancel", "not-acceptable");
        return;
    }

    if (content->transport->type != PROF_JINGLE_TRANSPORT_TYPE_INBANDBYTESTREAM) {
        _send_error(id, from, "cancel", "not-acceptable");
        return;
    }

    auto_gchar gchar* content_block_size = g_strdup_printf("%u", content->transport->blocksize);

    if (g_strcmp0(content_block_size, stanza_block_size) != 0) {
        _send_error(id, from, "modify", "resource-constraint");
        return;
    }

    ibb_session_t* session = (ibb_session_t*)malloc(sizeof(ibb_session_t));
    session->file = (prof_jingle_file_info_t*)content->description->description;
    session->seq = 0;
    session->stream = NULL;

    g_hash_table_insert(ibb_sessions, strdup(sid), session);

    _send_ack(id, from);
}

static void
_on_bytestream_data(xmpp_stanza_t* stanza)
{
    /*
    ```xml
        <iq from='romeo@montague.net/orchard'
            id='kr91n475'
            to='juliet@capulet.com/balcony'
            type='set'>
            <data xmlns='http://jabber.org/protocol/ibb' seq='0' sid='i781hf64'>
                qANQR1DBwU4DX7jmYZnncmUQB/9KuKBddzQH+tZ1ZywKK0yHKnq57kWq+RFtQdCJ
                WpdWpR0uQsuJe7+vh3NWn59/gTc5MDlX8dS9p0ovStmNcyLhxVgmqS8ZKhsblVeu
                IpQ0JgavABqibJolc3BKrVtVV1igKiX/N7Pi8RtY1K18toaMDhdEfhBRzO/XB0+P
                AQhYlRjNacGcslkhXqNjK5Va4tuOAPy2n1Q8UUrHbUd0g+xJ9Bm0G0LZXyvCWyKH
                kuNEHFQiLuCY6Iv0myq6iX6tjuHehZlFSh80b5BVV9tNLwNR5Eqz1klxMhoghJOA
            </data>
        </iq>
    ```

        get session data by sid
        write data to file (based on session data)
        send ack
    */
    const char* id = xmpp_stanza_get_id(stanza);
    const char* from = xmpp_stanza_get_from(stanza);

    xmpp_stanza_t* data_stanza = xmpp_stanza_get_child_by_name_and_ns(stanza, "data", XMPP_FEATURE_IBB);
    if (!data_stanza) {
        log_warning("IBB: empty data received from %s.", from);
        return;
    }

    const char* sid = xmpp_stanza_get_attribute(data_stanza, "sid");
    if (!sid) {
        return;
    }

    const char* seq_raw = xmpp_stanza_get_attribute(data_stanza, "seq");
    uint16_t seq;
    if (!seq_raw || !_convert_str_to_uint16(seq_raw, &seq)) {
        log_warning("IBB: couldn't convert the sequence number.");
        return;
    }

    const char* raw_data = xmpp_stanza_get_text(data_stanza);

    gsize data_size;
    auto_guchar guchar* data = g_base64_decode(raw_data, &data_size);

    cons_show("Seq_raw: %s\nSeq: %u\nRaw Data (cut for now): %s\nData (size: %d): %.*s", seq_raw, seq, NULL, (int)data_size, (int)data_size, data);
    log_error("Raw Data (b64): %s", raw_data);

    if (!data) {
        _send_error(id, from, "cancel", "bad-request");
        return;
    }

    ibb_session_t* session = g_hash_table_lookup(ibb_sessions, sid);
    if (!session) {
        _send_error(id, from, "cancel", "item-not-found");
        return;
    }

    if (seq == 0) {
        if (session->seq != 0) {
            _send_close(id, from, sid);
            return;
        }
        auto_char char* file_location = _get_file_location_by_file_name(session->file->name);
        cons_show("File location: %s", file_location);
        session->stream = fopen(file_location, "wb");
        if (!session->stream) {
            _send_close(id, from, sid);
            return;
        }
    } else if (session->seq + 1 != seq) {
        _send_close(id, from, sid); // TODO: also close session
        log_warning("[IBB] closing session, wrong sequence received: %u (Previous: %u)", seq, session->seq);
        return;
    } else {
        session->seq++;
    }

    if (!session->stream) {
        _send_close(id, from, sid);
        return;
    }

    // TODO: move this part to the Jingle session negotiation
    unsigned long file_size;
    gboolean res = string_to_ul(session->file->size, &file_size);
    if (!res) {
        cons_show("[IBB] Couldn't convert file size. Closing the session. File size: %s", session->file->size);
        _send_close(id, from, sid);
        return;
    }

    fprintf(session->stream, "%.*s", (int)data_size, data);
    long pos = ftell(session->stream);
    cons_show("[IBB] Writing %s (Part %u; Pos/size: %ld/%lu) on disk", session->file->name, session->seq, pos, file_size);

    _send_ack(id, from);

    if (pos >= file_size) {
        cons_show("[IBB] Download of %s finished (Pos/size: %ld/%lu). Closing the stream.", session->file->name, pos, file_size);
        _send_close(id, from, sid);
    }
}

static void
_on_bytestream_close(xmpp_stanza_t* stanza)
{
    const char* id = xmpp_stanza_get_id(stanza);
    const char* from = xmpp_stanza_get_from(stanza);

    xmpp_stanza_t* close_stanza = xmpp_stanza_get_child_by_name(stanza, "close");
    const char* sid = xmpp_stanza_get_attribute(close_stanza, "sid");
    if (!sid) {
        _send_error(id, from, "cancel", "item-not-found");
        return;
    }

    ibb_session_t* session = g_hash_table_lookup(ibb_sessions, sid);
    if (!session) {
        _send_error(id, from, "cancel", "item-not-found");
        return;
    }

    // TODO: clear/close the Jingle session
    g_hash_table_remove(ibb_sessions, sid);
    set_content_state_by_transport_id(sid, PROF_JINGLE_STATE_TRANSFER_FINISHED);

    _send_ack(id, from);
}

/**
 * @brief Send a result IQ response stanza.
 *
 * @param id The original stanza ID.
 * @param target The JID to which the response is sent.
 */
static void
_send_ack(const char* id, const char* target)
{
    if (id == NULL || target == NULL) {
        log_error("Improper usage of _send_ack. One of parameters is empty.");
        return;
    }
    xmpp_ctx_t* ctx = connection_get_ctx();
    xmpp_stanza_t* iq = xmpp_iq_new(ctx, STANZA_TYPE_RESULT, id);
    xmpp_stanza_set_to(iq, target);
    iq_send_stanza(iq);
    xmpp_stanza_release(iq);
}

/**
 * @brief Send an error IQ response stanza with specified attributes.
 *
 * @param id The original stanza ID.
 * @param target The JID to which the response is sent.
 * @param error_type The type of error (e.g., "cancel", "modify").
 * @param error_name The name of the specific error (e.g., "service-unavailable").
 */
static void
_send_error(const char* id, const char* target, const char* error_type, const char* error_name)
{
    if (id == NULL || target == NULL || error_type == NULL || error_name == NULL) {
        log_error("Improper usage of _send_error. One of parameters is empty.");
        return;
    }
    xmpp_ctx_t* ctx = connection_get_ctx();

    xmpp_stanza_t* iq = xmpp_iq_new(ctx, STANZA_TYPE_ERROR, id);
    xmpp_stanza_set_to(iq, target);

    xmpp_stanza_t* error = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(error, STANZA_NAME_ERROR);
    xmpp_stanza_set_type(error, error_type);

    xmpp_stanza_t* error_child = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(error_child, error_name);
    xmpp_stanza_set_ns(error_child, XMPP_NS_STANZAS_IETF);

    xmpp_stanza_add_child(error, error_child);
    xmpp_stanza_add_child(iq, error);

    iq_send_stanza(iq);

    xmpp_stanza_release(error_child);
    xmpp_stanza_release(error);
    xmpp_stanza_release(iq);
}

static void
_send_close(const char* id, const char* target, const char* sid)
{
    if (id == NULL || target == NULL || sid == NULL) {
        log_error("Improper usage of _send_close. One of the parameters is empty.");
        return;
    }

    xmpp_ctx_t* ctx = connection_get_ctx();
    xmpp_stanza_t* iq = xmpp_iq_new(ctx, STANZA_TYPE_SET, id);
    xmpp_stanza_set_to(iq, target);

    xmpp_stanza_t* close_stanza = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(close_stanza, "close");
    xmpp_stanza_set_ns(close_stanza, STANZA_NS_IBB);
    xmpp_stanza_set_attribute(close_stanza, "sid", sid);

    xmpp_stanza_add_child(iq, close_stanza);

    iq_send_stanza(iq);

    xmpp_stanza_release(close_stanza);
    xmpp_stanza_release(iq);

    ibb_session_t* session = g_hash_table_lookup(ibb_sessions, sid);
    if (!session) {
        return;
    }

    // TODO: clear/close the Jingle session
    g_hash_table_remove(ibb_sessions, sid);
    set_content_state_by_transport_id(sid, PROF_JINGLE_STATE_TRANSFER_FINISHED);
}

// Utils
// TODO. DANGEROUS!!!!
static char*
_get_file_location_by_file_name(char* file_name)
{
    auto_gchar gchar* downloads_dir = files_get_data_path(DIR_DOWNLOADS);
    if (g_mkdir_with_parents(downloads_dir, S_IRWXU) != 0) {
        cons_show_error("IBB: Failed to create download directory "
                        "at '%s' with error '%s'",
                        downloads_dir, strerror(errno));
        return NULL;
    }

    return unique_filename_from_url(file_name, downloads_dir);
}

// Cleanup Functions

// todo
static void
_ibb_session_destroy(ibb_session_t* session)
{
    if (!session) {
        return;
    }

    if (session->file) {
        cons_show("destroying a session for a file: %s", session->file->name);
    } else {
        cons_show("destroying unknown session", session);
    }

    if (session->stream) {
        fclose(session->stream);
    }
}

static gboolean
_convert_str_to_uint16(const char* str, uint16_t* result)
{
    char* endptr;
    errno = 0;
    long value = strtol(str, &endptr, 10);

    if (errno != 0 || *endptr != '\0') {
        log_warning("IBB: conversion error for data sequence number.");
        return FALSE;
    }

    if (value < 0 || value > 65535) {
        log_warning("IBB: data sequence is out of range.");
        return FALSE;
    }

    *result = (uint16_t)value;
    return TRUE;
}