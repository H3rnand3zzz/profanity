/*
 * jingle.c
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
 * Jingle Protocol (XEP-0166) Implementation
 */

// #include "config.h"
#include "assert.h"
#include "common.h"
#include "log.h"
#include "ui/ui.h"
#include "xmpp/connection.h"
#include "xmpp/iq.h"
#include "xmpp/jingle.h"
#include "xmpp/stanza.h"

#include <string.h>
// #include <stdlib.h>
#include <glib.h>
#include <strophe.h>

static void _handle_session_init(xmpp_stanza_t* const stanza);
static void _terminate_session(prof_jingle_session_t* session, const char* reason);
static gboolean _handle_terminate_session(xmpp_stanza_t* const stanza);
static void _send_ack(const char* id, const char* target);
static char* _get_child_text(xmpp_stanza_t* const stanza, char* child_name);
static xmpp_stanza_t* _add_child_with_text(xmpp_stanza_t* parent, const char* child_name, const char* child_text);
prof_jingle_creator_t _parse_content_creator(const char* creator_raw);
prof_jingle_senders_t _parse_content_senders(const char* senders_raw);
static const char* _stringify_senders(prof_jingle_senders_t senders);
static const char* _jingle_description_type_to_ns(prof_jingle_description_type_t description_type);
static const char* _jingle_transport_type_to_ns(prof_jingle_transport_type_t transport_type);
static char* uint_to_str(uint value);
static void _accept_session(prof_jingle_session_t* session);
static void* _get_item_by_transport_id(const char* transport_id, gboolean retrieve_content);
static xmpp_stanza_t* _xmpp_jingle_new(const char* action, const char* sid);

// cleanup functions
static void _cleanup_stanza_list(GList* stanza_list);
static void _jingle_session_destroy(prof_jingle_session_t* session);
static void _jingle_content_destroy(prof_jingle_content_t* content);
static void _jingle_description_destroy(prof_jingle_description_t* description);
static void _jingle_file_info_destroy(prof_jingle_file_info_t* file_info);
static void _jingle_transport_destroy(prof_jingle_transport_t* transport);
static void _jingle_transport_candidates_destroy(void** transport_candidates);

GHashTable* jingle_sessions;

void
jingle_init(void)
{
    log_info("Jingle initialising");
    assert(jingle_sessions == NULL);
    jingle_sessions = g_hash_table_new_full(g_str_hash, g_str_equal, free, (GDestroyNotify)_jingle_session_destroy);
}

void
jingle_close(void)
{
    if (jingle_sessions) {
        g_hash_table_destroy(jingle_sessions);
        jingle_sessions = NULL;
    }
}

const prof_jingle_content_t*
get_content_by_transport_id(const char* transport_id)
{
    return (const prof_jingle_content_t*)_get_item_by_transport_id(transport_id, TRUE);
}

static void*
_get_item_by_transport_id(const char* transport_id, gboolean retrieve_content)
{
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, jingle_sessions);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        prof_jingle_session_t* session = (prof_jingle_session_t*)value;

        GHashTableIter content_iter;
        gpointer content_key, content_value;
        g_hash_table_iter_init(&content_iter, session->content_table);
        while (g_hash_table_iter_next(&content_iter, &content_key, &content_value)) {
            const prof_jingle_content_t* content = (prof_jingle_content_t*)content_value;

            if (content->transport != NULL && strcmp(content->transport->sid, transport_id) == 0) {
                return retrieve_content ? (void*)content : (void*)session;
            }
        }
    }

    return NULL;
}

void
set_content_state_by_transport_id(const char* transport_id, prof_jingle_state_t state)
{
    prof_jingle_session_t* session = (prof_jingle_session_t*)_get_item_by_transport_id(transport_id, FALSE);

    gboolean all_downloads_finished = TRUE;
    GHashTableIter content_iter;
    gpointer content_key, content_value;
    g_hash_table_iter_init(&content_iter, session->content_table);
    while (g_hash_table_iter_next(&content_iter, &content_key, &content_value)) {
        prof_jingle_content_t* content = (prof_jingle_content_t*)content_value;

        if (content->transport != NULL && strcmp(content->transport->sid, transport_id) == 0) {
            content->state = state;
        }

        if (content->state != PROF_JINGLE_STATE_TRANSFER_FINISHED) {
            all_downloads_finished = FALSE;
        }
    }
    if (all_downloads_finished) {
        _terminate_session(session, "success");
    }
}

// Handlers

/*
 * XEP-0166 IQ stanzas handling.
 * @param stanza Stanza to handle
 * @returns true in case if the stanza was handled
 */
gboolean
handle_jingle_iq(xmpp_stanza_t* const stanza)
{
    // Check if the stanza is an IQ
    xmpp_stanza_t* jingle = xmpp_stanza_get_child_by_name_and_ns(stanza, "jingle", STANZA_NS_JINGLE);
    if (!jingle) {
        return FALSE;
    }

    // Check if the "jingle" element has the action attribute set to "session-initiate"
    const char* action = xmpp_stanza_get_attribute(jingle, "action");

    if (!action) {
        return FALSE;
    }

    // todo: initiator check

    if (strcmp(action, "session-initiate") == 0) {
        _handle_session_init(stanza);
    } else if (strcmp(action, "session-terminate") == 0) {
        _handle_terminate_session(stanza);
    } else if (strcmp(action, "session-info") == 0) {
        // session info
    } else if (strcmp(action, "session-accept") == 0) {
        // session accept
    } else if (strcmp(action, "transport-accept") == 0) {
    } else if (strcmp(action, "transport-info") == 0) {
    } else if (strcmp(action, "transport-reject") == 0) {
    } else if (strcmp(action, "transport-replace") == 0) {
    }
    return TRUE;
}

/*
 * XEP-0353 message handling stub.
 * @param stanza Stanza to handle
 * @returns true in case if it was XEP-0353 stanza
 */
gboolean
handle_jingle_message(xmpp_stanza_t* const stanza)
{
    xmpp_stanza_t* propose = xmpp_stanza_get_child_by_name_and_ns(stanza, STANZA_NAME_PROPOSE, STANZA_NS_JINGLE_MESSAGE);
    if (!propose) {
        return FALSE;
    }

    xmpp_stanza_t* description_stanza = xmpp_stanza_get_child_by_ns(propose, STANZA_NS_JINGLE_RTP);
    if (!description_stanza) {
        return FALSE;
    }

    const char* const from = xmpp_stanza_get_from(stanza);
    cons_show("Ring ring: %s is trying to call you", from);
    cons_alert(NULL);
    return TRUE;
}

static void
_handle_session_init(xmpp_stanza_t* const stanza)
{
    const char* from = xmpp_stanza_get_from(stanza);
    // presence of jingle stanza is presumed
    xmpp_stanza_t* jingle = xmpp_stanza_get_child_by_name_and_ns(stanza, "jingle", STANZA_NS_JINGLE);
    const char* sid = xmpp_stanza_get_attribute(jingle, "sid");
    if (!sid) {
        cons_debug("JINGLE: malformed stanza, no jingle sid.");
        return;
    }

    const char* initiator = xmpp_stanza_get_attribute(jingle, "initiator");
    if (!initiator) {
        cons_debug("JINGLE: malformed stanza, no jingle initiator.");
        return;
    }
    auto_jid Jid* initiator_jid = jid_create(initiator);
    if (g_strcmp0(initiator, from) != 0) {
        cons_debug("JINGLE: malformed stanza, initiator on opening stanza does not match IQ sender. (Initiator: %s; IQ Sender: %s)", initiator, from);
        return;
    }

    xmpp_stanza_t* content_stanza = xmpp_stanza_get_children(jingle);

    _send_ack(xmpp_stanza_get_id(stanza), from);

    prof_jingle_session_t* session = malloc(sizeof(prof_jingle_session_t));
    session->initiator = strdup(initiator);
    session->jingle_sid = strdup(sid);
    session->state = PROF_JINGLE_STATE_INITIATED;
    session->content_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, (GDestroyNotify)_jingle_content_destroy);
    g_hash_table_insert(jingle_sessions, strdup(sid), session);

    // TODO: check content creator (file request/file send)

    if (!content_stanza) {
        _terminate_session(session, "cancel");
        cons_debug("JINGLE: malformed stanza, no content.");
        return;
    }

    cons_show("handling session init");

    while (content_stanza) {
        const char* tag = xmpp_stanza_get_name(content_stanza);
        if (tag == NULL || strcmp(tag, "content") != 0) {
            cons_debug("skipped iteration for %s", tag);
            content_stanza = xmpp_stanza_get_next(content_stanza);
            continue;
        }

        cons_debug("jingle: iterating content");
        xmpp_stanza_t* description_stanza = xmpp_stanza_get_child_by_name(content_stanza, "description");
        if (!description_stanza) {
            cons_show("Jingle: No description, malformed.");
            continue;
        }

        xmpp_stanza_t* transport_stanza = xmpp_stanza_get_child_by_name(content_stanza, "transport");
        if (!transport_stanza) {
            cons_show("Jingle: No transport, malformed.");
            continue;
        }

        const char* transport_ns = xmpp_stanza_get_ns(transport_stanza);
        if (!transport_ns) {
            cons_show("Jingle: malformed, transport don't have NS.");
            content_stanza = xmpp_stanza_get_next(content_stanza);
            continue;
        }

        const char* description_ns = xmpp_stanza_get_ns(description_stanza);
        if (!description_ns) {
            cons_show("Jingle: malformed, description don't have NS.");
            continue;
        }

        if (strcmp(description_ns, STANZA_NS_JINGLE_FT5) != 0) {
            cons_show("Jingle: unsupported content (description) provided (NS: %s).", xmpp_stanza_get_ns(description_stanza));
            continue;
        }

        const char* content_name = xmpp_stanza_get_attribute(content_stanza, "name");
        if (!content_name) {
            cons_show("Jingle: malformed content, no name provided.");
            continue;
        }

        // parse content creator
        const char* content_creator_raw = xmpp_stanza_get_attribute(content_stanza, "creator");
        prof_jingle_creator_t content_creator = _parse_content_creator(content_creator_raw);
        if (content_creator == PROF_JINGLE_CREATOR_UNKNOWN) {
            cons_show("Jingle: malformed content, invalid creator provided.");
            continue;
        }

        // parse content senders
        const char* content_senders_raw = xmpp_stanza_get_attribute(content_stanza, "senders");
        prof_jingle_senders_t content_senders = _parse_content_senders(content_senders_raw);

        // optional argument, no checks necessary

        // file stanza
        xmpp_stanza_t* file_stanza = xmpp_stanza_get_child_by_name(description_stanza, "file");
        if (!file_stanza) {
            cons_show("JINGLE: Malformed stanza, no file data in the file transfer description.");
            content_stanza = xmpp_stanza_get_next(content_stanza);
            continue;
        }

        // parse file data
        prof_jingle_file_info_t* file_info = malloc(sizeof(prof_jingle_file_info_t));
        file_info->type = _get_child_text(file_stanza, "media-type");
        file_info->date = _get_child_text(file_stanza, "date");
        file_info->name = _get_child_text(file_stanza, "name");
        file_info->size = _get_child_text(file_stanza, "size");
        file_info->hash = _get_child_text(file_stanza, "hash");
        cons_show("File Offer Received from %s: \n    File name: %s\n    Date: %s\n    File type: %s\n    Size: %s\n    Hash: %s\nDo you want to receive it? Use `/files accept %s` to accept it or `/files cancel %s` to decline transfer.", from, file_info->name, file_info->date, file_info->type, file_info->size, file_info->hash, "ID", "ID");

        // save file data in struct
        prof_jingle_description_t* description = malloc(sizeof(prof_jingle_description_t));
        description->type = PROF_JINGLE_DESCRIPTION_TYPE_FILETRANSFER;
        description->description = file_info;

        if (strcmp(transport_ns, STANZA_NS_JINGLE_TRANSPORTS_IBB) == 0) {
            cons_show("transport is supported");
        } else {
            cons_show("Jingle: unsupported transport was offered (wrong NS: %s).", transport_ns);
            content_stanza = xmpp_stanza_get_next(content_stanza);
            continue; // cleanup?
        }

        const char* transport_sid = xmpp_stanza_get_attribute(transport_stanza, "sid");                   // check empty
        const char* transport_block_size_raw = xmpp_stanza_get_attribute(transport_stanza, "block-size"); // check empty
        // if not null (if candidates are present, it can be null)
        uint transport_block_size = atoi(transport_block_size_raw);

        cons_show("Transport SID: %s\nBlock Size: %s\nBlock size converted: %u", transport_sid, transport_block_size_raw, transport_block_size);

        prof_jingle_transport_t* transport = malloc(sizeof(prof_jingle_transport_t));
        transport->type = PROF_JINGLE_TRANSPORT_TYPE_INBANDBYTESTREAM;
        transport->sid = strdup(transport_sid);
        transport->blocksize = transport_block_size;
        transport->candidates = NULL;

        prof_jingle_content_t* content = malloc(sizeof(prof_jingle_content_t));
        content->name = strdup(content_name);
        content->creator = content_creator;
        content->senders = content_senders;
        content->description = description;
        content->transport = transport;

        g_hash_table_insert(session->content_table, strdup(content_name), content);

        content_stanza = xmpp_stanza_get_next(content_stanza);
    }
    // TODO: accept only from user command, current implementation is testing only
    _accept_session(session); // auto-accept
}

static gboolean
_handle_terminate_session(xmpp_stanza_t* const stanza)
{
    // delete
    return TRUE;
}

// XMPP Utils

/**
 * Sends an IQ stanza to accept a Jingle session.
 *
 * @param session The Jingle session to accept.
 */
static void
_accept_session(prof_jingle_session_t* session)
{
    xmpp_ctx_t* ctx = connection_get_ctx();

    auto_char char* my_jid = connection_get_barejid();

    auto_char char* id = connection_create_stanza_id();
    xmpp_stanza_t* iq_stanza = xmpp_iq_new(ctx, STANZA_TYPE_SET, id);
    xmpp_stanza_set_attribute(iq_stanza, "to", session->initiator);

    xmpp_stanza_t* jingle_stanza = _xmpp_jingle_new("session-accept", session->jingle_sid);
    xmpp_stanza_set_attribute(jingle_stanza, "responder", my_jid);

    GList* cleanup_list = NULL; // Linked list to keep track of stanzas for cleanup

    GHashTableIter content_iter;
    gpointer content_key, content_value;
    g_hash_table_iter_init(&content_iter, session->content_table);

    while (g_hash_table_iter_next(&content_iter, &content_key, &content_value)) {
        prof_jingle_content_t* content = (prof_jingle_content_t*)content_value;
        auto_char char* block_size = uint_to_str(content->transport->blocksize);

        xmpp_stanza_t* content_stanza = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(content_stanza, "content");
        xmpp_stanza_set_attribute(content_stanza, "creator", "initiator");
        xmpp_stanza_set_attribute(content_stanza, "senders", _stringify_senders(content->senders));
        xmpp_stanza_set_attribute(content_stanza, "name", content->name);
        xmpp_stanza_add_child(jingle_stanza, content_stanza);
        cleanup_list = g_list_prepend(cleanup_list, content_stanza);

        xmpp_stanza_t* description_stanza = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(description_stanza, "description");
        xmpp_stanza_set_ns(description_stanza, _jingle_description_type_to_ns(content->description->type));
        xmpp_stanza_add_child(content_stanza, description_stanza);
        cleanup_list = g_list_prepend(cleanup_list, description_stanza);

        xmpp_stanza_t* description_data_stanza = xmpp_stanza_new(ctx);
        if (content->description->type == PROF_JINGLE_DESCRIPTION_TYPE_FILETRANSFER) {
            prof_jingle_file_info_t* file_info = (prof_jingle_file_info_t*)content->description->description;
            xmpp_stanza_set_name(description_data_stanza, "file");

            xmpp_stanza_t* name_stanza = _add_child_with_text(description_data_stanza, "name", file_info->name);
            cleanup_list = g_list_prepend(cleanup_list, name_stanza);

            xmpp_stanza_t* media_type_stanza = _add_child_with_text(description_data_stanza, "media-type", file_info->type);
            cleanup_list = g_list_prepend(cleanup_list, media_type_stanza);

            xmpp_stanza_t* date_stanza = _add_child_with_text(description_data_stanza, "date", file_info->date);
            cleanup_list = g_list_prepend(cleanup_list, date_stanza);

            xmpp_stanza_t* size_stanza = _add_child_with_text(description_data_stanza, "size", file_info->size);
            cleanup_list = g_list_prepend(cleanup_list, size_stanza);

            if (file_info->hash) {
                xmpp_stanza_t* hash_stanza = _add_child_with_text(description_data_stanza, "hash", file_info->hash);
                cleanup_list = g_list_prepend(cleanup_list, hash_stanza);
            }
        }
        xmpp_stanza_add_child(description_stanza, description_data_stanza);
        cleanup_list = g_list_prepend(cleanup_list, description_data_stanza);

        xmpp_stanza_t* transport_stanza = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(transport_stanza, "transport");
        xmpp_stanza_set_ns(transport_stanza, _jingle_transport_type_to_ns(content->transport->type));
        xmpp_stanza_set_attribute(transport_stanza, "block-size", block_size);
        xmpp_stanza_set_attribute(transport_stanza, "sid", content->transport->sid);
        xmpp_stanza_add_child(content_stanza, transport_stanza);
        cleanup_list = g_list_prepend(cleanup_list, transport_stanza);
    }

    xmpp_stanza_add_child(iq_stanza, jingle_stanza);

    iq_send_stanza(iq_stanza);

    session->state = PROF_JINGLE_STATE_ACCEPTED;

    // cleanup
    _cleanup_stanza_list(cleanup_list);
    xmpp_stanza_release(jingle_stanza);
    xmpp_stanza_release(iq_stanza);
}

static void
_terminate_session(prof_jingle_session_t* session, const char* reason)
{
    xmpp_ctx_t* ctx = connection_get_ctx();

    auto_char char* id = connection_create_stanza_id();
    xmpp_stanza_t* iq_stanza = xmpp_iq_new(ctx, STANZA_TYPE_SET, id);
    xmpp_stanza_set_attribute(iq_stanza, "to", session->initiator);

    xmpp_stanza_t* jingle_stanza = _xmpp_jingle_new("session-terminate", session->jingle_sid);
    xmpp_stanza_add_child(iq_stanza, jingle_stanza);

    xmpp_stanza_t* reason_stanza = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(reason_stanza, "reason");
    xmpp_stanza_add_child(jingle_stanza, reason_stanza);

    xmpp_stanza_t* reason_name_stanza = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(reason_name_stanza, reason);
    xmpp_stanza_add_child(reason_stanza, reason_name_stanza);

    iq_send_stanza(iq_stanza);

    // cleanup
    xmpp_stanza_release(iq_stanza);
    xmpp_stanza_release(jingle_stanza);
    xmpp_stanza_release(reason_stanza);
    xmpp_stanza_release(reason_name_stanza);

    g_hash_table_remove(jingle_sessions, session->jingle_sid);
}

/**
 * Sends an acknowledgment IQ stanza.
 *
 * @param id The identifier of the original stanza to acknowledge.
 * @param target The target JID to send the acknowledgment to.
 */
static void
_send_ack(const char* id, const char* target)
{
    xmpp_ctx_t* ctx = connection_get_ctx();
    xmpp_stanza_t* iq = xmpp_iq_new(ctx, STANZA_TYPE_RESULT, id);
    xmpp_stanza_set_to(iq, target);
    iq_send_stanza(iq);
    xmpp_stanza_release(iq);
}

// Utils

static char*
_get_child_text(xmpp_stanza_t* const stanza, char* child_name)
{
    xmpp_stanza_t* child = xmpp_stanza_get_child_by_name(stanza, child_name);
    if (!child) {
        return NULL;
    }
    return xmpp_stanza_get_text(child);
}

static xmpp_stanza_t*
_add_child_with_text(xmpp_stanza_t* parent, const char* child_name, const char* child_text)
{
    xmpp_ctx_t* ctx = connection_get_ctx();
    xmpp_stanza_t* child_stanza = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(child_stanza, child_name);

    xmpp_stanza_t* txt = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(txt, child_text);
    xmpp_stanza_add_child(child_stanza, txt);
    xmpp_stanza_release(txt);

    xmpp_stanza_add_child(parent, child_stanza);
    return child_stanza;
}

static xmpp_stanza_t*
_xmpp_jingle_new(const char* action, const char* sid)
{
    xmpp_ctx_t* ctx = connection_get_ctx();
    xmpp_stanza_t* jingle = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(jingle, "jingle");
    xmpp_stanza_set_ns(jingle, STANZA_NS_JINGLE);
    xmpp_stanza_set_attribute(jingle, "sid", sid);
    xmpp_stanza_set_attribute(jingle, "action", action);

    return jingle;
}

prof_jingle_creator_t
_parse_content_creator(const char* creator_raw)
{
    if (!creator_raw) {
        cons_show("Jingle: malformed content, no creator provided.");
        return PROF_JINGLE_CREATOR_UNKNOWN;
    }

    if (strcmp(creator_raw, "initiator") == 0) {
        return PROF_JINGLE_CREATOR_INITIATOR;
    } else if (strcmp(creator_raw, "responder") == 0) {
        return PROF_JINGLE_CREATOR_RESPONDER;
    } else {
        return PROF_JINGLE_CREATOR_UNKNOWN;
    }
}

prof_jingle_senders_t
_parse_content_senders(const char* senders_raw)
{
    if (!senders_raw) {
        cons_show("Jingle: malformed content, no senders provided.");
        return PROF_JINGLE_SENDERS_UNKNOWN;
    }

    if (strcmp(senders_raw, "both") == 0) {
        return PROF_JINGLE_SENDERS_BOTH;
    } else if (strcmp(senders_raw, "initiator") == 0) {
        return PROF_JINGLE_SENDERS_INITIATOR;
    } else if (strcmp(senders_raw, "responder") == 0) {
        return PROF_JINGLE_SENDERS_RESPONDER;
    } else if (strcmp(senders_raw, "none") == 0) {
        return PROF_JINGLE_SENDERS_NONE;
    } else {
        cons_show("Jingle: malformed content, invalid senders provided.");
        return PROF_JINGLE_SENDERS_UNKNOWN;
    }
}

static const char*
_stringify_senders(prof_jingle_senders_t senders)
{
    switch (senders) {
    case PROF_JINGLE_SENDERS_BOTH:
        return "both";
    case PROF_JINGLE_SENDERS_INITIATOR:
        return "initiator";
    case PROF_JINGLE_SENDERS_RESPONDER:
        return "responder";
    case PROF_JINGLE_SENDERS_NONE:
        return "none";
    case PROF_JINGLE_SENDERS_UNKNOWN:
    default:
        return "unknown";
    }
}

static char*
uint_to_str(uint value)
{
    char* str = NULL;
    int num_chars = snprintf(NULL, 0, "%u", value);

    if (num_chars <= 0) {
        return NULL;
    }

    str = (char*)malloc(num_chars + 1);
    snprintf(str, num_chars + 1, "%u", value);

    return str;
}

static const char*
_jingle_transport_type_to_ns(prof_jingle_transport_type_t transport_type)
{
    switch (transport_type) {
    case PROF_JINGLE_TRANSPORT_TYPE_INBANDBYTESTREAM:
        return STANZA_NS_JINGLE_TRANSPORTS_IBB;
    case PROF_JINGLE_TRANSPORT_TYPE_SOCKS5:
        return STANZA_NS_JINGLE_TRANSPORTS_S5B;
    default:
        return NULL;
    }
}

static const char*
_jingle_description_type_to_ns(prof_jingle_description_type_t description_type)
{
    switch (description_type) {
    case PROF_JINGLE_DESCRIPTION_TYPE_FILETRANSFER:
        return STANZA_NS_JINGLE_FT5;
    case PROF_JINGLE_DESCRIPTION_TYPE_RTP:
        return STANZA_NS_JINGLE_RTP;
    default:
        return NULL;
    }
}

// Cleanup functions
static void
_cleanup_stanza_list(GList* stanza_list)
{
    GList* iter = stanza_list;
    while (iter != NULL) {
        xmpp_stanza_t* stanza_to_cleanup = (xmpp_stanza_t*)(iter->data);
        xmpp_stanza_release(stanza_to_cleanup);
        iter = g_list_next(iter);
    }
    g_list_free(stanza_list);
}

// TODO
static void
_jingle_transport_candidates_destroy(void** transport_candidates)
{
    if (!transport_candidates) {
        return;
    }
    return;
}

static void
_jingle_session_destroy(prof_jingle_session_t* session)
{

    if (!session) {
        return;
    }

    free(session->jingle_sid);
    free(session->initiator);
    g_hash_table_destroy(session->content_table);
    free(session);
}

static void
_jingle_content_destroy(prof_jingle_content_t* content)
{
    if (!content) {
        return;
    }

    free(content->name);
    _jingle_description_destroy(content->description);
    _jingle_transport_destroy(content->transport);
    free(content);
}

static void
_jingle_transport_destroy(prof_jingle_transport_t* transport)
{
    if (!transport) {
        return;
    }

    _jingle_transport_candidates_destroy(transport->candidates);
    free(transport->sid);
    free(transport);
}

static void
_jingle_description_destroy(prof_jingle_description_t* description)
{
    if (!description) {
        return;
    }

    if (description->type == PROF_JINGLE_DESCRIPTION_TYPE_FILETRANSFER) {
        _jingle_file_info_destroy((prof_jingle_file_info_t*)description->description);
    }
}

static void
_jingle_file_info_destroy(prof_jingle_file_info_t* file_info)
{
    if (!file_info) {
        return;
    }

    free(file_info->name);
    free(file_info->type);
    free(file_info->date);
    free(file_info->size);
    free(file_info->hash);
    free(file_info);
}