#include "ws_client.h"
#include <libwebsockets.h>
#include <switch_json.h>
#include <string.h>
#include <stdlib.h>

/**
 * Parse WebSocket URL into components.
 * Supports ws:// and wss:// schemes.
 *
 * @param url       Input URL (e.g., "wss://api.example.com:8443/v1/session")
 * @param host      Output buffer for hostname
 * @param host_len  Size of host buffer
 * @param port      Output pointer for port number
 * @param path      Output buffer for path
 * @param path_len  Size of path buffer
 * @param use_ssl   Output pointer for SSL flag (1=wss, 0=ws)
 * @return 0 on success, -1 on error
 */
static int parse_ws_url(const char *url, char *host, size_t host_len,
                        int *port, char *path, size_t path_len, int *use_ssl)
{
    const char *p = url;
    const char *host_start, *host_end;
    const char *port_start = NULL;
    const char *path_start;
    size_t host_copy_len;

    if (!url || !host || !port || !path || !use_ssl) {
        return -1;
    }

    /* Default values */
    *use_ssl = 0;
    *port = 80;
    path[0] = '/';
    path[1] = '\0';

    /* Parse scheme */
    if (strncmp(p, "wss://", 6) == 0) {
        *use_ssl = 1;
        *port = 443;
        p += 6;
    } else if (strncmp(p, "ws://", 5) == 0) {
        *use_ssl = 0;
        *port = 80;
        p += 5;
    } else {
        return -1; /* Invalid scheme */
    }

    host_start = p;

    /* Find end of host (port separator, path separator, or end of string) */
    host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/') {
        host_end++;
    }

    /* Extract port if present */
    if (*host_end == ':') {
        port_start = host_end + 1;
        const char *port_end = port_start;
        while (*port_end && *port_end != '/') {
            port_end++;
        }
        *port = atoi(port_start);
        if (*port <= 0 || *port > 65535) {
            return -1; /* Invalid port */
        }
        path_start = port_end;
    } else {
        path_start = host_end;
    }

    /* Copy host */
    host_copy_len = (size_t)(host_end - host_start);
    if (host_copy_len >= host_len) {
        return -1; /* Host too long */
    }
    memcpy(host, host_start, host_copy_len);
    host[host_copy_len] = '\0';

    /* Copy path */
    if (*path_start == '/') {
        size_t path_copy_len = strlen(path_start);
        if (path_copy_len >= path_len) {
            return -1; /* Path too long */
        }
        strncpy(path, path_start, path_len - 1);
        path[path_len - 1] = '\0';
    }
    /* else keep default "/" */

    return 0;
}

// LWS protocols
enum {
    PROTOCOL_LIVETRANSLATE,
    PROTOCOL_COUNT
};

struct per_session_data__livetranslate {
    livetranslate_session_t *lt;
};

static int callback_livetranslate(struct lws *wsi, enum lws_callback_reasons reason,
                                  void *user, void *in, size_t len)
{
    struct per_session_data__livetranslate *pss = (struct per_session_data__livetranslate *)user;
    livetranslate_session_t *lt = NULL;
    
    if (pss) lt = pss->lt;

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "WS connected\n");
        if (lt) {
            lt->ws_connected = SWITCH_TRUE;
            lws_callback_on_writable(wsi);
            
            // Send Config
            // We need to construct JSON
            cJSON *json = cJSON_CreateObject();
            cJSON_AddStringToObject(json, "type", "config");
            cJSON_AddStringToObject(json, "direction", lt->direction ? lt->direction : "caller_to_agent");
            cJSON_AddStringToObject(json, "src_lang", lt->src_lang ? lt->src_lang : "en-US");
            cJSON_AddStringToObject(json, "dst_lang", lt->dst_lang ? lt->dst_lang : "fr-FR");
            if (lt->api_key) cJSON_AddStringToObject(json, "api_key", lt->api_key);
            cJSON_AddStringToObject(json, "session_id", lt->session_id ? lt->session_id : lt->uuid_str);
            // Options...
            
            char *json_str = cJSON_PrintUnformatted(json);
            
            // Send TEXT frame
            unsigned char *buf = malloc(LWS_PRE + strlen(json_str));
            memcpy(buf + LWS_PRE, json_str, strlen(json_str));
            lws_write(wsi, buf + LWS_PRE, strlen(json_str), LWS_WRITE_TEXT);
            
            free(buf);
            free(json_str);
            cJSON_Delete(json);
        }
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        // Handle incoming data (Text or Binary)
        if (lws_frame_is_binary(wsi)) {
            // PCM
             if (lt) {
                // Copy data to incoming queue
                pcm_chunk_t *chunk = malloc(sizeof(pcm_chunk_t) + len);
                if (chunk) {
                    chunk->len = len;
                    memcpy(chunk->data, in, len);
                     if (switch_queue_trypush(lt->incoming_pcm_queue, chunk) != SWITCH_STATUS_SUCCESS) {
                        free(chunk);
                     }
                }
             }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "WS RX Text: %.*s\n", (int)len, (char *)in);
            
            // Handle events
            cJSON *json = cJSON_Parse((const char *)in);
            if (json) {
                const cJSON *type = cJSON_GetObjectItem(json, "type");
                if (type && type->valuestring) {
                    if (!strcmp(type->valuestring, "caption")) {
                        // Emit Custom Event
                        switch_event_t *event;
                        if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, "LIVETRANSLATE") == SWITCH_STATUS_SUCCESS) {
                            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Unique-ID", lt->uuid_str);
                            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Session-ID", lt->session_id);
                            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Direction", lt->direction);
                            
                            cJSON *mode = cJSON_GetObjectItem(json, "mode");
                            if (mode) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Mode", mode->valuestring);
                            
                            cJSON *src = cJSON_GetObjectItem(json, "src_text");
                            if (src) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Src-Text", src->valuestring);
                            
                            cJSON *dst = cJSON_GetObjectItem(json, "dst_text");
                            if (dst) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Dst-Text", dst->valuestring);
                            
                            // Also add body as raw JSON?
                            switch_event_add_body(event, "%.*s", (int)len, (char *)in);
                            
                            switch_event_fire(&event);
                        }
                    } else if (!strcmp(type->valuestring, "error")) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Livetranslate Error: %.*s\n", (int)len, (char *)in);
                        // Fire error event
                        switch_event_t *event;
                        if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, "LIVETRANSLATE_ERROR") == SWITCH_STATUS_SUCCESS) {
                             switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Unique-ID", lt->uuid_str);
                             switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Session-ID", lt->session_id);
                             cJSON *code = cJSON_GetObjectItem(json, "code");
                             if (code) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Error-Code", code->valuestring);
                             cJSON *msg = cJSON_GetObjectItem(json, "message");
                             if (msg) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Error-Message", msg->valuestring);
                             switch_event_fire(&event);
                        }
                    }
                }
                cJSON_Delete(json);
            }
        }
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        if (lt && lt->running) {
            void *pop;
            if (switch_queue_trypop(lt->outgoing_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
                if (pop) {
                    outgoing_pcm_chunk_t *chunk = (outgoing_pcm_chunk_t *)pop;
                    size_t pay_len = chunk->len;

                    unsigned char *buf = malloc(LWS_PRE + pay_len);
                    if (buf) {
                        memcpy(buf + LWS_PRE, chunk->data, pay_len);
                        lws_write(wsi, buf + LWS_PRE, pay_len, LWS_WRITE_BINARY);
                        free(buf);
                    }
                    free(chunk);

                    lws_callback_on_writable(wsi);
                }
            }
        }
        break;

    case LWS_CALLBACK_CLOSED:
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        if (lt) lt->ws_connected = SWITCH_FALSE;
        break;

    default:
        break;
    }

    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "livetranslate-protocol",
        callback_livetranslate,
        sizeof(struct per_session_data__livetranslate),
        1024,
    },
    { NULL, NULL, 0, 0 }
};

static void *SWITCH_THREAD_FUNC ws_thread_run(switch_thread_t *thread, void *obj)
{
    livetranslate_session_t *lt = (livetranslate_session_t *)obj;
    struct lws_context_creation_info info;
    struct lws_context *context;
    struct lws_client_connect_info i;
    char host[256];
    char path[256];
    int port = 0;
    int use_ssl = 0;
    const char *ws_url;

    (void)thread; /* unused parameter */

    /* Use configured URL or default */
    ws_url = lt->ws_url;
    if (!ws_url || !*ws_url) {
        ws_url = "ws://localhost:3000/v1/session";
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
            "No WebSocket URL configured, using default: %s\n", ws_url);
    }

    /* Parse the WebSocket URL */
    if (parse_ws_url(ws_url, host, sizeof(host), &port, path, sizeof(path), &use_ssl) != 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to parse WebSocket URL: %s\n", ws_url);
        return NULL;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
        "Connecting to WebSocket: host=%s port=%d path=%s ssl=%d\n",
        host, port, path, use_ssl);

    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    /* Enable SSL/TLS client support */
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    context = lws_create_context(&info);
    if (!context) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "LWS create context failed\n");
        return NULL;
    }

    memset(&i, 0, sizeof i);
    i.context = context;
    i.address = host;
    i.port = port;
    i.path = path;
    i.host = host;
    i.origin = host;
    i.ssl_connection = use_ssl ? (LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK) : 0;
    i.protocol = protocols[0].name;
    i.pwsi = (struct lws **)&lt->ws_handle;
    i.userdata = lt;

    lws_client_connect_via_info(&i);

    int n = 0;
    while (lt->running && n >= 0) {
        /* Adaptive timeout based on queue activity:
         * - Heavy load (>10 items): 0ms (immediate return, max throughput)
         * - Active (1-10 items): 10ms (responsive but efficient)
         * - Idle (0 items): 100ms (low CPU when nothing to do)
         */
        unsigned int queue_size = switch_queue_size(lt->outgoing_pcm_queue);
        int timeout_ms = (queue_size > 10) ? 0 : (queue_size > 0) ? 10 : 100;

        n = lws_service(context, timeout_ms);
    }

    lws_context_destroy(context);
    return NULL;
}

switch_status_t ws_client_start(livetranslate_session_t *lt)
{
    switch_thread_create(&lt->ws_send_thread, NULL, ws_thread_run, lt, lt->pool);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t ws_client_stop(livetranslate_session_t *lt)
{
    switch_status_t st;
    lt->running = SWITCH_FALSE;
    switch_thread_join(&st, lt->ws_send_thread);
    return SWITCH_STATUS_SUCCESS;
}
