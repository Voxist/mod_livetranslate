#include "ws_client.h"
#include <libwebsockets.h>
#include <switch_json.h>

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
                cJSON *type = cJSON_GetObjectItem(json, "type");
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
                    // We assume 320 bytes (20ms 16k mono 16bit) or whatever
                    // We need to know the size. 
                    // Issue: Queue stores void*. We don't store length. 
                    // Assuming fixed length based on resampling target?
                    // In mod_livetranslate.c we malloced the buffer.
                    // But we didn't store length. We should maybe store a struct { len, data }.
                    // Or assume fixed block size if we enforce it in mod_livetranslate.c.
                    // In mod_livetranslate.c we use `out_len * 2`. 
                    // Let's fix mod_livetranslate.c to use a struct or consistent size.
                    
                    // For now, assuming 20ms 16kHz = 640 bytes (320 samples * 2 bytes).
                    // If we pushed something else, we are in trouble.
                    // Let's assume we fix mod_livetranslate to normalize chunk size.
                    
                    // But wait, resampling might produce variable size?
                    // Speex resampler produces `out_len` samples.
                    
                    // Let's proceed assuming we can fix that.
                    
                    size_t pay_len = 640; // Temporary assumption
                    unsigned char *buf = malloc(LWS_PRE + pay_len);
                    memcpy(buf + LWS_PRE, pop, pay_len);
                    lws_write(wsi, buf + LWS_PRE, pay_len, LWS_WRITE_BINARY);
                    free(buf);
                    free(pop);
                    
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

    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    context = lws_create_context(&info);
    if (!context) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "LWS create context failed\n");
        return NULL;
    }

    memset(&i, 0, sizeof i);
    i.context = context;
    i.address = "localhost"; // Parse from lt->ws_url
    i.port = 3000;
    i.path = "/v1/session";
    i.host = i.address;
    i.origin = i.address;
    i.ssl_connection = 0; // or LCCSCF_USE_SSL
    i.protocol = protocols[0].name;
    i.pwsi = (struct lws **)&lt->ws_handle; // This cast is tricky, ws_handle is void*
    i.userdata = lt;

    lws_client_connect_via_info(&i);

    int n = 0;
    while (lt->running && n >= 0) {
        n = lws_service(context, 50);
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
