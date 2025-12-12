#include "mod_livetranslate.h"
#include "ws_client.h"
#include <math.h>
#include <ctype.h>

livetranslate_globals_t globals;

/* Conference volume level to linear gain mapping (from FreeSWITCH source) */
static const float CONF_LEVEL_GAIN[] = {
    0.20f,  /* -4: approx -14 dB */
    0.40f,  /* -3: approx -8 dB */
    0.60f,  /* -2: approx -4.4 dB */
    0.80f,  /* -1: approx -1.9 dB */
    1.00f,  /*  0: 0 dB */
    1.30f,  /* +1: approx +2.3 dB */
    2.30f,  /* +2: approx +7.6 dB */
    3.30f,  /* +3: approx +10.4 dB */
    4.30f   /* +4: approx +12.7 dB */
};

/**
 * Convert dB to linear gain.
 * -20 dB = 0.1, -14 dB = 0.2, 0 dB = 1.0
 */
static float db_to_linear(float db) {
    return powf(10.0f, db / 20.0f);
}

/*
 * Input validation functions
 */

/**
 * Validate language code format (e.g., en-US, fr-FR, zh-CN).
 * Accepts 2-10 character codes with alphanumeric and hyphen.
 */
static switch_bool_t validate_language_code(const char *lang) {
    size_t len;
    const char *p;

    if (zstr(lang)) return SWITCH_FALSE;

    len = strlen(lang);
    if (len < 2 || len > LT_MAX_LANG_CODE_LENGTH) return SWITCH_FALSE;

    /* Allow alphanumeric and hyphen only */
    for (p = lang; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-') return SWITCH_FALSE;
    }

    return SWITCH_TRUE;
}

/**
 * Validate WebSocket URL format and length.
 * Must start with ws:// or wss://.
 */
static switch_bool_t validate_ws_url(const char *url) {
    if (zstr(url)) return SWITCH_FALSE;
    if (strlen(url) > LT_MAX_URL_LENGTH) return SWITCH_FALSE;
    if (strncmp(url, "ws://", 5) != 0 && strncmp(url, "wss://", 6) != 0) return SWITCH_FALSE;
    return SWITCH_TRUE;
}

/**
 * Validate identifier for safe use in API commands.
 * Prevents command injection by allowing only alphanumeric, underscore, hyphen.
 */
static switch_bool_t is_safe_identifier(const char *id) {
    const char *p;

    if (zstr(id)) return SWITCH_FALSE;

    for (p = id; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') return SWITCH_FALSE;
    }

    return SWITCH_TRUE;
}

/**
 * Validate numeric value is within acceptable range.
 */
static switch_bool_t validate_numeric_range(int val, int min, int max) {
    return (val >= min && val <= max);
}

/**
 * Validate float gain value is within acceptable range.
 */
static switch_bool_t validate_gain(float val) {
    return (val >= 0.0f && val <= 10.0f);
}

/**
 * Detect conference membership and cache identifiers.
 * Must be called after session joins a conference.
 */
static switch_status_t agc_detect_conference(livetranslate_session_t *lt)
{
    switch_channel_t *channel = switch_core_session_get_channel(lt->fs_session);
    const char *conf_name = switch_channel_get_variable(channel, "conference_name");
    const char *member_id = switch_channel_get_variable(channel, "conference_member_id");

    if (zstr(conf_name) || zstr(member_id)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session),
            SWITCH_LOG_DEBUG, "AGC: Channel not in conference (no conference_name or conference_member_id)\n");
        lt->conf_agc_enabled = SWITCH_FALSE;
        return SWITCH_STATUS_FALSE;
    }

    lt->conference_name = switch_core_session_strdup(lt->fs_session, conf_name);
    lt->conference_member_id = switch_core_session_strdup(lt->fs_session, member_id);
    lt->conf_agc_enabled = SWITCH_TRUE;

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_INFO,
        "AGC: Enabled for conference '%s', member ID %s\n", conf_name, member_id);

    return SWITCH_STATUS_SUCCESS;
}

/**
 * Set conference member volume_in level via API command.
 * Level is clamped to -4..+4 range.
 */
static switch_status_t agc_set_conference_volume(livetranslate_session_t *lt, int level)
{
    switch_stream_handle_t stream = { 0 };
    char *cmd = NULL;
    switch_status_t status;

    if (!lt->conf_agc_enabled || zstr(lt->conference_name) || zstr(lt->conference_member_id)) {
        return SWITCH_STATUS_FALSE;
    }

    /* Validate identifiers to prevent command injection */
    if (!is_safe_identifier(lt->conference_name) || !is_safe_identifier(lt->conference_member_id)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_ERROR,
            "AGC: Invalid conference name or member ID (potential injection attempt)\n");
        return SWITCH_STATUS_FALSE;
    }

    /* Clamp level to valid range */
    if (level < -4) level = -4;
    if (level > 4) level = 4;

    SWITCH_STANDARD_STREAM(stream);

    /* Use dynamic allocation to prevent buffer overflow */
    cmd = switch_mprintf("%s volume_in %s %d",
        lt->conference_name, lt->conference_member_id, level);

    if (!cmd) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_ERROR,
            "AGC: Failed to allocate command buffer\n");
        return SWITCH_STATUS_MEMERR;
    }

    status = switch_api_execute("conference", cmd, lt->fs_session, &stream);
    switch_safe_free(cmd);

    if (status == SWITCH_STATUS_SUCCESS) {
        lt->agc_conf_level = level;
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG,
            "AGC: Set conference '%s' member %s volume_in to %d\n",
            lt->conference_name, lt->conference_member_id, level);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_WARNING,
            "AGC: Failed to set conference volume: %s\n",
            stream.data ? (char *)stream.data : "unknown error");
    }

    switch_safe_free(stream.data);
    return status;
}

/**
 * Calculate the conference level and extra channel gain needed to achieve
 * a target linear gain. Returns the extra channel-level gain to apply.
 */
static float agc_calc_gain_split(float target_gain, int *conf_level_out)
{
    /* Conference level -4 gives us 0.2 (approx -14 dB) */
    /* If target is >= 0.2, we can achieve it with conference level alone */
    if (target_gain >= 0.20f) {
        /* Find the conference level that gets closest without going below target */
        for (int lvl = -4; lvl <= 4; lvl++) {
            float conf_gain = CONF_LEVEL_GAIN[lvl + 4];
            if (conf_gain >= target_gain) {
                *conf_level_out = lvl;
                /* Return the extra channel gain needed */
                return target_gain / conf_gain;
            }
        }
        /* Fallback: use level 0 */
        *conf_level_out = 0;
        return target_gain;
    } else {
        /* Target is below -14 dB, use level -4 plus extra channel attenuation */
        *conf_level_out = -4;
        /* Extra gain = target / 0.2 (conference level -4 gain) */
        return target_gain / 0.20f;
    }
}

/**
 * Called when translation audio starts playing.
 * Immediately ducks the conference volume.
 */
static void agc_on_translation_start(livetranslate_session_t *lt)
{
    int conf_level;

    if (!lt->conf_agc_enabled) return;

    lt->agc_translation_active = SWITCH_TRUE;

    if (lt->agc_state != AGC_STATE_DUCKED) {
        float extra_gain;

        lt->agc_state = AGC_STATE_DUCKED;

        /* Calculate conference level and extra channel gain */
        extra_gain = agc_calc_gain_split(lt->agc_ducked_gain, &conf_level);
        lt->agc_current_gain = extra_gain;

        agc_set_conference_volume(lt, conf_level);

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG,
            "AGC: Ducked to target gain %.3f (conf level %d, extra gain %.3f)\n",
            lt->agc_ducked_gain, conf_level, extra_gain);
    }
}

/**
 * Called when translation audio stops (ducking timer expired).
 * Initiates ramping back to normal volume.
 */
static void agc_on_translation_stop(livetranslate_session_t *lt)
{
    if (!lt->conf_agc_enabled) return;

    lt->agc_translation_active = SWITCH_FALSE;

    if (lt->agc_state == AGC_STATE_DUCKED) {
        lt->agc_state = AGC_STATE_RAMPING_UP;
        lt->agc_ramp_start = switch_micro_time_now();
        lt->agc_last_step = lt->agc_ramp_start;

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG,
            "AGC: Starting ramp-up from gain %.3f to %.3f over %dms\n",
            lt->agc_current_gain * CONF_LEVEL_GAIN[lt->agc_conf_level + 4],
            lt->agc_normal_gain, lt->agc_ramp_up_ms);
    }
}

/**
 * Process AGC ramping. Called from bug callback on every frame.
 * Uses discrete conference level steps with smooth channel-level interpolation.
 */
static void agc_process_ramp(livetranslate_session_t *lt)
{
    switch_time_t now;
    int elapsed_ms;
    float progress;
    float target_gain;
    int target_conf_level;

    if (!lt->conf_agc_enabled || lt->agc_state != AGC_STATE_RAMPING_UP) {
        return;
    }

    /* If translation restarted during ramp, go back to ducked */
    if (lt->agc_translation_active) {
        lt->agc_state = AGC_STATE_DUCKED;
        agc_on_translation_start(lt);
        return;
    }

    /* Optimization: only check time every 2 frames (~40ms at 20ms/frame)
     * This reduces syscalls while still being responsive enough for AGC ramp */
    lt->frame_counter++;
    if ((lt->frame_counter & 1) != 0) {
        return; /* Skip odd frames */
    }

    now = switch_micro_time_now();
    elapsed_ms = (int)((now - lt->agc_ramp_start) / 1000);

    if (elapsed_ms >= lt->agc_ramp_up_ms) {
        /* Ramp complete */
        lt->agc_state = AGC_STATE_IDLE;
        lt->agc_current_gain = 1.0f;
        agc_set_conference_volume(lt, 0);

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG,
            "AGC: Ramp complete, restored to normal (conf level 0, gain 1.0)\n");
        return;
    }

    /* Check if it's time for the next step */
    if ((now - lt->agc_last_step) < (lt->agc_ramp_step_ms * 1000)) {
        return;
    }

    /* Calculate progress (0.0 to 1.0) */
    progress = (float)elapsed_ms / (float)lt->agc_ramp_up_ms;

    /* Interpolate gain linearly from ducked to normal */
    target_gain = lt->agc_ducked_gain + (lt->agc_normal_gain - lt->agc_ducked_gain) * progress;

    /* Split into conference level and channel gain */
    lt->agc_current_gain = agc_calc_gain_split(target_gain, &target_conf_level);

    /* Only update conference level if it changed */
    if (target_conf_level != lt->agc_conf_level) {
        agc_set_conference_volume(lt, target_conf_level);
    }

    lt->agc_last_step = now;
}

/**
 * Restore conference volume to normal on session cleanup.
 */
static void agc_cleanup(livetranslate_session_t *lt)
{
    if (lt->conf_agc_enabled && lt->agc_state != AGC_STATE_IDLE) {
        agc_set_conference_volume(lt, 0);
        lt->agc_state = AGC_STATE_IDLE;
        lt->agc_current_gain = 1.0f;

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG,
            "AGC: Cleanup - restored conference volume to normal\n");
    }
}

/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_livetranslate_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_livetranslate_load);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_livetranslate_runtime);

SWITCH_MODULE_DEFINITION(mod_livetranslate, mod_livetranslate_load, mod_livetranslate_shutdown, NULL);


static switch_bool_t livetranslate_bug_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
    livetranslate_session_t *lt = (livetranslate_session_t *)user_data;
    switch_frame_t *frame;

    switch (type) {
    case SWITCH_ABC_TYPE_INIT:
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG, "Audio Bug INIT\n");
        break;

    case SWITCH_ABC_TYPE_READ_REPLACE:
    {
        frame = switch_core_media_bug_get_read_replace_frame(bug);
        if (frame && lt->running && lt->ws_connected) {
            /* 1. Check for incoming translation audio */
            void *pop = NULL;
            pcm_chunk_t *chunk = NULL;
            switch_bool_t was_ducking = (switch_micro_time_now() < lt->ducking_until);

            if (switch_queue_trypop(lt->incoming_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS && pop) {
                chunk = (pcm_chunk_t *)pop;
                /* Extend ducking timer */
                lt->ducking_until = switch_micro_time_now() + (lt->ducking_release_ms * 1000);

                /* AGC: Signal translation start if not already active */
                if (!lt->agc_translation_active) {
                    agc_on_translation_start(lt);
                }
            }

            /* 2. Check if we should be ducking (Translation active or in release period) */
            switch_time_t now = switch_micro_time_now();
            if (now < lt->ducking_until) {
                /* Apply attenuation to speaker's own channel (they hear their translation) */
                int16_t *data = (int16_t *)frame->data;
                uint32_t samples = frame->samples;

                /* If we have a chunk, mix it in */
                const int16_t *trans_data = chunk ? (const int16_t *)chunk->data : NULL;

                /* Safety: ensure chunk len matches frame if present */
                if (chunk && chunk->len < samples * 2) samples = chunk->len / 2;

                /* Convert gains to Q16 fixed-point for faster integer math */
                int32_t orig_gain_q16 = (int32_t)(lt->original_gain * 65536.0f);
                int32_t trans_gain_q16 = (int32_t)(lt->translated_gain * 65536.0f);

                for (uint32_t i = 0; i < samples; i++) {
                    /* Original attenuated using fixed-point multiply */
                    int32_t mixed = (data[i] * orig_gain_q16) >> 16;

                    /* Add translation if available */
                    if (trans_data) {
                        mixed += (trans_data[i] * trans_gain_q16) >> 16;
                    }

                    /* Branchless clamp using ternary (compiler optimizes well) */
                    mixed = (mixed > 32767) ? 32767 : ((mixed < -32768) ? -32768 : mixed);

                    data[i] = (int16_t)mixed;
                }
            } else {
                /* Ducking just ended - signal AGC to start ramping up */
                if (was_ducking && lt->agc_translation_active) {
                    agc_on_translation_stop(lt);
                }
            }

            /* AGC: Process ramp-up on every frame */
            agc_process_ramp(lt);

            if (chunk) free(chunk);
        }
        /* If no translation and not ducking, pass through original audio */
    }
    break;

    case SWITCH_ABC_TYPE_READ:
    {
        switch_frame_t read_frame = { 0 };
        if (switch_core_media_bug_read(bug, &read_frame, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS && read_frame.data) {
            frame = &read_frame;
            if (lt->running && lt->ws_connected) {
                // ... (Resampling and sending logic remains the same)
                void *data = frame->data;
                size_t len = frame->datalen;
                
                // Resampling
                if (frame->rate != 16000) {
                     if (!lt->resampler) {
                         int err = 0;
                         lt->resampler = speex_resampler_init(1, frame->rate, 16000, SWITCH_RESAMPLE_QUALITY, &err);
                         if (err) {
                             switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_ERROR, "Resampler init failed\n");
                             return SWITCH_TRUE;
                         }
                     }
                     
                     // Resample using pre-allocated buffer
                     spx_uint32_t in_len = frame->samples;
                     spx_uint32_t out_len = in_len * 16000 / frame->rate + LT_RESAMPLE_BUFFER_MARGIN;
                     size_t needed_size = out_len * sizeof(int16_t);

                     // Grow resample buffer if needed (rare after first frame)
                     if (needed_size > lt->resample_buffer_size) {
                         int16_t *new_buf = realloc(lt->resample_buffer, needed_size);
                         if (new_buf) {
                             lt->resample_buffer = new_buf;
                             lt->resample_buffer_size = needed_size;
                         } else {
                             switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session),
                                 SWITCH_LOG_ERROR, "Failed to allocate resample buffer\n");
                             break;
                         }
                     }

                     if (lt->resample_buffer) {
                        speex_resampler_process_interleaved_int(lt->resampler,
                            (const spx_int16_t *)frame->data,
                            &in_len,
                            (spx_int16_t *)lt->resample_buffer,
                            &out_len);

                        // Wrap in outgoing_pcm_chunk_t with actual length
                        size_t actual_len = out_len * sizeof(int16_t);
                        outgoing_pcm_chunk_t *chunk = malloc(sizeof(outgoing_pcm_chunk_t) + actual_len);
                        if (chunk) {
                            chunk->len = actual_len;
                            memcpy(chunk->data, lt->resample_buffer, actual_len);
                            if (switch_queue_trypush(lt->outgoing_pcm_queue, chunk) != SWITCH_STATUS_SUCCESS) {
                                free(chunk);
                            }
                        }
                     }
                } else {
                    // 16k, wrap in outgoing_pcm_chunk_t
                    outgoing_pcm_chunk_t *chunk = malloc(sizeof(outgoing_pcm_chunk_t) + len);
                    if (chunk) {
                        chunk->len = len;
                        memcpy(chunk->data, data, len);
                        if (switch_queue_trypush(lt->outgoing_pcm_queue, chunk) != SWITCH_STATUS_SUCCESS) {
                            free(chunk);
                        }
                    }
                }
            }
        }
    }
    break;

    case SWITCH_ABC_TYPE_CLOSE:
        /* Restore conference volume before cleanup */
        agc_cleanup(lt);

        if (lt->resampler) {
            speex_resampler_destroy(lt->resampler);
            lt->resampler = NULL;
        }
        /* Free pre-allocated resample buffer */
        if (lt->resample_buffer) {
            free(lt->resample_buffer);
            lt->resample_buffer = NULL;
            lt->resample_buffer_size = 0;
        }
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(lt->fs_session), SWITCH_LOG_DEBUG, "Audio Bug CLOSE\n");
        break;

    default:
        break;
    }

    return SWITCH_TRUE;
}

SWITCH_STANDARD_API(livetranslate_start_function)
{
    switch_core_session_t *target_session = NULL;
    char *uuid = NULL;
    const char *params = NULL;
    livetranslate_session_t *lt = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char *argv[10] = { 0 };

    (void)session; /* unused parameter from SWITCH_STANDARD_API macro */

    if (!zstr(cmd)) {
        char *mycmd = strdup(cmd);
        int argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
        if (argc > 0) uuid = argv[0];
        if (argc > 1) params = argv[1]; /* This parsing is simplistic, need proper param parsing */
        free(mycmd);
    }

    if (zstr(uuid)) {
        stream->write_function(stream, "-ERR Missing UUID\n");
        return SWITCH_STATUS_SUCCESS;
    }

    if ((target_session = switch_core_session_locate(uuid))) {
        switch_memory_pool_t *pool = switch_core_session_get_pool(target_session);
        
        lt = switch_core_session_alloc(target_session, sizeof(*lt));
        lt->pool = pool;
        lt->uuid_str = switch_core_session_strdup(target_session, uuid);
        lt->fs_session = target_session;
        lt->running = SWITCH_TRUE;
        lt->ws_connected = SWITCH_FALSE;
        
        /* Default values */
        lt->direction = "caller_to_agent";
        lt->src_lang = "en-US";
        lt->dst_lang = "fr-FR";
        lt->ws_url = globals.default_ws_url ? globals.default_ws_url : "wss://localhost:3000/v1/session";
        lt->original_gain = 0.1f;       /* -20dB for speaker's own channel */
        lt->translated_gain = 1.0f;     /* 0dB */
        lt->ducking_release_ms = 600;   /* Default hold time */

        /* Conference AGC defaults */
        lt->conf_agc_enabled = SWITCH_FALSE;
        lt->agc_state = AGC_STATE_IDLE;
        lt->agc_ducked_gain = 0.1f;     /* -20dB default */
        lt->agc_normal_gain = 1.0f;     /* 0dB */
        lt->agc_current_gain = 1.0f;
        lt->agc_conf_level = 0;
        lt->agc_ramp_up_ms = 500;       /* Default ramp duration */
        lt->agc_ramp_step_ms = 50;      /* Step interval */
        lt->agc_translation_active = SWITCH_FALSE;

        /* Pre-allocated resample buffer (will grow as needed) */
        lt->resample_buffer = NULL;
        lt->resample_buffer_size = 0;
        lt->frame_counter = 0;

        /* Parse Params with validation */
        if (params) {
            char *pdup = strdup(params);
            int ac = 0;
            char *av[20] = { 0 };
            ac = switch_separate_string(pdup, ' ', av, (sizeof(av) / sizeof(av[0])));

            for (int i = 0; i < ac; i++) {
                char *key = av[i];
                char *val = strchr(key, '=');
                if (val) {
                    *val++ = '\0';
                    if (!strcasecmp(key, "src_lang")) {
                        if (validate_language_code(val)) {
                            lt->src_lang = switch_core_session_strdup(target_session, val);
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid src_lang format: %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "dst_lang")) {
                        if (validate_language_code(val)) {
                            lt->dst_lang = switch_core_session_strdup(target_session, val);
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid dst_lang format: %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "direction")) lt->direction = switch_core_session_strdup(target_session, val);
                    else if (!strcasecmp(key, "role")) lt->role = switch_core_session_strdup(target_session, val);
                    else if (!strcasecmp(key, "url")) {
                        if (validate_ws_url(val)) {
                            lt->ws_url = switch_core_session_strdup(target_session, val);
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid WebSocket URL (must be ws:// or wss://): %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "api_key")) lt->api_key = switch_core_session_strdup(target_session, val);
                    else if (!strcasecmp(key, "session_id")) {
                        if (strlen(val) <= LT_MAX_SESSION_ID_LENGTH) {
                            lt->session_id = switch_core_session_strdup(target_session, val);
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "session_id too long (max %d chars)\n", LT_MAX_SESSION_ID_LENGTH);
                        }
                    }
                    else if (!strcasecmp(key, "original_gain")) {
                        float gain = (float)atof(val);
                        if (validate_gain(gain)) {
                            lt->original_gain = gain;
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid original_gain (0.0-10.0): %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "translated_gain")) {
                        float gain = (float)atof(val);
                        if (validate_gain(gain)) {
                            lt->translated_gain = gain;
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid translated_gain (0.0-10.0): %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "ducking_release_ms")) {
                        int ms = atoi(val);
                        if (validate_numeric_range(ms, 0, 10000)) {
                            lt->ducking_release_ms = ms;
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid ducking_release_ms (0-10000): %s\n", val);
                        }
                    }
                    /* Conference AGC parameters */
                    else if (!strcasecmp(key, "conf_agc")) lt->conf_agc_enabled = switch_true(val);
                    else if (!strcasecmp(key, "conf_agc_ducked_db")) {
                        float db = (float)atof(val);
                        if (db >= -60.0f && db <= 20.0f) {
                            lt->agc_ducked_gain = db_to_linear(db);
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid conf_agc_ducked_db (-60 to +20): %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "conf_agc_ramp_up_ms")) {
                        int ms = atoi(val);
                        if (validate_numeric_range(ms, 10, 5000)) {
                            lt->agc_ramp_up_ms = ms;
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid conf_agc_ramp_up_ms (10-5000): %s\n", val);
                        }
                    }
                    else if (!strcasecmp(key, "conf_agc_ramp_step_ms")) {
                        int ms = atoi(val);
                        if (validate_numeric_range(ms, 5, 500)) {
                            lt->agc_ramp_step_ms = ms;
                        } else {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                                "Invalid conf_agc_ramp_step_ms (5-500): %s\n", val);
                        }
                    }
                }
            }
            free(pdup);
        }
        
        if (!lt->session_id) {
            // default session_id to uuid|direction
            char buf[256];
            switch_snprintf(buf, sizeof(buf), "%s|%s", uuid, lt->direction);
            lt->session_id = switch_core_session_strdup(target_session, buf);
        }

        switch_queue_create(&lt->outgoing_pcm_queue, LT_OUTGOING_QUEUE_SIZE, lt->pool);
        switch_queue_create(&lt->incoming_pcm_queue, LT_INCOMING_QUEUE_SIZE, lt->pool);
        switch_mutex_init(&lt->mutex, SWITCH_MUTEX_NESTED, lt->pool);

        // Attach media bug
        switch_media_bug_flag_t flags = SMBF_READ_STREAM | SMBF_READ_REPLACE;
        
        if (switch_core_media_bug_add(target_session, "livetranslate", NULL, livetranslate_bug_callback, lt, 0, flags, &lt->bug) != SWITCH_STATUS_SUCCESS) {
             stream->write_function(stream, "-ERR Failed to attach media bug\n");
             status = SWITCH_STATUS_FALSE;
        } else {
             ws_client_start(lt);

             /* Detect conference membership if AGC is requested */
             if (lt->conf_agc_enabled) {
                 agc_detect_conference(lt);
             }

             /* Add to global hash */
             switch_mutex_lock(globals.sessions_mutex);
             switch_core_hash_insert(globals.sessions, lt->session_id, lt);
             switch_mutex_unlock(globals.sessions_mutex);

             stream->write_function(stream, "+OK Started %s\n", lt->session_id);
        }

        switch_core_session_rwunlock(target_session);
    } else {
        stream->write_function(stream, "-ERR Session not found\n");
    }

    return status;
}

SWITCH_STANDARD_API(livetranslate_stop_function)
{
    livetranslate_session_t *lt;
    char *uuid = NULL;

    (void)session; /* unused parameter from SWITCH_STANDARD_API macro */

    if (!zstr(cmd)) {
        uuid = strdup(cmd);
    }

    if (zstr(uuid)) {
        stream->write_function(stream, "-ERR Missing UUID\n");
        if (uuid) free(uuid);
        return SWITCH_STATUS_SUCCESS;
    }

    // Find session by UUID? 
    // We track by "uuid|direction" or just "session_id".
    // If user passes UUID, we might need to stop ALL directions?
    // For now, let's assume they pass the session_id or we search.
    
    // The global hash keys are session_id.
    // If the command only gives UUID, we might miss it if session_id != uuid.
    // But in start we defaulted session_id to "uuid|direction".
    
    // Let's try to find keys starting with uuid?
    // Or just require session_id.
    
    // Better: Iterate hash and match UUID.
    
    switch_mutex_lock(globals.sessions_mutex);
    // Ideally use a session_id to look up.
    lt = switch_core_hash_find(globals.sessions, uuid);
    if (lt) {
        switch_core_hash_delete(globals.sessions, uuid);
    }
    switch_mutex_unlock(globals.sessions_mutex);

    if (lt) {
        lt->running = SWITCH_FALSE;

        /* Restore conference volume before stopping */
        agc_cleanup(lt);

        ws_client_stop(lt);
        /* Bug removal should happen automatically if session ends,
         * but if we stop manually, we must remove the bug. */
        if (lt->bug) {
            switch_core_media_bug_remove(lt->fs_session, &lt->bug);
        }

        /* Drain queues to prevent memory leaks */
        void *pop;
        while (switch_queue_trypop(lt->outgoing_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            if (pop) free(pop);
        }
        while (switch_queue_trypop(lt->incoming_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            if (pop) free(pop);
        }

        stream->write_function(stream, "+OK Stopped %s\n", uuid);
    } else {
        stream->write_function(stream, "-ERR Session not found (use session_id)\n");
    }

    if (uuid) free(uuid);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_livetranslate_load)
{
    switch_api_interface_t *api_interface;

    memset(&globals, 0, sizeof(globals));
    globals.pool = pool;
    switch_core_hash_init(&globals.sessions);
    switch_mutex_init(&globals.sessions_mutex, SWITCH_MUTEX_NESTED, pool);

    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_livetranslate loading...\n");

    SWITCH_ADD_API(api_interface, "livetranslate_start", "Start Live Translation", livetranslate_start_function, "<uuid> <params>");
    SWITCH_ADD_API(api_interface, "livetranslate_stop", "Stop Live Translation", livetranslate_stop_function, "<uuid>");

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_livetranslate_shutdown)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_livetranslate shutting down...\n");
    switch_core_hash_destroy(&globals.sessions);
    return SWITCH_STATUS_SUCCESS;
}
