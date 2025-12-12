#ifndef MOD_LIVETRANSLATE_H
#define MOD_LIVETRANSLATE_H

#include <switch.h>
#include <speex/speex_resampler.h>

typedef struct {
    size_t len;
    unsigned char data[];
} pcm_chunk_t;

// AGC state machine states
typedef enum {
    AGC_STATE_IDLE,
    AGC_STATE_DUCKED,
    AGC_STATE_RAMPING_UP
} agc_state_t;

struct livetranslate_session_s;
typedef struct livetranslate_session_s livetranslate_session_t;

typedef struct {
    switch_hash_t *sessions;
    switch_mutex_t *sessions_mutex;
    char *default_ws_url;
    int default_sample_rate;
    switch_memory_pool_t *pool;
} livetranslate_globals_t;

// Struct definition must be here for ws_client to use it
struct livetranslate_session_s {
    switch_memory_pool_t *pool;

    char *uuid_str;
    char *direction;
    char *role;
    char *ws_url;
    char *api_key;
    char *src_lang;
    char *dst_lang;
    char *session_id;

    switch_core_session_t *fs_session;
    switch_media_bug_t *bug;

    switch_mutex_t *mutex;
    SpeexResamplerState *resampler;
    switch_codec_t write_codec;
    
    // Audio queues
    switch_queue_t *outgoing_pcm_queue;
    switch_queue_t *incoming_pcm_queue;

    switch_bool_t running;
    switch_bool_t ws_connected;
    
    void *ws_handle;
    switch_thread_t *ws_send_thread;

    int sample_rate;
    int channels;

    // Mixing gains (linear factors)
    float original_gain;
    float translated_gain;

    // Ducking logic
    int ducking_release_ms; // How long to hold ducking after translation stops
    switch_time_t ducking_until;

    // Conference AGC (Automatic Gain Control)
    char *conference_name;
    char *conference_member_id;
    switch_bool_t conf_agc_enabled;
    agc_state_t agc_state;

    // AGC configurable parameters
    float agc_ducked_gain;        // Linear gain when ducked (e.g., 0.1 = -20dB)
    float agc_normal_gain;        // Normal gain (typically 1.0)
    float agc_current_gain;       // Current gain during ramp
    int agc_conf_level;           // Current conference volume_in level (-4 to +4)
    int agc_ramp_up_ms;           // Ramp duration in ms
    int agc_ramp_step_ms;         // Step interval (default 50ms)
    switch_time_t agc_ramp_start; // When ramping started
    switch_time_t agc_last_step;  // Last ramp step time
    switch_bool_t agc_translation_active; // Is translation audio currently playing?
};

extern livetranslate_globals_t globals;

#endif
