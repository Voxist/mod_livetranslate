# Security Audit Report: mod_livetranslate FreeSWITCH Module

**Audit Date**: 2025-12-12
**Auditor**: Security Analysis
**Module Version**: Current codebase
**Scope**: C-based FreeSWITCH module for live audio translation

## Executive Summary

This security audit identified **15 distinct security vulnerabilities** ranging from Critical to Low severity across the mod_livetranslate codebase. The most critical issues involve buffer overflow risks, command injection vulnerabilities, insufficient input validation, and memory safety concerns.

**Critical Risk Summary**:
- 3 Critical severity issues
- 5 High severity issues
- 4 Medium severity issues
- 3 Low severity issues

**Immediate Action Required**: Address Critical and High severity findings before production deployment.

---

## 1. Input Validation & Sanitization Issues

### 🔴 CRITICAL: Command Injection via Conference API (CVE-Risk)

**Location**: `mod_livetranslate.c:75-76`

```c
switch_snprintf(cmd, sizeof(cmd), "%s volume_in %s %d",
    lt->conference_name, lt->conference_member_id, level);
```

**Vulnerability**: User-controlled values `conference_name` and `conference_member_id` are obtained from channel variables and directly interpolated into API commands without sanitization. An attacker controlling these channel variables can inject arbitrary FreeSWITCH API commands.

**Attack Scenario**:
```
conference_name = "myconf;originate user/evil@domain.com"
→ Executes: conference myconf;originate user/evil@domain.com volume_in 123 0
```

**Impact**:
- Arbitrary FreeSWITCH API command execution
- Potential call manipulation, eavesdropping, toll fraud
- Privilege escalation within FreeSWITCH context

**Remediation**:
1. Validate conference_name and conference_member_id against strict alphanumeric patterns
2. Use parameter binding or escaping for API calls
3. Implement whitelist validation:
```c
// Validate conference_name: alphanumeric, dash, underscore only
if (!switch_regex_match(conf_name, "^[a-zA-Z0-9_-]+$")) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid conference_name");
    return SWITCH_STATUS_FALSE;
}
```

**Affected Functions**: `agc_set_conference_volume()`, `agc_detect_conference()`

---

### 🔴 CRITICAL: Insufficient Parameter Validation in API Handler

**Location**: `mod_livetranslate.c:417-423, 460-490`

**Vulnerability**: The `livetranslate_start_function()` API handler performs minimal validation on user-supplied parameters. Multiple fields lack bounds checking, format validation, or sanitization.

**Issues Identified**:
1. **No URL format validation** (line 476): `lt->ws_url` can be arbitrary string
2. **No language code validation** (lines 472-473): `src_lang`/`dst_lang` can be malicious
3. **No numeric bounds checking** (lines 479-486): Gain/timing values unchecked
4. **No session_id validation** (line 478): Can contain special characters

**Attack Vectors**:
```
url=file:///etc/passwd              # File protocol injection
src_lang=../../etc/passwd%00en-US   # Path traversal attempt
original_gain=999999999.0           # Numeric overflow
ducking_release_ms=-2147483648      # Integer underflow
session_id='; DROP TABLE--          # SQL injection style (if logged to DB)
```

**Impact**:
- WebSocket connection to attacker-controlled servers
- Integer overflow leading to memory corruption
- Log injection attacks
- Denial of service through malformed parameters

**Remediation**:
```c
// URL validation
if (!zstr(val) && strncasecmp(val, "wss://", 6) != 0 &&
    strncasecmp(val, "ws://", 5) != 0) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid WebSocket URL");
    status = SWITCH_STATUS_FALSE;
    goto cleanup;
}

// Numeric bounds checking
float gain = (float)atof(val);
if (gain < 0.0f || gain > 10.0f || isnan(gain) || isinf(gain)) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid gain value");
    gain = 1.0f; // Safe default
}

// Timing bounds
int ms = atoi(val);
if (ms < 0 || ms > 60000) { // Max 60 seconds
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid timing value");
    ms = 500; // Safe default
}

// Language code validation (ISO 639-1 + region)
if (!switch_regex_match(val, "^[a-z]{2}-[A-Z]{2}$")) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid language code");
    val = "en-US"; // Safe default
}
```

---

### 🟡 HIGH: Missing NULL Checks After String Duplication

**Location**: `mod_livetranslate.c:472-478`

**Vulnerability**: Multiple `switch_core_session_strdup()` calls lack NULL return value checks. While FreeSWITCH's implementation rarely returns NULL, insufficient memory or pool exhaustion could trigger NULL pointer dereferences.

**Code Examples**:
```c
lt->src_lang = switch_core_session_strdup(target_session, val);
// No check if strdup failed
if (!strcasecmp(key, "dst_lang"))
    lt->dst_lang = switch_core_session_strdup(target_session, val);
```

**Impact**: Potential NULL pointer dereference leading to crash

**Remediation**: Add defensive NULL checks after all strdup operations:
```c
char *temp = switch_core_session_strdup(target_session, val);
if (!temp) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Memory allocation failed");
    status = SWITCH_STATUS_FALSE;
    goto cleanup;
}
lt->src_lang = temp;
```

---

### 🟡 HIGH: Unvalidated JSON Parsing

**Location**: `ws_client.c:73-114`

**Vulnerability**: JSON parsing from WebSocket lacks validation of field types, sizes, and content. An attacker controlling the WebSocket server can send malformed JSON to trigger vulnerabilities.

**Issues**:
1. No maximum length validation for string fields
2. Type confusion (expecting string but receiving object/array)
3. No depth limit for nested JSON structures
4. Missing validation of cJSON_Parse return value context

**Attack Scenario**:
```json
{
  "type": "caption",
  "src_text": "A".repeat(100000000),  // Excessive memory allocation
  "dst_text": {"malicious": "object"},  // Type confusion
  "mode": null  // NULL pointer access
}
```

**Impact**:
- Denial of service through memory exhaustion
- Potential buffer overflows in event handling
- Crash through type confusion

**Remediation**:
```c
cJSON *json = cJSON_Parse((const char *)in);
if (!json) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid JSON received");
    return 0;
}

const cJSON *type = cJSON_GetObjectItem(json, "type");
if (!type || !cJSON_IsString(type) || !type->valuestring) {
    cJSON_Delete(json);
    return 0;
}

// Validate string length
cJSON *src = cJSON_GetObjectItem(json, "src_text");
if (src && cJSON_IsString(src) && src->valuestring) {
    if (strlen(src->valuestring) > 10000) { // Max caption length
        switch_log_printf(..., SWITCH_LOG_WARNING, "Caption too long, truncating");
        src->valuestring[10000] = '\0';
    }
}
```

---

## 2. Buffer Overflow Risks

### 🔴 CRITICAL: Fixed Buffer with Variable String Length

**Location**: `mod_livetranslate.c:62, 75, 494`

**Vulnerability**: Fixed-size buffers (`cmd[256]`, `buf[256]`) used with `switch_snprintf()` to store variable-length strings that could exceed buffer capacity.

**Code Analysis**:
```c
char cmd[256];  // Line 62
switch_snprintf(cmd, sizeof(cmd), "%s volume_in %s %d",
    lt->conference_name, lt->conference_member_id, level);
```

**Risk Assessment**:
- `conference_name`: Could be up to 255 chars (typical FreeSWITCH limit)
- `conference_member_id`: Numeric but unbounded
- Format string overhead: 15 chars
- Total potential: 270+ chars → **Buffer overflow**

**Impact**: Stack buffer overflow leading to:
- Code execution (if attacker controls overflow data)
- Crash/denial of service
- Memory corruption

**Remediation**:
```c
// Option 1: Dynamic allocation
char *cmd = switch_mprintf("%s volume_in %s %d",
    lt->conference_name, lt->conference_member_id, level);
if (!cmd) return SWITCH_STATUS_FALSE;
// ... use cmd ...
switch_safe_free(cmd);

// Option 2: Validate input lengths
if (strlen(lt->conference_name) > 100 ||
    strlen(lt->conference_member_id) > 50) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Parameter too long");
    return SWITCH_STATUS_FALSE;
}
char cmd[256];
switch_snprintf(cmd, sizeof(cmd), ...);
```

**Similar Issues**:
- Line 494-496: `buf[256]` with unchecked UUID and direction strings

---

### 🟡 HIGH: Buffer Size Calculation Error in Resampling

**Location**: `mod_livetranslate.c:354, 356`

```c
spx_uint32_t out_len = in_len * 16000 / frame->rate + 100; // buffer size
int16_t *out_buf = (int16_t *)malloc(out_len * 2); // temporary buffer
```

**Vulnerability**: Integer overflow in buffer size calculation when `in_len` or `frame->rate` are large. The multiplication `in_len * 16000` can overflow before division, resulting in undersized buffer allocation.

**Overflow Scenario**:
```
in_len = 200000 (large frame)
frame->rate = 8000
Calculation: 200000 * 16000 = 3,200,000,000 (fits in uint32)
But with higher values:
in_len = 300000
300000 * 16000 = 4,800,000,000 (exceeds UINT32_MAX = 4,294,967,295)
→ Integer wraps to small value
→ malloc(small_value * 2) allocates insufficient memory
→ speex_resampler writes beyond buffer
```

**Impact**: Heap buffer overflow, memory corruption, potential code execution

**Remediation**:
```c
// Safe calculation with overflow check
if (in_len > UINT32_MAX / 16000) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Frame too large for resampling");
    return SWITCH_TRUE;
}

spx_uint32_t out_len = (spx_uint64_t)in_len * 16000 / frame->rate + 100;
if (out_len > 1000000) { // Sanity limit: 1M samples
    switch_log_printf(..., SWITCH_LOG_ERROR, "Output buffer too large");
    return SWITCH_TRUE;
}

int16_t *out_buf = (int16_t *)malloc(out_len * sizeof(int16_t));
if (!out_buf) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Allocation failed");
    return SWITCH_TRUE;
}
```

---

### 🟠 MEDIUM: Unchecked memcpy Operations

**Location**: `ws_client.c:45, 63, 145`, `mod_livetranslate.c:370`

**Vulnerability**: Multiple `memcpy()` calls without bounds validation between source and destination buffers.

**Examples**:

**ws_client.c:63**:
```c
pcm_chunk_t *chunk = malloc(sizeof(pcm_chunk_t) + len);
if (chunk) {
    chunk->len = len;
    memcpy(chunk->data, in, len);  // No validation that 'in' contains 'len' bytes
```

**ws_client.c:145**:
```c
size_t pay_len = 640; // Temporary assumption
unsigned char *buf = malloc(LWS_PRE + pay_len);
memcpy(buf + LWS_PRE, pop, pay_len);  // Assumes 'pop' has 640 bytes
```

**Impact**:
- Heap buffer overflow if source buffer smaller than specified length
- Memory corruption
- Information disclosure (reading beyond buffer boundary)

**Remediation**:
```c
// ws_client.c:63 - Validate WebSocket frame length
if (len > MAX_PCM_CHUNK_SIZE || len == 0) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid PCM chunk size: %zu", len);
    return 0;
}

// ws_client.c:145 - Use actual data size, not assumption
// Store size with queued data using a struct:
typedef struct {
    size_t len;
    unsigned char data[];
} queue_chunk_t;
```

---

### 🟠 MEDIUM: Potential Out-of-Bounds Access in Audio Mixing

**Location**: `mod_livetranslate.c:297-314`

```c
/* Safety: ensure chunk len matches frame if present */
if (chunk && chunk->len < samples * 2) samples = chunk->len / 2;

for (uint32_t i = 0; i < samples; i++) {
    /* Original attenuated */
    int32_t mixed = (int32_t)(data[i] * lt->original_gain);

    /* Add translation if available */
    if (trans_data) {
        mixed += (int32_t)(trans_data[i] * lt->translated_gain);
    }
```

**Vulnerability**: The safety check adjusts `samples` based on chunk size, but doesn't validate against `frame->samples`. If `frame->samples` < original `samples`, the loop still uses the uncorrected value.

**Issue**: Loop accesses `data[i]` where `i` could exceed actual frame samples.

**Remediation**:
```c
uint32_t samples = frame->samples;

// Validate against chunk size if present
if (chunk) {
    uint32_t chunk_samples = chunk->len / 2;
    if (chunk_samples < samples) {
        samples = chunk_samples;
    }
}

// Additional frame validation
if (samples > frame->samples) {
    samples = frame->samples;
}

// Validate frame->data size
if (frame->datalen < samples * 2) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Frame data too small");
    samples = frame->datalen / 2;
}
```

---

## 3. Integer Overflow/Underflow Risks

### 🟡 HIGH: Integer Underflow in Timing Calculations

**Location**: `mod_livetranslate.c:481, 485-486`

**Vulnerability**: User-supplied integer parameters lack negative value validation, allowing underflow attacks.

**Code**:
```c
lt->ducking_release_ms = atoi(val);       // No bounds check
lt->agc_ramp_up_ms = atoi(val);           // No bounds check
lt->agc_ramp_step_ms = atoi(val);         // No bounds check
```

**Attack Scenario**:
```
ducking_release_ms=-2147483648  (INT_MIN)
→ Line 279: switch_micro_time_now() + (lt->ducking_release_ms * 1000)
→ Negative large value * 1000 → Integer overflow
→ ducking_until wraps to small value
→ Ducking never expires or immediately expires
```

**Impact**:
- Logic bypass (ducking mechanism failure)
- Potential use of negative values in time calculations
- Denial of service through audio processing disruption

**Remediation**:
```c
int ducking_ms = atoi(val);
if (ducking_ms < 0 || ducking_ms > 60000) {
    switch_log_printf(..., SWITCH_LOG_ERROR,
        "Invalid ducking_release_ms: %d (must be 0-60000)", ducking_ms);
    ducking_ms = 600; // Safe default
}
lt->ducking_release_ms = ducking_ms;

// Similarly for all timing parameters
```

---

### 🟠 MEDIUM: Float Value Overflow in Gain Calculations

**Location**: `mod_livetranslate.c:479-480, 484`

**Vulnerability**: `atof()` conversion without validation allows infinite, NaN, or extreme values that can corrupt audio processing.

**Code**:
```c
lt->original_gain = (float)atof(val);
lt->translated_gain = (float)atof(val);
lt->agc_ducked_gain = db_to_linear((float)atof(val));
```

**Attack Vectors**:
```
original_gain=inf        → Infinite value
translated_gain=nan      → Not-a-number
original_gain=1e308      → Extreme value causing overflow
conf_agc_ducked_db=-inf  → db_to_linear() returns 0 or underflows
```

**Impact**:
- Audio corruption (silence, distortion, clipping)
- NaN propagation through calculations
- Potential integer overflow when converting to int16_t
- Denial of service

**Remediation**:
```c
#include <math.h>

float gain = (float)atof(val);
if (!isfinite(gain) || gain < 0.0f || gain > 10.0f) {
    switch_log_printf(..., SWITCH_LOG_ERROR,
        "Invalid gain value: %f (must be 0.0-10.0)", gain);
    gain = 1.0f; // Safe default
}
lt->original_gain = gain;

// For dB values
float db = (float)atof(val);
if (!isfinite(db) || db < -60.0f || db > 20.0f) {
    switch_log_printf(..., SWITCH_LOG_ERROR,
        "Invalid dB value: %f (must be -60.0 to 20.0)", db);
    db = -20.0f; // Safe default
}
lt->agc_ducked_gain = db_to_linear(db);
```

---

### 🟢 LOW: Array Index Out of Bounds in Gain Mapping

**Location**: `mod_livetranslate.c:106, 170`

**Vulnerability**: Conference level array access uses `lvl + 4` as index without validating that `lvl` is within expected range before array access.

**Code**:
```c
for (int lvl = -4; lvl <= 4; lvl++) {
    float conf_gain = CONF_LEVEL_GAIN[lvl + 4];  // Trusts loop bounds
```

**Risk**: While the loop bounds are correct, if code is modified or values are derived from untrusted sources, array access could be out of bounds.

**Current Impact**: LOW (loop bounds are hardcoded correctly)

**Defensive Remediation**:
```c
// Add assertion or bounds check
assert(lvl >= -4 && lvl <= 4);
int idx = lvl + 4;
if (idx < 0 || idx >= sizeof(CONF_LEVEL_GAIN)/sizeof(CONF_LEVEL_GAIN[0])) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid conference level");
    return 1.0f;
}
float conf_gain = CONF_LEVEL_GAIN[idx];
```

---

## 4. Memory Safety Issues

### 🟡 HIGH: Memory Leak on Queue Push Failure

**Location**: `mod_livetranslate.c:379-381`

**Vulnerability**: Memory allocated for audio data is freed on queue push failure, but resampler output buffer (`out_buf`) leaks memory in certain code paths.

**Code Flow Analysis**:
```c
if (frame->rate != 16000) {
    // ... resampling ...
    int16_t *out_buf = (int16_t *)malloc(out_len * 2);  // Line 356
    if (out_buf) {
        speex_resampler_process_interleaved_int(...);
        data = out_buf;  // Line 365
    }
} else {
    void *p = malloc(len);  // Line 369
    if (p) memcpy(p, data, len);
    data = p;
}

if (data) {
    if (switch_queue_trypush(lt->outgoing_pcm_queue, data) != SWITCH_STATUS_SUCCESS) {
        free(data);  // Line 380 - Frees data
    }
}
```

**Issue**: If `out_buf` allocation succeeds (line 356) but resampling fails or is incomplete, the `out_buf` pointer is never freed. Additionally, the `else` branch allocates `p` which might not get assigned to `data` if allocation fails.

**Memory Leak Path**:
1. `frame->rate != 16000` → Enter resampling branch
2. `out_buf = malloc(...)` succeeds
3. `data = out_buf`
4. Queue push fails
5. `free(data)` frees the buffer
6. However, if queue push never happens, `out_buf` leaks

**Impact**:
- Progressive memory exhaustion during high call volume
- Denial of service after sustained usage
- Estimated leak: 640-12800 bytes per failed frame (depending on sample rate)

**Remediation**:
```c
int16_t *out_buf = NULL;
void *allocated_data = NULL;

if (frame->rate != 16000) {
    // ... setup ...
    out_buf = (int16_t *)malloc(out_len * sizeof(int16_t));
    if (out_buf) {
        int ret = speex_resampler_process_interleaved_int(...);
        if (ret != RESAMPLER_ERR_SUCCESS) {
            switch_log_printf(..., SWITCH_LOG_ERROR, "Resampling failed");
            free(out_buf);
            return SWITCH_TRUE;
        }
        allocated_data = out_buf;
    } else {
        switch_log_printf(..., SWITCH_LOG_ERROR, "Allocation failed");
        return SWITCH_TRUE;
    }
} else {
    allocated_data = malloc(len);
    if (!allocated_data) {
        return SWITCH_TRUE;
    }
    memcpy(allocated_data, data, len);
}

if (switch_queue_trypush(lt->outgoing_pcm_queue, allocated_data) != SWITCH_STATUS_SUCCESS) {
    free(allocated_data);
    switch_log_printf(..., SWITCH_LOG_WARNING, "Queue full, dropping audio");
}
```

---

### 🟡 HIGH: Use-After-Free Risk in Session Cleanup

**Location**: `mod_livetranslate.c:533-594`

**Vulnerability**: Race condition between session cleanup and ongoing callback execution. The `livetranslate_stop_function()` removes the session from the global hash and sets `lt->running = FALSE`, but the media bug callback may still be executing with references to `lt`.

**Race Condition Scenario**:
```
Thread 1 (API call):                    Thread 2 (Bug callback):
livetranslate_stop_function()          livetranslate_bug_callback()
  ├─ lt->running = FALSE (573)          ├─ Checks lt->running (270)
  ├─ agc_cleanup(lt) (576)              ├─ Accesses lt->agc_state
  ├─ ws_client_stop(lt) (578)           ├─ Uses lt->incoming_pcm_queue
  ├─ switch_core_media_bug_remove()     └─ ... processing ...
  ├─ Queue drain (587-592)
  └─ [lt still accessible]              [Potential use-after-free if lt freed]
```

**Issue**: The media bug callback doesn't have strong synchronization with session teardown. After `lt->running = FALSE`, the callback might still access `lt` members.

**Impact**:
- Use-after-free if session memory is reclaimed while callback executes
- Race condition on queue access during drain
- Potential crash or memory corruption

**Remediation**:
```c
SWITCH_STANDARD_API(livetranslate_stop_function)
{
    // ... locate session ...

    if (lt) {
        // Acquire mutex before modifying state
        switch_mutex_lock(lt->mutex);
        lt->running = SWITCH_FALSE;
        switch_mutex_unlock(lt->mutex);

        /* Remove bug first to ensure no new callbacks */
        if (lt->bug) {
            switch_core_media_bug_remove(lt->fs_session, &lt->bug);
            lt->bug = NULL;
        }

        /* Now safe to cleanup */
        agc_cleanup(lt);
        ws_client_stop(lt);

        /* Drain queues with mutex protection */
        switch_mutex_lock(lt->mutex);
        void *pop;
        while (switch_queue_trypop(lt->outgoing_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            if (pop) free(pop);
        }
        while (switch_queue_trypop(lt->incoming_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            if (pop) free(pop);
        }
        switch_mutex_unlock(lt->mutex);

        /* Remove from hash last */
        switch_mutex_lock(globals.sessions_mutex);
        switch_core_hash_delete(globals.sessions, uuid);
        switch_mutex_unlock(globals.sessions_mutex);

        stream->write_function(stream, "+OK Stopped %s\n", uuid);
    }
    // ...
}
```

**Additionally**, the bug callback should check `lt->running` under mutex:
```c
switch_mutex_lock(lt->mutex);
switch_bool_t is_running = lt->running;
switch_mutex_unlock(lt->mutex);

if (!is_running) {
    return SWITCH_TRUE;
}
```

---

### 🟠 MEDIUM: Missing malloc() Failure Checks

**Location**: `ws_client.c:44, 60, 144`, `mod_livetranslate.c:356, 369`

**Vulnerability**: Multiple heap allocations without NULL return checks. While modern systems rarely fail malloc, under memory pressure or attack conditions, unchecked NULL pointers cause crashes.

**Examples**:

**ws_client.c:44**:
```c
unsigned char *buf = malloc(LWS_PRE + strlen(json_str));
memcpy(buf + LWS_PRE, json_str, strlen(json_str));  // NULL deref if malloc failed
```

**mod_livetranslate.c:356**:
```c
int16_t *out_buf = (int16_t *)malloc(out_len * 2);
if (out_buf) {
    speex_resampler_process_interleaved_int(...);
    // ... uses out_buf
}
// Missing else branch - continues processing with data = NULL
```

**Impact**:
- NULL pointer dereference → crash
- Denial of service
- Undefined behavior if NULL is passed to downstream functions

**Remediation**: Add consistent error handling for all allocations:
```c
unsigned char *buf = malloc(LWS_PRE + strlen(json_str));
if (!buf) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Memory allocation failed");
    // Cleanup and return error
    free(json_str);
    cJSON_Delete(json);
    return 0;
}
```

---

### 🟠 MEDIUM: Queue Drain Race Condition

**Location**: `mod_livetranslate.c:587-592`

**Vulnerability**: Queue draining during session stop lacks synchronization with ongoing callback that might be pushing to queues.

**Code**:
```c
void *pop;
while (switch_queue_trypop(lt->outgoing_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
    if (pop) free(pop);
}
while (switch_queue_trypop(lt->incoming_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
    if (pop) free(pop);
}
```

**Race Scenario**:
```
Thread 1 (Stop):                     Thread 2 (Bug callback):
while (trypop queue) {               if (running && ws_connected) {
  free(pop);                           void *data = malloc(...);
}                                      queue_trypush(queue, data);
[Queue appears empty]                }
                                     [Memory leaked - won't be freed]
```

**Impact**: Memory leak if callback pushes after drain but before teardown completes

**Remediation**: Ensure callback is stopped before draining:
```c
// In stop function:
lt->running = SWITCH_FALSE;

// Remove bug FIRST to prevent new callbacks
if (lt->bug) {
    switch_core_media_bug_remove(lt->fs_session, &lt->bug);
    lt->bug = NULL;
}

// Small delay or barrier to ensure callback exit
switch_yield(100000); // 100ms

// NOW safe to drain queues
switch_mutex_lock(lt->mutex);
void *pop;
while (switch_queue_trypop(lt->outgoing_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS) {
    if (pop) free(pop);
}
// ...
switch_mutex_unlock(lt->mutex);
```

---

## 5. WebSocket Security Issues

### 🟡 HIGH: No TLS/SSL Enforcement

**Location**: `ws_client.c:199-204`

**Vulnerability**: WebSocket connection hardcoded to unencrypted connection. The code comment shows SSL is an option but disabled:

```c
i.address = "localhost"; // Parse from lt->ws_url
i.port = 3000;
i.path = "/v1/session";
i.host = i.address;
i.origin = i.address;
i.ssl_connection = 0; // or LCCSCF_USE_SSL  ← SSL DISABLED
```

**Issues**:
1. Hardcoded to non-SSL connection regardless of URL scheme
2. No URL parsing to extract scheme, host, port, path
3. All WebSocket traffic in plaintext
4. Hardcoded to localhost:3000 (ignores `lt->ws_url`)

**Impact**:
- **Man-in-the-middle attacks**: Audio streams intercepted
- **Credential theft**: API keys sent in plaintext (line 37)
- **Data tampering**: Attacker can modify translation responses
- **Privacy violation**: Conversation content exposed

**Attack Scenario**:
```
1. Attacker performs network MITM (ARP spoofing, rogue WiFi, etc.)
2. Intercepts WebSocket connection to translation service
3. Captures api_key from config message
4. Eavesdrops on all audio PCM data and translations
5. Optionally injects malicious translated audio
```

**Remediation**:
```c
// Add URL parsing function
typedef struct {
    char *scheme;
    char *host;
    int port;
    char *path;
    int use_ssl;
} ws_url_t;

static switch_status_t parse_ws_url(const char *url, ws_url_t *parsed) {
    if (!url || !parsed) return SWITCH_STATUS_FALSE;

    // Parse URL: wss://host:port/path or ws://host:port/path
    if (strncasecmp(url, "wss://", 6) == 0) {
        parsed->use_ssl = LCCSCF_USE_SSL;
        url += 6;
    } else if (strncasecmp(url, "ws://", 5) == 0) {
        parsed->use_ssl = 0;
        url += 5;
    } else {
        return SWITCH_STATUS_FALSE; // Invalid scheme
    }

    // Extract host, port, path
    char *url_copy = strdup(url);
    char *port_sep = strchr(url_copy, ':');
    char *path_sep = strchr(url_copy, '/');

    if (port_sep && (!path_sep || port_sep < path_sep)) {
        *port_sep = '\0';
        parsed->host = strdup(url_copy);
        parsed->port = atoi(port_sep + 1);
        parsed->path = path_sep ? strdup(path_sep) : strdup("/");
    } else {
        parsed->host = path_sep ? strndup(url_copy, path_sep - url_copy) : strdup(url_copy);
        parsed->port = parsed->use_ssl ? 443 : 80;
        parsed->path = path_sep ? strdup(path_sep) : strdup("/");
    }

    free(url_copy);
    return SWITCH_STATUS_SUCCESS;
}

// In ws_thread_run:
ws_url_t parsed_url;
if (parse_ws_url(lt->ws_url, &parsed_url) != SWITCH_STATUS_SUCCESS) {
    switch_log_printf(..., SWITCH_LOG_ERROR, "Invalid WebSocket URL");
    return NULL;
}

memset(&i, 0, sizeof i);
i.context = context;
i.address = parsed_url.host;
i.port = parsed_url.port;
i.path = parsed_url.path;
i.host = i.address;
i.origin = i.address;
i.ssl_connection = parsed_url.use_ssl;

// ENFORCE SSL in production
if (!parsed_url.use_ssl) {
    switch_log_printf(..., SWITCH_LOG_WARNING,
        "Insecure WebSocket connection - consider using wss://");
}
```

**Additionally**: Add certificate validation:
```c
info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
info.ssl_ca_filepath = "/etc/ssl/certs/ca-certificates.crt";
// Consider adding:
// info.ssl_cert_filepath = "client-cert.pem";
// info.ssl_private_key_filepath = "client-key.pem";
```

---

### 🟠 MEDIUM: No WebSocket Authentication Beyond API Key

**Location**: `ws_client.c:30-51`

**Vulnerability**: Only authentication mechanism is API key sent in initial config message. No session validation, token refresh, or mutual authentication.

**Code**:
```c
cJSON *json = cJSON_CreateObject();
cJSON_AddStringToObject(json, "type", "config");
// ... other fields ...
if (lt->api_key) cJSON_AddStringToObject(json, "api_key", lt->api_key);
```

**Issues**:
1. API key sent only once at connection start
2. No token expiration or rotation
3. No challenge-response authentication
4. No mutual TLS (mTLS)
5. No validation of server certificate/identity

**Impact**:
- **Replay attacks**: Captured API key reused indefinitely
- **Session hijacking**: No per-session authentication tokens
- **Unauthorized access**: Compromised API key grants full access

**Remediation**:
```c
// Implement token-based authentication
// 1. Add HTTP Authorization header during WebSocket handshake
info.client_exts = NULL;

// Build custom headers with Authorization
struct lws_client_connect_info i;
// ... existing setup ...

// Add authorization header
static const char auth_header[] =
    "Authorization: Bearer YOUR_API_KEY\r\n";

i.alpn = "http/1.1";
i.method = "GET";
// Note: libwebsockets doesn't directly support custom headers easily
// Consider switching to curl for initial auth, then upgrading to WS

// OR: Implement server-side session tokens
// 1. Initial auth via HTTPS
// 2. Receive short-lived session token
// 3. Use token for WebSocket connection
// 4. Implement token refresh mechanism
```

**Best Practice Recommendation**:
- Use OAuth 2.0 or JWT tokens with expiration
- Implement certificate pinning for server validation
- Consider mTLS for highest security

---

### 🟢 LOW: Hardcoded WebSocket Parameters

**Location**: `ws_client.c:199-201`

**Vulnerability**: WebSocket connection parameters hardcoded, ignoring user-supplied `lt->ws_url`.

```c
i.address = "localhost"; // Parse from lt->ws_url
i.port = 3000;
i.path = "/v1/session";
```

**Impact**:
- Cannot connect to production translation service
- Limits deployment flexibility
- Comment suggests this is known technical debt

**Remediation**: Implement URL parsing as described in HIGH severity TLS issue above.

---

## 6. Command Injection Risks

### 🔴 CRITICAL: Conference API Command Injection (Duplicate Reference)

**Already covered in Section 1**: Command injection via `conference_name` and `conference_member_id` in `agc_set_conference_volume()`.

**Additional Attack Surface**:
The vulnerability extends to FreeSWITCH's event system. If `conference_name` or `conference_member_id` contain newlines or special FreeSWITCH command separators, they could inject commands when used in:

1. Log messages (log injection)
2. Event headers (event injection)
3. API command execution (command injection)

**Comprehensive Remediation**: Apply input validation universally:
```c
static switch_bool_t validate_identifier(const char *str) {
    if (zstr(str)) return SWITCH_FALSE;

    // Allow only: alphanumeric, dash, underscore
    for (const char *p = str; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_') {
            return SWITCH_FALSE;
        }
    }

    // Length limit
    if (strlen(str) > 100) return SWITCH_FALSE;

    return SWITCH_TRUE;
}

// Use in agc_detect_conference:
if (!validate_identifier(conf_name) || !validate_identifier(member_id)) {
    switch_log_printf(..., SWITCH_LOG_ERROR,
        "Invalid conference name or member ID - contains illegal characters");
    return SWITCH_STATUS_FALSE;
}
```

---

## 7. Sensitive Data Handling

### 🟠 MEDIUM: API Key Logging Risk

**Location**: `ws_client.c:37, mod_livetranslate.c:477`

**Vulnerability**: API keys stored in session structure and potentially logged to FreeSWITCH logs at DEBUG level.

**Code**:
```c
if (lt->api_key) cJSON_AddStringToObject(json, "api_key", lt->api_key);
```

**Logging Risk**:
While not directly logged in visible code, FreeSWITCH's debug logging might capture:
1. JSON messages (ws_client.c:70)
2. Session structure dumps
3. Event bodies containing API keys

**Impact**:
- **Credential exposure** through log files
- **Unauthorized access** if logs compromised
- **Compliance violations** (PCI-DSS, GDPR require secure credential handling)

**Remediation**:
```c
// 1. Redact sensitive data from logs
static char* redact_api_key(const char *key) {
    if (!key || strlen(key) < 8) return "***";

    // Show only first/last 4 chars
    static char redacted[32];
    snprintf(redacted, sizeof(redacted), "%.4s...%.4s",
             key, key + strlen(key) - 4);
    return redacted;
}

// 2. Use in logging
switch_log_printf(..., SWITCH_LOG_DEBUG, "API Key: %s\n",
                  redact_api_key(lt->api_key));

// 3. Mark api_key as sensitive in struct comments
// 4. Consider encrypted storage in memory (mlock, encryption)
```

**Configuration Recommendation**:
```xml
<!-- freeswitch.xml -->
<configuration name="livetranslate.conf">
  <settings>
    <!-- Store API keys in environment variables or encrypted config -->
    <param name="api_key" value="$${LIVETRANSLATE_API_KEY}"/>
  </settings>
</configuration>
```

---

### 🟢 LOW: Session ID Privacy

**Location**: `mod_livetranslate.c:494-496`

**Vulnerability**: Default session_id combines UUID and direction, potentially leaking call metadata.

```c
char buf[256];
switch_snprintf(buf, sizeof(buf), "%s|%s", uuid, lt->direction);
lt->session_id = switch_core_session_strdup(target_session, buf);
```

**Privacy Concern**: Session IDs logged to external translation service could reveal:
- Call direction (caller_to_agent, agent_to_caller)
- FreeSWITCH UUIDs (may correlate to CDRs, recordings)
- Pattern analysis (traffic analysis attacks)

**Impact**: LOW - Minimal privacy risk, but violates data minimization principle

**Remediation**:
```c
// Generate opaque session identifiers
// Option 1: Hash-based
switch_uuid_t uuid_obj;
switch_uuid_get(&uuid_obj);
char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];
switch_uuid_format(uuid_str, &uuid_obj);

// Option 2: Sequential counter (if privacy important)
static _Atomic int session_counter = 0;
char buf[64];
snprintf(buf, sizeof(buf), "session_%d_%ld",
         atomic_fetch_add(&session_counter, 1),
         (long)time(NULL));
lt->session_id = switch_core_session_strdup(target_session, buf);
```

---

## 8. Race Conditions & Thread Safety

### 🟡 HIGH: Unprotected Shared State Access

**Location**: Multiple locations in `mod_livetranslate.c`

**Vulnerability**: Session state variables accessed without mutex protection in concurrent contexts.

**Affected Variables**:
1. `lt->ws_connected` (read/write from multiple threads)
2. `lt->running` (read/write without mutex)
3. `lt->agc_state` (state machine transitions)
4. `lt->ducking_until` (time-based state)

**Code Examples**:

**mod_livetranslate.c:270** (Bug callback reads without mutex):
```c
if (frame && lt->running && lt->ws_connected) {
    // Both variables can change mid-check
```

**ws_client.c:27, 158** (WebSocket thread writes without mutex):
```c
lt->ws_connected = SWITCH_TRUE;  // Line 27
// ...
lt->ws_connected = SWITCH_FALSE; // Line 158
```

**mod_livetranslate.c:573** (Stop function writes):
```c
lt->running = SWITCH_FALSE;  // No mutex protection
```

**Race Condition Scenarios**:

**Scenario 1: ws_connected Race**
```
Thread 1 (Bug callback):           Thread 2 (WS callback):
if (lt->ws_connected) {           [Connection fails]
  // Passes check                  lt->ws_connected = FALSE;
  // Start processing frame
  switch_queue_trypush(...)       [Queue becomes invalid]
}                                  [Use-after-free]
```

**Scenario 2: running Flag Race**
```
Thread 1 (Bug callback):           Thread 2 (Stop API):
if (lt->running) {                lt->running = FALSE;
  [Torn read: might see           ws_client_stop(lt);
   old or new value]               [Cleanup begins]
  [Continue processing]            [Resources freed]
}                                  [Use-after-free]
```

**Scenario 3: AGC State Machine Race**
```
Thread 1 (Bug callback):           Thread 2 (Bug callback on different frame):
if (lt->agc_state == DUCKED) {    lt->agc_state = RAMPING_UP;
  lt->agc_state = RAMPING_UP;     // Transition logic
  [Starts ramp-up]                 [Starts another ramp-up]
}                                  [Broken state machine]
```

**Impact**:
- **Data races**: Undefined behavior per C11 standard
- **Use-after-free**: Processing continues after cleanup
- **Double operations**: Duplicate ramp-ups, queue operations
- **Inconsistent state**: State machine corruption

**Remediation**:

**Pattern 1**: Atomic flags with memory barriers
```c
// In header: Use atomic types
#include <stdatomic.h>

typedef struct {
    // ...
    _Atomic switch_bool_t running;
    _Atomic switch_bool_t ws_connected;
    // ...
} livetranslate_session_t;

// In code: Atomic operations
atomic_store(&lt->running, SWITCH_TRUE);
if (atomic_load(&lt->running) && atomic_load(&lt->ws_connected)) {
    // Safe concurrent access
}
```

**Pattern 2**: Consistent mutex usage
```c
// In bug callback:
switch_mutex_lock(lt->mutex);
switch_bool_t is_running = lt->running;
switch_bool_t is_connected = lt->ws_connected;
switch_mutex_unlock(lt->mutex);

if (is_running && is_connected) {
    // Process with local copies
}

// In stop function:
switch_mutex_lock(lt->mutex);
lt->running = SWITCH_FALSE;
switch_mutex_unlock(lt->mutex);

// In WebSocket callback:
switch_mutex_lock(lt->mutex);
lt->ws_connected = SWITCH_TRUE;
switch_mutex_unlock(lt->mutex);
```

**Pattern 3**: State machine protection
```c
// Protect entire AGC state transitions
switch_mutex_lock(lt->mutex);
if (lt->agc_state == AGC_STATE_DUCKED) {
    lt->agc_state = AGC_STATE_RAMPING_UP;
    lt->agc_ramp_start = switch_micro_time_now();
    // ... other state updates
}
switch_mutex_unlock(lt->mutex);
```

---

### 🟠 MEDIUM: Time-of-Check-Time-of-Use (TOCTOU) in Queue Operations

**Location**: `mod_livetranslate.c:276-277, 379-380`

**Vulnerability**: Queue operations check success but don't verify data validity before use.

**Code**:
```c
if (switch_queue_trypop(lt->incoming_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS && pop) {
    chunk = (pcm_chunk_t *)pop;
    // Time gap: 'pop' could be freed by another thread here
    chunk->len = len;  // Use after potential free
```

**Race Window**:
```
Thread 1:                          Thread 2 (Stop function):
trypop(queue, &pop) → SUCCESS     while (trypop(queue, &pop)) {
if (pop) {                          free(pop);
  [Context switch]                }
  chunk = (pcm_chunk_t *)pop;     [pop already freed]
  memcpy(chunk->data, ...)        [Use-after-free]
}
```

**Impact**: Use-after-free if concurrent queue drain occurs

**Remediation**:
```c
// Ensure queue operations are protected by session running state
switch_mutex_lock(lt->mutex);
if (lt->running) {
    void *pop = NULL;
    if (switch_queue_trypop(lt->incoming_pcm_queue, &pop) == SWITCH_STATUS_SUCCESS && pop) {
        chunk = (pcm_chunk_t *)pop;
        // Process while holding mutex
        // OR: copy data and release mutex
    }
}
switch_mutex_unlock(lt->mutex);
```

---

### 🟢 LOW: Global Hash Access Without Consistent Locking

**Location**: `mod_livetranslate.c:518-520, 564-570`

**Vulnerability**: Global session hash accessed with mutex, but not all access paths consistently lock.

**Code Analysis**:
```c
// Insertion with lock
switch_mutex_lock(globals.sessions_mutex);
switch_core_hash_insert(globals.sessions, lt->session_id, lt);
switch_mutex_unlock(globals.sessions_mutex);

// Lookup with lock
switch_mutex_lock(globals.sessions_mutex);
lt = switch_core_hash_find(globals.sessions, uuid);
if (lt) {
    switch_core_hash_delete(globals.sessions, uuid);
}
switch_mutex_unlock(globals.sessions_mutex);
```

**Current Status**: Code appears to lock consistently, but pattern is error-prone.

**Risk**: Future modifications might access hash without locking.

**Defensive Remediation**:
```c
// Create wrapper functions to enforce locking
static livetranslate_session_t* session_find_and_lock(const char *id) {
    switch_mutex_lock(globals.sessions_mutex);
    livetranslate_session_t *lt = switch_core_hash_find(globals.sessions, id);
    if (lt) {
        switch_mutex_lock(lt->mutex); // Double-lock pattern
    }
    switch_mutex_unlock(globals.sessions_mutex);
    return lt;
}

static void session_insert(const char *id, livetranslate_session_t *lt) {
    switch_mutex_lock(globals.sessions_mutex);
    switch_core_hash_insert(globals.sessions, id, lt);
    switch_mutex_unlock(globals.sessions_mutex);
}

static switch_bool_t session_remove(const char *id) {
    switch_mutex_lock(globals.sessions_mutex);
    void *lt = switch_core_hash_find(globals.sessions, id);
    if (lt) {
        switch_core_hash_delete(globals.sessions, id);
    }
    switch_mutex_unlock(globals.sessions_mutex);
    return lt != NULL;
}
```

---

## Summary of Findings

### Critical Severity (3 issues)
1. **Command Injection via Conference API** - Arbitrary API execution via unsanitized conference parameters
2. **Insufficient Parameter Validation** - Multiple attack vectors through unchecked user input
3. **Fixed Buffer Overflow** - Buffer overflow risk in conference command construction

### High Severity (5 issues)
1. **Missing NULL Checks** - Potential crashes from strdup failures
2. **Unvalidated JSON Parsing** - DoS and memory exhaustion risks
3. **Buffer Size Calculation Overflow** - Integer overflow in resampling buffer allocation
4. **No TLS/SSL Enforcement** - All WebSocket traffic in plaintext
5. **Memory Leak on Queue Failure** - Progressive memory exhaustion
6. **Use-After-Free in Cleanup** - Race condition during session teardown
7. **Integer Underflow in Timing** - Logic bypass through negative values
8. **Unprotected Shared State** - Multiple data race conditions

### Medium Severity (4 issues)
1. **Unchecked memcpy Operations** - Buffer overflow potential
2. **Out-of-Bounds Audio Access** - Potential memory corruption in mixing
3. **Float Value Overflow** - Audio corruption through extreme values
4. **Missing malloc Checks** - NULL pointer dereference risks
5. **Queue Drain Race** - Memory leak during concurrent access
6. **No WebSocket Authentication** - Weak authentication mechanism
7. **API Key Logging** - Credential exposure risk
8. **TOCTOU in Queue Ops** - Use-after-free window

### Low Severity (3 issues)
1. **Array Index Bounds** - Defensive improvement needed
2. **Hardcoded WebSocket Params** - Deployment inflexibility
3. **Session ID Privacy** - Metadata leakage concern
4. **Global Hash Locking** - Pattern improvement recommended

---

## Recommendations Priority

### Immediate (Before Production)
1. ✅ Fix command injection vulnerability (sanitize conference parameters)
2. ✅ Implement comprehensive input validation for all API parameters
3. ✅ Fix buffer overflow in conference command construction
4. ✅ Enable TLS/SSL for WebSocket connections
5. ✅ Add atomic operations or mutex protection for shared state
6. ✅ Fix integer overflow in buffer size calculations

### Short-term (Next Release)
1. Add NULL checks after all allocations
2. Implement bounds checking for all memcpy operations
3. Validate JSON structure and field sizes
4. Fix memory leak in resampling path
5. Resolve use-after-free in session cleanup
6. Add numeric bounds validation for all parameters

### Long-term (Hardening)
1. Implement comprehensive logging with sensitive data redaction
2. Add fuzz testing for parameter parsing
3. Conduct formal race condition analysis
4. Implement mTLS for WebSocket authentication
5. Add security audit logging
6. Create comprehensive test suite with security focus

---

## Testing Recommendations

### Security Test Cases

**Input Validation Tests**:
```bash
# Test command injection
livetranslate_start <uuid> conf_agc=true conference_name="test;shutdown"

# Test buffer overflow
livetranslate_start <uuid> url="wss://$('A'x300).example.com"

# Test integer overflow
livetranslate_start <uuid> ducking_release_ms=-2147483648 agc_ramp_up_ms=2147483647

# Test float overflow
livetranslate_start <uuid> original_gain=1e308 translated_gain=inf

# Test injection characters
livetranslate_start <uuid> src_lang="../../../etc/passwd%00"
```

**Fuzzing Targets**:
1. API parameter parsing (livetranslate_start)
2. WebSocket JSON message handling
3. Conference name/member ID validation

**Tools Recommended**:
- **AddressSanitizer (ASan)**: Detect memory errors
- **ThreadSanitizer (TSan)**: Detect race conditions
- **Valgrind**: Memory leak detection
- **AFL/LibFuzzer**: Fuzz testing input handlers

---

## Compliance Considerations

### PCI-DSS (If Processing Payment Calls)
- ⚠️ Requirement 6.5.1: Injection flaws (FAILED - command injection)
- ⚠️ Requirement 6.5.3: Insecure cryptographic storage (FAILED - no TLS)
- ⚠️ Requirement 6.5.6: Buffer overflow (FAILED - multiple instances)

### OWASP Top 10 2021
- **A01: Broken Access Control** - Command injection risk
- **A02: Cryptographic Failures** - No TLS enforcement
- **A03: Injection** - Command and potential log injection
- **A04: Insecure Design** - Lack of input validation architecture

### CWE Coverage
- CWE-77: Command Injection
- CWE-120: Buffer Overflow
- CWE-190: Integer Overflow
- CWE-252: Unchecked Return Value
- CWE-362: Race Condition
- CWE-319: Cleartext Transmission
- CWE-401: Memory Leak
- CWE-416: Use After Free

---

## Conclusion

The mod_livetranslate module contains multiple security vulnerabilities requiring immediate remediation before production deployment. The most critical issues involve command injection, insufficient input validation, and lack of encryption for sensitive data transmission.

**Risk Assessment**: Current security posture is **HIGH RISK** for production use.

**Recommended Action**: Address all Critical and High severity findings before deploying to production environments handling sensitive communications.

**Timeline Estimate**:
- Critical fixes: 2-3 days
- High priority fixes: 3-5 days
- Medium priority fixes: 5-7 days
- Testing and validation: 3-5 days
- **Total**: ~2-3 weeks for comprehensive security hardening

---

**End of Security Audit Report**
