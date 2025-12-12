# mod_livetranslate

A FreeSWITCH module for real-time voice translation via WebSocket-based translation backends.

## Overview

`mod_livetranslate` enables real-time bidirectional voice translation in FreeSWITCH calls. It:

- Taps audio from channels using FreeSWITCH audio bugs
- Streams PCM audio (16kHz, 16-bit LE, mono) to a WebSocket translation service
- Receives translated audio and captions from the service
- Injects translated audio back into the call with configurable gain control
- Emits FreeSWITCH events for transcripts and captions

## Features

- **Full-duplex translation**: Support for bidirectional translation (caller↔agent)
- **Real-time audio streaming**: Low-latency PCM streaming over WebSocket
- **Audio ducking**: Automatic volume reduction during translation playback
- **Conference AGC**: Automatic gain control for conference scenarios
- **Caption events**: FreeSWITCH custom events for transcript integration
- **Configurable gains**: Separate control for original and translated audio levels

## Requirements

- FreeSWITCH 1.10.x
- libwebsockets
- speexdsp (for resampling)
- pkg-config

### Alpine Linux (Docker)

```bash
apk add build-base pkgconf speexdsp-dev libwebsockets-dev openssl-dev
```

### Debian/Ubuntu

```bash
apt-get install build-essential pkg-config libfreeswitch-dev \
    libwebsockets-dev libspeexdsp-dev libssl-dev
```

## Building

### Using Make (Direct)

```bash
make clean && make
sudo make install
```

The module will be installed to `/usr/lib/freeswitch/mod/`.

### Using Docker (Recommended for Cross-Platform)

```bash
./build_module.sh
```

This builds the module in a Docker container and extracts `mod_livetranslate.so` to `build_output/`.

### Using Autotools (FreeSWITCH Source Tree)

If building as part of the FreeSWITCH source tree:

```bash
autoreconf -fisv
./configure
make
make install
```

## Configuration

### Loading the Module

Add to `modules.conf.xml`:

```xml
<load module="mod_livetranslate"/>
```

### Module Configuration (Optional)

Create `livetranslate.conf.xml`:

```xml
<configuration name="livetranslate.conf" description="Live Translation Module">
  <settings>
    <param name="default_ws_url" value="wss://livetranslate.example.com/v1/session"/>
    <param name="default_sample_rate" value="16000"/>
  </settings>
</configuration>
```

## Usage

### Dialplan Application

```xml
<action application="livetranslate_start"
        data="url=wss://localhost:3000/v1/session src_lang=en-US dst_lang=fr-FR direction=caller_to_agent"/>
```

### API Commands

Start translation on a channel:

```
livetranslate_start <uuid> url=wss://... src_lang=en-US dst_lang=fr-FR
```

Stop translation:

```
livetranslate_stop <session_id>
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `url` | (from config) | WebSocket URL for translation service |
| `src_lang` | `en-US` | Source language code |
| `dst_lang` | `fr-FR` | Destination language code |
| `direction` | `caller_to_agent` | Translation direction |
| `role` | (none) | Role identifier (caller/agent/supervisor) |
| `session_id` | `<uuid>\|<direction>` | External correlation ID |
| `api_key` | (none) | API key for authentication |
| `original_gain` | `0.1` | Gain for original audio during ducking (linear) |
| `translated_gain` | `1.0` | Gain for translated audio (linear) |
| `ducking_release_ms` | `600` | Hold time after translation stops (ms) |

### Conference AGC Parameters

For conference scenarios, automatic gain control reduces the speaker's volume in the conference mix while their translation plays:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `conf_agc` | `false` | Enable conference AGC |
| `conf_agc_ducked_db` | `-20` | Target attenuation when ducked (dB) |
| `conf_agc_ramp_up_ms` | `500` | Duration of volume ramp-up (ms) |
| `conf_agc_ramp_step_ms` | `50` | Interval between ramp steps (ms) |

Example with conference AGC:

```
livetranslate_start <uuid> conf_agc=true conf_agc_ducked_db=-20 conf_agc_ramp_up_ms=500
```

## WebSocket Protocol

The module communicates with the translation service using a simple protocol:

### Initial Config Frame (JSON)

```json
{
  "type": "config",
  "direction": "caller_to_agent",
  "src_lang": "en-US",
  "dst_lang": "fr-FR",
  "session_id": "uuid|direction",
  "api_key": "optional-key"
}
```

### Audio Frames (Binary)

- Format: PCM 16kHz, 16-bit little-endian, mono
- Frame size: 20ms (640 bytes / 320 samples)

### Caption Events (JSON)

```json
{
  "type": "caption",
  "mode": "final",
  "src_text": "Hello, how can I help you?",
  "dst_text": "Bonjour, comment puis-je vous aider?"
}
```

### Error Events (JSON)

```json
{
  "type": "error",
  "code": "ASR_ERROR",
  "message": "Speech recognition failed"
}
```

## FreeSWITCH Events

The module emits custom events:

### LIVETRANSLATE (Caption Event)

```
Event-Name: CUSTOM
Event-Subclass: LIVETRANSLATE
Unique-ID: <channel-uuid>
Session-ID: <session-id>
Direction: caller_to_agent
Mode: final
Src-Text: Hello
Dst-Text: Bonjour
```

### LIVETRANSLATE_ERROR (Error Event)

```
Event-Name: CUSTOM
Event-Subclass: LIVETRANSLATE_ERROR
Unique-ID: <channel-uuid>
Session-ID: <session-id>
Error-Code: ASR_ERROR
Error-Message: Speech recognition failed
```

## Architecture

```
FreeSWITCH Call
       │
       ▼
┌─────────────────┐
│ mod_livetranslate│
│   Audio Bug     │◄─── Captures audio from channel
│   Resampler     │     Converts to 16kHz if needed
│   WS Client     │     libwebsockets connection
└────────┬────────┘
         │
         ▼ WebSocket (binary PCM + JSON)
┌─────────────────┐
│ Translation     │
│ Backend Service │
│ (ASR→MT→TTS)    │
└────────┬────────┘
         │
         ▼ WebSocket (translated PCM + captions)
┌─────────────────┐
│ mod_livetranslate│
│   Audio Inject  │     Mixes translated audio
│   Event Emit    │     Fires LIVETRANSLATE events
└─────────────────┘
```

## Development

### File Structure

```
mod_livetranslate/
├── mod_livetranslate.c   # Main module code
├── mod_livetranslate.h   # Header with data structures
├── ws_client.c           # WebSocket client implementation
├── ws_client.h           # WebSocket client header
├── Makefile              # Simple build
├── Makefile.am           # Autotools build
├── Dockerfile            # Docker build environment
└── build_module.sh       # Docker build script
```

### Building for Development

```bash
# Build with debug symbols
make CFLAGS="-g -O0 -Wall"

# Install and reload
sudo make install
fs_cli -x 'reload mod_livetranslate'
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [livetranslation-service](https://github.com/voxist/livetranslation-service) - Go WebSocket backend service
