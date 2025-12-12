#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include "mod_livetranslate.h"

// Forward declare livetranslate_session_t as it's used in function signatures
// but defined in mod_livetranslate.h.
// However, mod_livetranslate.h forward declares it too.
// The issue is circular dependency or order.
// mod_livetranslate.h includes ws_client.h ? NO.
// mod_livetranslate.c includes mod_livetranslate.h THEN ws_client.h.
// BUT mod_livetranslate.h DOES NOT define the struct, it only typedefs it if we reverted previous changes.
// Let's check mod_livetranslate.h.

switch_status_t ws_client_start(livetranslate_session_t *lt);
switch_status_t ws_client_stop(livetranslate_session_t *lt);

#endif
