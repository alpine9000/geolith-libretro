#ifndef GEO_IPC_H
#define GEO_IPC_H

#include <stdint.h>

// Start/stop lightweight TCP JSON IPC on 127.0.0.1:GEO_IPC_PORT_DEFAULT (9000)
int  geo_ipc_start(void);
void geo_ipc_stop(void);

// Apply any pending commands enqueued by the IPC thread (call once per frame)
void geo_ipc_apply_pending(void);

// Send a debug byte event over IPC when the 68K writes to GEO_DBG_TEXT_ADDR
void geo_ipc_send_debug_byte(uint8_t byte);

#endif // GEO_IPC_H
