#ifndef GEO_IPC_H
#define GEO_IPC_H

#include <stdint.h>

// Start/stop lightweight TCP JSON IPC on 127.0.0.1:GEO_DEBUG_PORT or 6123
int  geo_ipc_start(void);
void geo_ipc_stop(void);

// Called each frame to send current state to connected client(s)
void geo_ipc_update(uint32_t pc, uint32_t sr, int paused, int profiler_enabled);

// Apply any pending commands enqueued by the IPC thread (call once per frame)
void geo_ipc_apply_pending(void);

#endif // GEO_IPC_H
