#ifndef GEO_RSP_H
#define GEO_RSP_H

#include <stdint.h>

int  geo_rsp_start(void);
void geo_rsp_stop(void);

// Call each frame to service RSP and send stop replies if needed
void geo_rsp_poll(uint32_t pc, uint32_t sr, int paused);

// (No on-screen diagnostics; see stderr logs controlled by GEO_RSP_LOG)

#endif // GEO_RSP_H
