#ifndef GEO_UI_H
#define GEO_UI_H

#include <stdint.h>
#include <stdbool.h>

// Signature compatible with libretro's input_state_cb
typedef int (*geo_ui_input_state_t)(unsigned port, unsigned device, unsigned index, unsigned id);

// Forward keyboard events from the frontend callback
void geo_ui_kb_event(bool down, unsigned keycode, uint32_t character, uint16_t mod);

// Handle input per frame and update debugger/profiler states; emit notifications if provided
void geo_ui_handle_input(geo_ui_input_state_t input_state_cb,
                         void (*notify)(const char *msg, int frames));

// Draw overlays (debugger/profiler) according to current UI state
void geo_ui_draw_overlays(uint32_t *present_buf, int present_w, int present_h,
                          int vis_w, int vis_h);

// (No separate end-of-frame hook; call geo_debugger_end_of_frame_update directly.)

#endif // GEO_UI_H
