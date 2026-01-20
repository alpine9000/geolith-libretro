// Simple 68K debugger (end-of-frame pause)
#ifndef GEO_DEBUGGER_H
#define GEO_DEBUGGER_H

#include <stdint.h>

// Initialize debugger (reads optional env GEO_DBG_ELF or GEO_PROF_ELF)
void geo_debugger_init(void);

// Instruction hook (called via dispatcher)
void geo_debugger_instr_hook(unsigned pc);

// (Debugger is always enabled; window visibility controls display)

// Pause/continue state
int  geo_debugger_is_paused(void);
void geo_debugger_continue(void);

// Request a single-frame step (pause again after next frame)
void geo_debugger_step_frame(void);

// Request a single-instruction step (mid-frame halt via timeslice end)
void geo_debugger_step_instr(void);

// Query immediate break request for mid-frame halts (clears the flag)
int  geo_debugger_break_now(void);

// Returns 1 if a step/break just modified the emulated frame and the
// frontend should resnapshot the base visible region; clears the flag.
int  geo_debugger_consume_resnap_needed(void);

// Called from retro layer at end of a frame to latch breakpoint hits
void geo_debugger_end_of_frame_update(void (*notify)(const char *msg, int frames));

void geo_debugger_list_breakpoints(void (*notify)(const char *msg, int frames));

// UI and overlay (always enabled; window visibility controls display)
void geo_debugger_ui_update(int key_enable, int key_toggle, int key_continue,
                            int key_step_instr, int key_step_line,
                            int key_toggle_bp,
                            void (*notify)(const char *msg, int frames));

// Direct control helpers (bypass UI edge detection)
void geo_debugger_break_immediate(void);     // break now (mid-frame), enable if needed
void geo_debugger_toggle_break(void);        // break if running, continue if paused
void geo_debugger_step_instr_cmd(void);      // arm single-instruction step
void geo_debugger_step_next_line_cmd(void);  // arm next-line step

// Breakpoint control by address (PC is 24-bit for Neo Geo)
void geo_debugger_add_breakpoint(uint32_t pc24);
void geo_debugger_remove_breakpoint(uint32_t pc24);
int  geo_debugger_has_breakpoint(uint32_t pc24);

void geo_debugger_draw_overlay(uint32_t *vbuf,
                               int fb_width, int fb_height,
                               int vis_left, int vis_top,
                               int vis_width, int vis_height);

// In-emulator debugger window visibility (overlay display)
void geo_debugger_window_set_visible(int vis);
int  geo_debugger_window_is_visible(void);

#endif // GEO_DEBUGGER_H
