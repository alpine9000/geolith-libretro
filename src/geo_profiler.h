// Minimal 68K profiler (PC sampling) interface
#ifndef GEO_PROFILER_H
#define GEO_PROFILER_H

#include <stddef.h>
#include <stdint.h>

// Initialize profiler state
void geo_profiler_init(void);

// Instruction hook called before each instruction (wired via Musashi config)
void geo_profiler_instr_hook(unsigned pc);

// Dump results to hard-coded path and reset state
int  geo_profiler_dump(void);
const char *geo_profiler_dump_path(void);

// Enable/disable sampling at runtime
void geo_profiler_set_enabled(int enabled);
int  geo_profiler_get_enabled(void);

// Optional: clear accumulated counts without dumping
void geo_profiler_reset(void);

// Live top lines API (for on-screen display)
typedef struct geo_prof_line_hit_s {
    const char *file;
    uint32_t line;
    uint64_t cycles;
    uint64_t count;
    const char *source; // optional cached source text for this line (may be NULL)
} geo_prof_line_hit_t;

typedef struct geo_profiler_stream_hit_s {
    uint32_t pc;
    uint64_t samples;
    uint64_t cycles;
} geo_profiler_stream_hit_t;

// Fill up to max entries with current top lines by cycles; returns count filled
size_t geo_profiler_top_lines(geo_prof_line_hit_t *out, size_t max);

// Streaming helpers (collect hits since last flush, enable/disable stream tracking)
void geo_profiler_stream_enable(int enable);
size_t geo_profiler_stream_collect(geo_profiler_stream_hit_t *out, size_t max);
size_t geo_profiler_stream_pending(void);
void geo_profiler_capture_stream_hits(const geo_profiler_stream_hit_t *hits, size_t count);

// Optional: handle UI keys and notifications (F10 toggle, scrolling)
// - key_* are 1 if currently pressed, 0 otherwise (edge detection handled internally)
// - notify(msg, frames) is optional and may be NULL; used to show short messages
void geo_profiler_ui_update(int key_f10, int key_comma, int key_period,
                            void (*notify)(const char *msg, int frames));

// Optional: draw overlay directly into framebuffer
// - vbuf: pointer to 0xAARRGGBB pixels
// - fb_width/fb_height: framebuffer dimensions in pixels
// - vis_left, vis_top, vis_width, vis_height: visible rectangle for overlay bounds
void geo_profiler_draw_overlay(uint32_t *vbuf,
                               int fb_width, int fb_height,
                               int vis_left, int vis_top,
                               int vis_width, int vis_height);

// Read current scroll offset for overlay windowing (0-based)
int geo_profiler_get_scroll(void);

// Reset live UI/render state (scroll and key edges)
void geo_profiler_render_reset(void);

#endif // GEO_PROFILER_H
