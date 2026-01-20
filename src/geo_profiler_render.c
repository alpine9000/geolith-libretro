#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geo_profiler.h"
#include "geo_text.h"

// Uses shared geo_text helpers for 5x7 font and blending

// (legacy 5x7 helpers removed)

// Live UI state (scroll + key edges)
static int s_prev_f10 = 0;
static int s_prev_comma = 0;
static int s_prev_period = 0;
static int s_scroll = 0;

int geo_profiler_get_scroll(void) {
    return s_scroll;
}

void geo_profiler_render_reset(void) {
    s_scroll = 0;
    s_prev_f10 = s_prev_comma = s_prev_period = 0;
}

void geo_profiler_ui_update(int key_f10, int key_comma, int key_period,
                            void (*notify)(const char *msg, int frames)) {
    int now_f10 = key_f10 ? 1 : 0;
    if (now_f10 && !s_prev_f10) {
        int en = geo_profiler_get_enabled();
        if (!en) {
            const char *e_elf = getenv("GEO_PROF_ELF");
            const char *e_json = getenv("GEO_PROF_JSON");
            if (!e_elf || !*e_elf || !e_json || !*e_json) {
                if (notify) notify("Set GEO_PROF_ELF and GEO_PROF_JSON env vars", 240);
            } else {
                geo_profiler_init();
                geo_profiler_reset();
                geo_profiler_set_enabled(1);
                s_scroll = 0;
                if (notify) notify("Profiler ON", 120);
            }
        } else {
            geo_profiler_set_enabled(0);
            geo_profiler_dump();
            if (notify) notify("Profiler OFF", 120);
        }
    }
    s_prev_f10 = now_f10;

    int now_comma = key_comma ? 1 : 0;
    if (now_comma && !s_prev_comma) {
        if (s_scroll > 0) s_scroll--;
    }
    s_prev_comma = now_comma;

    int now_period = key_period ? 1 : 0;
    if (now_period && !s_prev_period) {
        s_scroll++;
    }
    s_prev_period = now_period;
}

void geo_profiler_draw_overlay(uint32_t *vbuf,
                               int fb_width, int fb_height,
                               int vis_left, int vis_top,
                               int vis_width, int vis_height) {
    if (!vbuf) return;
    int x_vis_left = vis_left;
    int y_vis_top  = vis_top;
    int x_vis_right = x_vis_left + vis_width;
    int y_vis_bottom = y_vis_top + vis_height;
    int x0 = x_vis_left + 2;
    int y0 = y_vis_top + 2;
    int avail_w = x_vis_right - x0 - 2; if (avail_w < 20) avail_w = 20;
    int avail_h = y_vis_bottom - y0 - 2; if (avail_h < 12) avail_h = 12;
    const int row_px = 10;
    int max_rows_fit = avail_h / row_px; if (max_rows_fit < 0) max_rows_fit = 0;

    geo_prof_line_hit_t hits[64];
    int scroll = s_scroll;
    int need = scroll + max_rows_fit; if (need < 0) need = 0; if (need > 64) need = 64;
    size_t req = (size_t)need; if (req == 0 && max_rows_fit > 0) req = (size_t)((max_rows_fit < 64) ? max_rows_fit : 64);
    size_t n = geo_profiler_top_lines(hits, req);
    if (scroll < 0) scroll = 0; if ((size_t)scroll > n) scroll = (n>0)? (int)n-1 : 0;
    size_t n_draw = 0;
    if (n > 0 && max_rows_fit > 0) { n_draw = (size_t)max_rows_fit; if (scroll + (int)n_draw > (int)n) { int over = scroll + (int)n_draw - (int)n; n_draw = over>0 && over<(int)n_draw ? n_draw - (size_t)over : (size_t)((int)n - scroll); } }

    // Alpha background 50% (shared adjustable alpha)
    int bg_alpha = geo_overlay_alpha_get();
    int boxw = avail_w < 360 ? avail_w : 360;
    int boxh = (int)(n_draw * row_px + 8); if (boxh < 24) boxh = 24;
    for (int y=0; y<boxh; ++y) {
        int py = y0 + y; if (py < 0 || py >= fb_height) continue;
        uint32_t *row = vbuf + py * fb_width;
        for (int x=0; x<boxw; ++x) {
            int px = x0 + x; if (px < 0 || px >= fb_width) continue;
            uint32_t *p = &row[px];
            *p = geo_blend_over(*p, 0xff202020, (uint8_t)bg_alpha);
        }
    }

    uint32_t color = 0xffffffff; char label[128]; char snippet[256]; int yy = y0 + 4;
    int ta = geo_overlay_text_alpha(); int ta_dim = ta > 32 ? ta-32 : ta;
    if (!geo_profiler_get_enabled()) {
        geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, x0 + 4, yy, "Profiler OFF - Press F10", 0xffe0e0e0, (uint8_t)ta);
        return;
    }
    if (n == 0) { geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, x0 + 4, yy, "collecting...", color, (uint8_t)ta); return; }
    for (size_t i=0; i<n_draw; ++i) {
        const geo_prof_line_hit_t *h = &hits[scroll + i];
        const char *fname = h->file ? h->file : "?";
        const char *base = fname; for (const char *p=fname; *p; ++p) if (*p=='/' || *p=='\\') base = p+1;
        int idxnum = (int)(scroll + i) + 1;
        int llen = snprintf(label, sizeof(label), "%d %s:%u %llu ", idxnum, base, (unsigned)h->line, (unsigned long long)h->count);
        if (llen < 0) llen = 0; if (llen > (int)sizeof(label)-1) llen = (int)sizeof(label)-1;
        int max_px = boxw - 8; int label_px = geo_text5x7_width(label); if (label_px < 0) label_px = 0; int avail_px2 = max_px - label_px; if (avail_px2 < 0) avail_px2 = 0;
        int slen = 0; snippet[0] = '\0';
        if (h->source && h->source[0]) { const char *src = h->source; int used_px = 0; while (src[slen]) { int adv = geo_glyph_advance_px(src[slen]); if (used_px + adv > avail_px2) break; snippet[slen] = src[slen]; used_px += adv; slen++; if (slen >= (int)sizeof(snippet)-1) break; } snippet[slen] = '\0'; }
        int x_text = x0 + 4; geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, x_text, yy, label, 0xffffffff, (uint8_t)ta);
        geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, x_text + label_px, yy, snippet, 0xffffffff, (uint8_t)ta_dim);
        yy += 10;
    }
}
