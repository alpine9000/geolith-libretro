#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geo_profiler.h"

// 5x7 glyphs and alpha blending
static void glyph5x7_get(char c, uint8_t out[5]) {
    out[0]=out[1]=out[2]=out[3]=out[4]=0;
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    static const uint8_t dig[10][5] = {
        {0x3e,0x51,0x49,0x45,0x3e}, {0x00,0x42,0x7f,0x40,0x00}, {0x42,0x61,0x51,0x49,0x46},
        {0x21,0x41,0x45,0x4b,0x31}, {0x18,0x14,0x12,0x7f,0x10}, {0x27,0x45,0x45,0x45,0x39},
        {0x3c,0x4a,0x49,0x49,0x30}, {0x01,0x71,0x09,0x05,0x03}, {0x36,0x49,0x49,0x49,0x36},
        {0x06,0x49,0x49,0x29,0x1e}
    };
    static const uint8_t upper[26][5] = {
        {0x7e,0x11,0x11,0x11,0x7e},{0x7f,0x49,0x49,0x49,0x36},{0x3e,0x41,0x41,0x41,0x22},
        {0x7f,0x41,0x41,0x22,0x1c},{0x7f,0x49,0x49,0x49,0x41},{0x7f,0x09,0x09,0x09,0x01},
        {0x3e,0x41,0x49,0x49,0x7a},{0x7f,0x08,0x08,0x08,0x7f},{0x00,0x41,0x7f,0x41,0x00},
        {0x20,0x40,0x41,0x3f,0x01},{0x7f,0x08,0x14,0x22,0x41},{0x7f,0x40,0x40,0x40,0x40},
        {0x7f,0x02,0x0c,0x02,0x7f},{0x7f,0x04,0x08,0x10,0x7f},{0x3e,0x41,0x41,0x41,0x3e},
        {0x7f,0x09,0x09,0x09,0x06},{0x3e,0x41,0x51,0x21,0x5e},{0x7f,0x09,0x19,0x29,0x46},
        {0x46,0x49,0x49,0x49,0x31},{0x01,0x01,0x7f,0x01,0x01},{0x3f,0x40,0x40,0x40,0x3f},
        {0x1f,0x20,0x40,0x20,0x1f},{0x7f,0x20,0x18,0x20,0x7f},{0x63,0x14,0x08,0x14,0x63},
        {0x07,0x08,0x70,0x08,0x07},{0x61,0x51,0x49,0x45,0x43}
    };
    if (c >= '0' && c <= '9') { memcpy(out, dig[c-'0'], 5); return; }
    if (c >= 'A' && c <= 'Z') { memcpy(out, upper[c-'A'], 5); return; }
    if (c == '.') { out[0]=0x00; out[1]=0x60; out[2]=0x60; out[3]=0x00; out[4]=0x00; return; }
    if (c == ',') { out[0]=0x00; out[1]=0x40; out[2]=0x20; out[3]=0x00; out[4]=0x00; return; }
    if (c == ':') { out[0]=0x00; out[1]=0x36; out[2]=0x36; out[3]=0x00; out[4]=0x00; return; }
    if (c == ';') { out[0]=0x00; out[1]=0x36; out[2]=0x36; out[3]=0x20; out[4]=0x00; return; }
    if (c == '-') { out[0]=0x00; out[1]=0x08; out[2]=0x08; out[3]=0x08; out[4]=0x00; return; }
    if (c == '_') { out[0]=0x40; out[1]=0x40; out[2]=0x40; out[3]=0x40; out[4]=0x40; return; }
    if (c == '+') { out[0]=0x08; out[1]=0x08; out[2]=0x3e; out[3]=0x08; out[4]=0x08; return; }
    if (c == '=') { out[0]=0x00; out[1]=0x14; out[2]=0x14; out[3]=0x14; out[4]=0x00; return; }
    if (c == '*') { out[0]=0x14; out[1]=0x08; out[2]=0x3e; out[3]=0x08; out[4]=0x14; return; }
    if (c == '!') { out[0]=0x00; out[1]=0x00; out[2]=0x5f; out[3]=0x00; out[4]=0x00; return; }
    if (c == '?') { out[0]=0x02; out[1]=0x01; out[2]=0x51; out[3]=0x09; out[4]=0x06; return; }
    if (c == '\'') { out[0]=0x00; out[1]=0x00; out[2]=0x06; out[3]=0x00; out[4]=0x00; return; }
    if (c == '"') { out[0]=0x00; out[1]=0x06; out[2]=0x00; out[3]=0x06; out[4]=0x00; return; }
    if (c == '/') { out[0]=0x60; out[1]=0x10; out[2]=0x08; out[3]=0x04; out[4]=0x03; return; }
    if (c == '\\') { out[0]=0x03; out[1]=0x04; out[2]=0x08; out[3]=0x10; out[4]=0x60; return; }
    if (c == '(') { out[0]=0x00; out[1]=0x1c; out[2]=0x22; out[3]=0x41; out[4]=0x00; return; }
    if (c == ')') { out[0]=0x00; out[1]=0x41; out[2]=0x22; out[3]=0x1c; out[4]=0x00; return; }
    if (c == '[') { out[0]=0x00; out[1]=0x7f; out[2]=0x41; out[3]=0x41; out[4]=0x00; return; }
    if (c == ']') { out[0]=0x00; out[1]=0x41; out[2]=0x41; out[3]=0x7f; out[4]=0x00; return; }
    if (c == '{') { out[0]=0x00; out[1]=0x08; out[2]=0x36; out[3]=0x41; out[4]=0x00; return; }
    if (c == '}') { out[0]=0x00; out[1]=0x41; out[2]=0x36; out[3]=0x08; out[4]=0x00; return; }
    if (c == '<') { out[0]=0x08; out[1]=0x14; out[2]=0x22; out[3]=0x41; out[4]=0x00; return; }
    if (c == '>') { out[0]=0x41; out[1]=0x22; out[2]=0x14; out[3]=0x08; out[4]=0x00; return; }
    if (c == '|') { out[0]=0x00; out[1]=0x00; out[2]=0x7f; out[3]=0x00; out[4]=0x00; return; }
    if (c == '#') { out[0]=0x14; out[1]=0x7f; out[2]=0x14; out[3]=0x7f; out[4]=0x14; return; }
    if (c == '%') { out[0]=0x61; out[1]=0x64; out[2]=0x08; out[3]=0x13; out[4]=0x23; return; }
}

static inline uint32_t blend_over(uint32_t dst, uint32_t src, uint8_t a) {
    uint32_t inv = (uint32_t)(255 - a);
    uint32_t dr = (dst >> 16) & 0xFF, dg = (dst >> 8) & 0xFF, db = dst & 0xFF;
    uint32_t sr = (src >> 16) & 0xFF, sg = (src >> 8) & 0xFF, sb = src & 0xFF;
    uint32_t rr = (sr * a + dr * inv) / 255;
    uint32_t gg = (sg * a + dg * inv) / 255;
    uint32_t bb = (sb * a + db * inv) / 255;
    return 0xFF000000u | (rr << 16) | (gg << 8) | bb;
}

static void draw_char5x7_alpha(uint32_t *vbuf, int fbw, int fbh, int x, int y, char c, uint32_t color, uint8_t alpha) {
    uint8_t cols[5]; glyph5x7_get(c, cols);
    for (int dx=0; dx<5; dx++) {
        uint8_t bits = cols[dx];
        for (int dy=0; dy<7; dy++) {
            if (bits & (1 << dy)) {
                int px = x + dx; int py = y + dy;
                if (px>=0 && px<fbw && py>=0 && py<fbh) {
                    uint32_t *p = &vbuf[py*fbw + px];
                    *p = blend_over(*p, color, alpha);
                }
            }
        }
    }
}

static inline int glyph_advance_px(char c) { return (c==' ') ? 3 : 6; }

static void draw_text5x7_alpha(uint32_t *vbuf, int fbw, int fbh, int x, int y, const char *s, uint32_t color, uint8_t alpha) {
    for (const char *p=s; *p; ++p) { draw_char5x7_alpha(vbuf, fbw, fbh, x, y, *p, color, alpha); x += glyph_advance_px(*p); }
}

static int text5x7_width(const char *s) { int w=0; if (!s) return 0; for (const char *p=s; *p; ++p) w += glyph_advance_px(*p); return w; }

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
                geo_profiler_reset();
                geo_profiler_set_enabled(1);
                s_scroll = 0;
                if (notify) notify("Profiler ON", 120);
            }
        } else {
            geo_profiler_set_enabled(0);
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
    if (!geo_profiler_get_enabled() || !vbuf) return;
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

    // Alpha background 50%
    int boxw = avail_w < 360 ? avail_w : 360;
    int boxh = (int)(n_draw * row_px + 8); if (boxh < 24) boxh = 24;
    for (int y=0; y<boxh; ++y) {
        int py = y0 + y; if (py < 0 || py >= fb_height) continue;
        uint32_t *row = vbuf + py * fb_width;
        for (int x=0; x<boxw; ++x) {
            int px = x0 + x; if (px < 0 || px >= fb_width) continue;
            uint32_t *p = &row[px];
            *p = blend_over(*p, 0xff202020, 128);
        }
    }

    uint32_t color = 0xffffffff; char label[128]; char snippet[256]; int yy = y0 + 4;
    if (n == 0) { draw_text5x7_alpha(vbuf, fb_width, fb_height, x0 + 4, yy, "collecting...", color, 217); return; }
    for (size_t i=0; i<n_draw; ++i) {
        const geo_prof_line_hit_t *h = &hits[scroll + i];
        const char *fname = h->file ? h->file : "?";
        const char *base = fname; for (const char *p=fname; *p; ++p) if (*p=='/' || *p=='\\') base = p+1;
        int idxnum = (int)(scroll + i) + 1;
        int llen = snprintf(label, sizeof(label), "%d %s:%u %llu ", idxnum, base, (unsigned)h->line, (unsigned long long)h->count);
        if (llen < 0) llen = 0; if (llen > (int)sizeof(label)-1) llen = (int)sizeof(label)-1;
        int max_px = boxw - 8; int label_px = text5x7_width(label); if (label_px < 0) label_px = 0; int avail_px2 = max_px - label_px; if (avail_px2 < 0) avail_px2 = 0;
        int slen = 0; snippet[0] = '\0';
        if (h->source && h->source[0]) { const char *src = h->source; int used_px = 0; while (src[slen]) { int adv = glyph_advance_px(src[slen]); if (used_px + adv > avail_px2) break; snippet[slen] = src[slen]; used_px += adv; slen++; if (slen >= (int)sizeof(snippet)-1) break; } snippet[slen] = '\0'; }
        int x_text = x0 + 4; draw_text5x7_alpha(vbuf, fb_width, fb_height, x_text, yy, label, 0xffffffff, 217);
        draw_text5x7_alpha(vbuf, fb_width, fb_height, x_text + label_px, yy, snippet, 0xffffffff, 217);
        yy += 10;
    }
}
