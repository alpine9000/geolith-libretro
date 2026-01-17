#include "geo_text.h"

#include <string.h>

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

uint32_t geo_blend_over(uint32_t dst, uint32_t src, uint8_t a) {
    uint32_t inv = (uint32_t)(255 - a);
    uint32_t dr = (dst >> 16) & 0xFF, dg = (dst >> 8) & 0xFF, db = dst & 0xFF;
    uint32_t sr = (src >> 16) & 0xFF, sg = (src >> 8) & 0xFF, sb = src & 0xFF;
    uint32_t rr = (sr * a + dr * inv) / 255;
    uint32_t gg = (sg * a + dg * inv) / 255;
    uint32_t bb = (sb * a + db * inv) / 255;
    return 0xFF000000u | (rr << 16) | (gg << 8) | bb;
}

void geo_draw_char5x7_alpha(uint32_t *vbuf, int fbw, int fbh,
                            int x, int y, char c, uint32_t color, uint8_t alpha) {
    uint8_t cols[5]; glyph5x7_get(c, cols);
    for (int dx=0; dx<5; dx++) {
        uint8_t bits = cols[dx];
        for (int dy=0; dy<7; dy++) {
            if (bits & (1 << dy)) {
                int px = x + dx; int py = y + dy;
                if ((unsigned)px < (unsigned)fbw && (unsigned)py < (unsigned)fbh) {
                    uint32_t *p = &vbuf[py*fbw + px];
                    *p = geo_blend_over(*p, color, alpha);
                }
            }
        }
    }
}

int geo_glyph_advance_px(char c) {
    (void)c; return 6; // 5 pixels + 1 space
}

int geo_text5x7_width(const char *txt) {
    int w = 0; if (!txt) return 0; for (const char *p=txt; *p; ++p) w += geo_glyph_advance_px(*p); return w;
}

void geo_draw_text5x7_alpha(uint32_t *vbuf, int fbw, int fbh,
                            int x, int y, const char *txt, uint32_t color, uint8_t alpha) {
    int cx = x, cy = y;
    for (const char *p = txt; *p; ++p) {
        if (*p == '\n') { cy += 10; cx = x; continue; }
        geo_draw_char5x7_alpha(vbuf, fbw, fbh, cx, cy, *p, color, alpha);
        cx += geo_glyph_advance_px(*p);
    }
}

int geo_glyph_advance_px_scaled(int scale) {
    if (scale < 1) scale = 1;
    return 6 * scale;
}

int geo_text5x7_width_scaled(const char *txt, int scale) {
    if (scale < 1) scale = 1;
    int w = 0; if (!txt) return 0; for (const char *p=txt; *p; ++p) w += geo_glyph_advance_px_scaled(scale); return w;
}

void geo_draw_text5x7_alpha_scaled(uint32_t *vbuf, int fbw, int fbh,
                                   int x, int y, const char *txt, uint32_t color, uint8_t alpha, int scale) {
    if (scale < 1) scale = 1;
    int cx = x, cy = y;
    for (const char *p = txt; *p; ++p) {
        if (*p == '\n') { cy += 10 * scale; cx = x; continue; }
        uint8_t cols[5]; glyph5x7_get(*p, cols);
        for (int dx=0; dx<5; dx++) {
            uint8_t bits = cols[dx];
            for (int dy=0; dy<7; dy++) {
                if (bits & (1 << dy)) {
                    int px0 = cx + dx * scale; int py0 = cy + dy * scale;
                    for (int oy=0; oy<scale; ++oy) {
                        int py = py0 + oy; if ((unsigned)py >= (unsigned)fbh) continue;
                        uint32_t *row = vbuf + py * fbw;
                        for (int ox=0; ox<scale; ++ox) {
                            int px = px0 + ox; if ((unsigned)px >= (unsigned)fbw) continue;
                            row[px] = geo_blend_over(row[px], color, alpha);
                        }
                    }
                }
            }
        }
        cx += 6 * scale; // 5 + 1 spacing
    }
}

// Shared overlay alpha
#define GEO_OVERLAY_ALPHA_MIN 50
static int s_overlay_alpha = 140; // default, similar to previous overlays

int geo_overlay_alpha_get(void) {
    if (s_overlay_alpha < GEO_OVERLAY_ALPHA_MIN) s_overlay_alpha = GEO_OVERLAY_ALPHA_MIN;
    if (s_overlay_alpha > 255) s_overlay_alpha = 255;
    return s_overlay_alpha;
}

void geo_overlay_alpha_set(int a) {
    if (a < GEO_OVERLAY_ALPHA_MIN) a = GEO_OVERLAY_ALPHA_MIN; if (a > 255) a = 255; s_overlay_alpha = a;
}

void geo_overlay_alpha_adjust(int delta) {
    int a = geo_overlay_alpha_get(); a += delta; if (a < GEO_OVERLAY_ALPHA_MIN) a = GEO_OVERLAY_ALPHA_MIN; if (a > 255) a = 255; s_overlay_alpha = a;
}

int geo_overlay_text_alpha(void) {
    // Map background alpha [0..255] to text alpha [96..255]
    int bg = geo_overlay_alpha_get();
    int ta = 96 + (bg * 159) / 255; // 96 .. 255
    if (ta < 0) ta = 0; if (ta > 255) ta = 255; return ta;
}
