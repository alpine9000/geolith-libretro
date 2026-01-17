#ifndef GEO_TEXT_H
#define GEO_TEXT_H

#include <stdint.h>

// Alpha blend src over dst (0xAARRGGBB), return composited pixel
uint32_t geo_blend_over(uint32_t dst, uint32_t src, uint8_t a);

// 5x7 font rendering helpers
void geo_draw_char5x7_alpha(uint32_t *vbuf, int fbw, int fbh,
                            int x, int y, char c, uint32_t color, uint8_t alpha);

void geo_draw_text5x7_alpha(uint32_t *vbuf, int fbw, int fbh,
                            int x, int y, const char *txt, uint32_t color, uint8_t alpha);

int  geo_text5x7_width(const char *txt);  // in pixels
int  geo_glyph_advance_px(char c);        // glyph advance in pixels

// Scaled 5x7 text (integer scale > 0)
void geo_draw_text5x7_alpha_scaled(uint32_t *vbuf, int fbw, int fbh,
                                   int x, int y, const char *txt, uint32_t color, uint8_t alpha, int scale);
int  geo_text5x7_width_scaled(const char *txt, int scale);
int  geo_glyph_advance_px_scaled(int scale);

// Shared overlay alpha (0-255) used for overlay backgrounds
int  geo_overlay_alpha_get(void);
void geo_overlay_alpha_set(int a);
void geo_overlay_alpha_adjust(int delta);

// Suggested text alpha for overlays based on background alpha
int  geo_overlay_text_alpha(void);

#endif // GEO_TEXT_H
