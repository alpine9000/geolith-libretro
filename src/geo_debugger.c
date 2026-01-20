#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <pthread.h>

#include "m68k/m68k.h"

#include "geo_debugger.h"
#include "geo_profiler_elf.h" // reuse line table loader
#include "geo_text.h"

// State
static int s_paused = 0;
static int s_step_frame = 0;   // step whole frame
static int s_step_instr = 0;   // step a single instruction
static int s_step_line  = 0;   // step to next source line
static uint32_t s_step_line_file = 0; // source file idx at step start (UINT32_MAX = wildcard)
static uint32_t s_step_line_num  = 0; // source line at step start (UINT32_MAX = wildcard)
static int s_break_now = 0;    // immediate break requested (mid-frame)
static int s_break_requested = 0; // set in hook, latched at end of frame
static int s_resnap_needed = 0; // request base resnapshot after step/break
static int s_step_armed_ui = 0; // UI armed a step this frame; suppress running HUD flash
static int s_window_visible = 0; // in-emulator overlay window visible flag

// Last PC seen and last-hit PC
static uint32_t s_last_pc = 0;
static uint32_t s_hit_pc = 0;

// Simple fixed-size breakpoint table
#define GEO_DBG_BP_MAX 64
static uint32_t s_bps[GEO_DBG_BP_MAX];
static size_t s_nbps = 0;
static pthread_mutex_t s_bp_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_bp_event(const char *verb, uint32_t pc24) {
    printf("Debugger: %s 0x%06x\n", verb, (unsigned)(pc24 & 0x00ffffffu));
    fflush(stdout);
}

// Line table for source mapping (optional)
static LineTable s_line_table = {0};
static const LineRow *s_rows = NULL; static size_t s_nrows = 0;

static inline const LineRow* lt_find(uint32_t addr){ return (s_rows && s_nrows) ? geo_line_find_row_addr(s_rows, s_nrows, addr) : NULL; }
// Forward declaration for next-line step
static void geo_debugger_step_next_line(void);

// Draw a list of small text items (e.g., registers) from left to right,
// wrapping to the next line when exceeding max width. Returns the next y
// position after the last drawn row (i.e., y of first row below the block).
static int draw_groups_wrapped(uint32_t *vbuf, int fbw, int fbh,
                               int x_start, int y_start, int max_w,
                               const char **items, int cnt,
                               uint32_t color, uint8_t alpha, int row_px) {
    int x = x_start;
    int y = y_start;
    for (int i = 0; i < cnt; ++i) {
        int w = geo_text5x7_width(items[i]);
        if (x > x_start && (x - x_start + w) > max_w) {
            y += row_px;
            x = x_start;
        }
        geo_draw_text5x7_alpha(vbuf, fbw, fbh, x, y, items[i], color, alpha);
        x += w;
    }
    return y + row_px;
}

static void load_line_table_from_env(void) {
    const char *p = getenv("GEO_DBG_ELF");
    if (!p || !p[0]) p = getenv("GEO_PROF_ELF");
    if (!p || !p[0]) return;
    LineTable lt = {0};
    if (geo_elf_load_line_table(p, &lt)) {
        s_line_table = lt; s_rows = lt.rows; s_nrows = lt.nrows;
    }
}

void geo_debugger_init(void) {
    s_paused = 0; s_step_frame = 0; s_step_instr = 0; s_step_line = 0; s_step_line_file = 0; s_step_line_num = 0; s_break_requested = 0; s_break_now = 0; s_resnap_needed = 0; s_last_pc = 0; s_hit_pc = 0; s_window_visible = 0;
    s_nbps = 0;
    load_line_table_from_env();
}

int  geo_debugger_is_paused(void) { return s_paused; }
void geo_debugger_continue(void) { s_paused = 0; s_step_frame = 0; }
void geo_debugger_step_frame(void) { s_paused = 0; s_step_frame = 1; }
void geo_debugger_step_instr(void) {
    s_paused = 0;
    s_step_instr = 1;
    s_step_armed_ui = 1;
}
int  geo_debugger_break_now(void) { int r = s_break_now; s_break_now = 0; return r; }
int  geo_debugger_consume_resnap_needed(void) { int r = s_resnap_needed; s_resnap_needed = 0; return r; }

static int has_breakpoint_locked(uint32_t pc24) {
    for (size_t i = 0; i < s_nbps; ++i) {
        if (s_bps[i] == pc24) return 1;
    }
    return 0;
}

static int has_breakpoint(uint32_t pc24) {
    int result;
    pthread_mutex_lock(&s_bp_mutex);
    result = has_breakpoint_locked(pc24);
    pthread_mutex_unlock(&s_bp_mutex);
    return result;
}

static void toggle_breakpoint(uint32_t pc24) {
    pc24 &= 0x00ffffffu;
    pthread_mutex_lock(&s_bp_mutex);
    for (size_t i=0;i<s_nbps;i++) {
        if (s_bps[i] == pc24) {
            // remove by swap-with-last
            s_bps[i] = s_bps[s_nbps-1];
            s_nbps--;
            pthread_mutex_unlock(&s_bp_mutex);
            return;
        }
    }
    if (s_nbps < GEO_DBG_BP_MAX) {
        s_bps[s_nbps++] = pc24;
        log_bp_event("Breakpoint set", pc24);
    }
    pthread_mutex_unlock(&s_bp_mutex);
}

void geo_debugger_add_breakpoint(uint32_t pc24) {
    pc24 &= 0x00ffffffu;
    pthread_mutex_lock(&s_bp_mutex);
    if (!has_breakpoint_locked(pc24) && s_nbps < GEO_DBG_BP_MAX) {
        s_bps[s_nbps++] = pc24;
        log_bp_event("Breakpoint set", pc24);
    }
    pthread_mutex_unlock(&s_bp_mutex);
}

void geo_debugger_remove_breakpoint(uint32_t pc24) {
    pc24 &= 0x00ffffffu;
    pthread_mutex_lock(&s_bp_mutex);
    for (size_t i=0;i<s_nbps;i++) {
        if (s_bps[i] == pc24) {
            s_bps[i] = s_bps[s_nbps-1];
            s_nbps--;
            log_bp_event("Breakpoint cleared", pc24);
            pthread_mutex_unlock(&s_bp_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&s_bp_mutex);
}

int geo_debugger_has_breakpoint(uint32_t pc24) { return has_breakpoint(pc24 & 0x00ffffffu); }

// Begin step-until-next-source-line on next emulation frame
static void geo_debugger_step_next_line(void) {
    s_paused = 0;
    s_step_instr = 0;
    s_step_line = 1;
    s_step_armed_ui = 1;
    // Capture current mapping; if none, wildcard to any mapped line
    uint32_t pc24 = (uint32_t)(m68k_get_reg(NULL, M68K_REG_PC)) & 0x00ffffffu;
    const LineRow *r = lt_find(pc24);
    if (r) { s_step_line_file = r->file; s_step_line_num = r->line; }
    else { s_step_line_file = UINT32_MAX; s_step_line_num = UINT32_MAX; }
}

void geo_debugger_break_immediate(void) {
    s_paused = 1;
    s_step_frame = 0; s_step_instr = 0; s_step_line = 0; s_step_armed_ui = 0;
    s_break_requested = 1; s_break_now = 1; s_resnap_needed = 1;
    m68k_end_timeslice();
}

void geo_debugger_toggle_break(void) {
    if (!s_paused) geo_debugger_break_immediate();
    else geo_debugger_continue();
}

void geo_debugger_step_instr_cmd(void) {
    s_paused = 0;
    s_step_line = 0;
    s_step_instr = 1;
    s_step_armed_ui = 1;
}

void geo_debugger_step_next_line_cmd(void) {
    geo_debugger_step_next_line();
}

void geo_debugger_window_set_visible(int vis) { s_window_visible = vis ? 1 : 0; }
int  geo_debugger_window_is_visible(void) { return s_window_visible; }

void geo_debugger_instr_hook(unsigned pc) {
    // Called before executing instruction
    s_last_pc = pc & 0x00ffffffu;
    // Single-instruction step: end timeslice so current instruction runs and CPU returns to host
    if (s_step_instr) {
        s_step_instr = 0;
        s_paused = 1;
        s_break_now = 1;
        s_resnap_needed = 1;
        s_step_armed_ui = 0;
        // Stop CPU after this instruction
        m68k_end_timeslice();
        return;
    }
    // Step until next source line
    if (s_step_line) {
        const LineRow *r = lt_find(s_last_pc);
        int should_break = 0;
        if (r) {
            if (s_step_line_file == UINT32_MAX) {
                should_break = 1; // break on first mapped line
            } else if (r->file != s_step_line_file || r->line != s_step_line_num) {
                should_break = 1;
            }
        }
        if (should_break) {
            s_step_line = 0;
            s_paused = 1;
            s_break_now = 1;
            s_resnap_needed = 1;
            s_step_armed_ui = 0;
            m68k_end_timeslice();
            return;
        }
    }
    if (has_breakpoint(s_last_pc)) {
        // Mid-frame breakpoint: pause immediately and end timeslice
        s_break_requested = 1; // used for user notification at frame end
        s_hit_pc = s_last_pc;
        s_paused = 1;
        s_break_now = 1;
        s_resnap_needed = 1;
        m68k_end_timeslice();
        return;
    }
}

void geo_debugger_end_of_frame_update(void (*notify)(const char *msg, int frames)) {
    if (s_break_requested) {
        s_break_requested = 0;
        s_paused = 1;
        if (notify) notify("Breakpoint hit", 120);
        return;
    }
    if (s_step_frame) {
        // We ran one frame after a step-frame request; re-pause now
        s_step_frame = 0;
        s_paused = 1;
        if (notify) notify("Step frame", 90);
    }
}

void geo_debugger_ui_update(int key_enable, int key_toggle, int key_continue,
                            int key_step_instr, int key_step_line,
                            int key_toggle_bp, void (*notify)(const char *msg, int frames)) {
    static int prev_tog=0, prev_cont=0, prev_step=0, prev_step_ln=0, prev_bp=0;
    (void)key_enable; // always enabled now
    int now;

    // Running mode: only allow Break (T) and Disable (handled above)
    if (!s_paused) {
        // Suppress running HUD on the frame we armed a step to avoid flicker
        if (s_step_armed_ui) {
            // Still show footer minimally if desired; for now, draw nothing
            return;
        }
        now = key_toggle?1:0; if (now && !prev_tog) {
            // Break immediately mid-frame
            s_paused = 1; s_step_frame = 0; s_step_instr = 0; s_break_requested = 1; s_break_now = 1;
            m68k_end_timeslice();
            if (notify) notify("Break", 90);
        }
        prev_tog = now;
        // ignore continue/step/bp while running
        prev_cont = key_continue?1:0;
        prev_step = key_step_instr?1:0;
        prev_step_ln = key_step_line?1:0;
        prev_bp   = key_toggle_bp?1:0;
        return;
    }

    // key_toggle acts as Break/Continue toggle
    now = key_toggle?1:0; if (now && !prev_tog) {
        if (!s_paused) { s_paused = 1; s_step_frame = 0; if (notify) notify("Break", 90); }
        else { geo_debugger_continue(); if (notify) notify("Continue", 60); }
    }
    prev_tog = now;

    now = key_continue?1:0; if (now && !prev_cont) { geo_debugger_continue(); if (notify) notify("Continue", 60); }
    prev_cont = now;

    now = key_step_instr?1:0; if (now && !prev_step) { geo_debugger_step_instr(); if (notify) notify("Step", 90); }
    prev_step = now;

    now = key_step_line?1:0; if (now && !prev_step_ln) { geo_debugger_step_next_line(); if (notify) notify("Next line", 90); }
    prev_step_ln = now;

    now = key_toggle_bp?1:0; if (now && !prev_bp) {
        uint32_t pc24 = (uint32_t)(m68k_get_reg(NULL, M68K_REG_PC)) & 0x00ffffffu;
        toggle_breakpoint(pc24);
        if (notify) notify(has_breakpoint(pc24)?"Breakpoint set":"Breakpoint cleared", 90);
    }
    prev_bp = now;
}

void geo_debugger_list_breakpoints(void (*notify)(const char *msg, int frames)) {
    pthread_mutex_lock(&s_bp_mutex);
    if (s_nbps == 0) {
        printf("Debugger: no breakpoints\n");
        fflush(stdout);
        pthread_mutex_unlock(&s_bp_mutex);
        if (notify) notify("Breakpoints: none", 120);
        return;
    }
    printf("Debugger: breakpoints (%zu)\n", s_nbps);
    for (size_t i = 0; i < s_nbps; ++i) {
        printf("  0x%06x\n", (unsigned)s_bps[i]);
    }
    fflush(stdout);
    pthread_mutex_unlock(&s_bp_mutex);
    if (notify) notify("Breakpoints logged to console", 120);
}

// Minimal overlay just shows paused state, PC and file:line
static inline uint32_t blend_over(uint32_t dst, uint32_t src, uint8_t a) {
    uint32_t inv = (uint32_t)(255 - a);
    uint32_t dr = (dst >> 16) & 0xFF, dg = (dst >> 8) & 0xFF, db = dst & 0xFF;
    uint32_t sr = (src >> 16) & 0xFF, sg = (src >> 8) & 0xFF, sb = src & 0xFF;
    uint32_t rr = (sr * a + dr * inv) / 255;
    uint32_t gg = (sg * a + dg * inv) / 255;
    uint32_t bb = (sb * a + db * inv) / 255;
    return 0xFF000000u | (rr << 16) | (gg << 8) | bb;
}

// 5x7 glyphs subset (A-Z, 0-9, space, colon, X, P, A, U, S, E, D, B, R, K)
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
    if (c == ' ') { out[0]=out[1]=out[2]=out[3]=out[4]=0; return; }
    if (c == ':') { out[0]=0x00; out[1]=0x36; out[2]=0x36; out[3]=0x00; out[4]=0x00; return; }
}

static void draw_text5x7_alpha(uint32_t *vbuf, int fbw, int fbh, int x, int y, const char *txt, uint32_t color, uint8_t alpha) {
    int cx = x, cy = y;
    for (const char *p = txt; *p; ++p) {
        if (*p == '\n') { cy += 10; cx = x; continue; }
        uint8_t cols[5]; glyph5x7_get(*p, cols);
        for (int dx=0; dx<5; dx++) {
            uint8_t bits = cols[dx];
            for (int dy=0; dy<7; dy++) {
                if (bits & (1 << dy)) {
                    int px = cx + dx; int py = cy + dy;
                    if ((unsigned)px < (unsigned)fbw && (unsigned)py < (unsigned)fbh) {
                        uint32_t *pp = &vbuf[py*fbw + px];
                        *pp = blend_over(*pp, color, alpha);
                    }
                }
            }
        }
        cx += 6; // 5 + 1 spacing
    }
}

static void fill_rect_alpha(uint32_t *vbuf, int fbw, int fbh, int x, int y, int w, int h, uint32_t color, uint8_t alpha) {
    if (!vbuf || w <= 0 || h <= 0) return;
    int x0 = x < 0 ? 0 : x;
    int y0 = y < 0 ? 0 : y;
    int x1 = x + w; if (x1 > fbw) x1 = fbw;
    int y1 = y + h; if (y1 > fbh) y1 = fbh;
    for (int py = y0; py < y1; ++py) {
        uint32_t *row = vbuf + py * fbw;
        for (int px = x0; px < x1; ++px) {
            row[px] = geo_blend_over(row[px], color, alpha);
        }
    }
}

// Internal disassembler fallback: a few lines starting at pc
static void draw_disasm_overlay(uint32_t *vbuf, int fbw, int fbh, int x, int y, int x_right, uint32_t pc24, int lines) {
    uint32_t pc = pc24;
    int row_px = 10;
    int center = (lines > 0) ? (lines / 2) : 0;
    int base_y = y + center * row_px;
    for (int i=0; i<lines; ++i) {
        char buf[128];
        unsigned adv = m68k_disassemble(buf, pc, M68K_CPU_TYPE_68000);
        char out[180];
        int is_cur = (i == 0);
        if (is_cur) {
            // Highlight current line background
            fill_rect_alpha(vbuf, fbw, fbh, x-2, base_y - 1, (x_right - x) - 4, 9, 0xff4060a0, 160);
        }
        snprintf(out, sizeof(out), "%c  %06X  %s", (is_cur?'>':' '), (unsigned)pc, buf);
        int ta = geo_overlay_text_alpha(); int ta_dim = ta > 32 ? ta-32 : ta;
        geo_draw_text5x7_alpha(vbuf, fbw, fbh, x, base_y + i*row_px, out, is_cur?0xffffffff:0xffe0e0e0, (uint8_t)(is_cur?ta:ta_dim));
        if (adv == 0) adv = 2; // safety
        pc = (pc + adv) & 0x00ffffffu;
    }
}

// ---------------- Mixed source/asm via external objdump -----------------
typedef struct {
    int is_src;        // 1=source line, 0=asm line
    uint32_t addr;     // for asm lines, parsed address; for src lines, 0xffffffff
    char text[192];
} MixedLine;

static MixedLine s_mixed[128];
static int s_mixed_n = 0;
static uint32_t s_mixed_start = 0, s_mixed_end = 0;
static uint32_t s_mixed_anchor_pc = 0; // pc used when generating

static const char* getenv_nonempty(const char *k){ const char *v = getenv(k); return (v && v[0]) ? v : NULL; }

static int parse_hex_addr6(const char *s, uint32_t *out) {
    // expects 1+ spaces then 1-8 hex digits then ':'
    const char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    const char *q = p; int nhex = 0; uint32_t v = 0; while (*q && isxdigit((unsigned char)*q)) { char c=*q; v = (v<<4) | (uint32_t)(isdigit((unsigned char)c)? c-'0' : (10 + (tolower(c)-'a'))); q++; nhex++; }
    if (nhex < 1 || *q != ':') return 0;
    *out = v & 0x00ffffffu; return 1;
}

static void quote_arg(const char *in, char *out, size_t outsz) {
    // Simple shell-escaping: wrap in single quotes, escape existing single quotes
    size_t n = 0; if (outsz == 0) return; out[n++] = '\''; for (const char *p=in; *p && n+4<outsz; ++p) { if (*p=='\''){ out[n++]='\''; out[n++]='\\'; out[n++]='\''; out[n++]='\''; } else { out[n++]=*p; } } if (n<outsz) out[n++]='\''; if (n<=outsz) out[n]='\0'; else out[outsz-1]='\0'; }

static int fetch_mixed_for_pc(uint32_t pc24) {
    const char *elf = getenv_nonempty("GEO_DBG_ELF"); if (!elf) elf = getenv_nonempty("GEO_PROF_ELF"); if (!elf) return 0;
    const char *obj = getenv_nonempty("GEO_DBG_OBJDUMP"); if (!obj) obj = "m68k-neogeo-elf-objdump";
    uint32_t start = (pc24 > 0x40) ? (pc24 - 0x20) : 0;
    uint32_t stop  = (pc24 + 0x100) & 0x00ffffffu;
    char elf_q[1024]; quote_arg(elf, elf_q, sizeof(elf_q));
    char cmd[1400];
    snprintf(cmd, sizeof(cmd), "%s -S -l -d -C --no-show-raw-insn --start-address=0x%06x --stop-address=0x%06x %s", obj, (unsigned)start, (unsigned)stop, elf_q);

    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    s_mixed_n = 0; s_mixed_start = start; s_mixed_end = stop; s_mixed_anchor_pc = pc24;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (s_mixed_n >= (int)(sizeof(s_mixed)/sizeof(s_mixed[0]))) break;
        // Trim
        size_t L = strlen(line); while (L && (line[L-1]=='\n' || line[L-1]=='\r')) line[--L] = '\0';
        if (!L) continue;
        // Look for address line
        uint32_t a = 0; int is_addr = parse_hex_addr6(line, &a);
        if (is_addr) {
            // Skip the leading address+colon and spaces
            const char *p = line; while (*p && *p!=':') p++; if (*p==':') p++; while (*p=='\t' || *p==' ') p++;
            // Keep asm mnemonic line
            s_mixed[s_mixed_n].is_src = 0; s_mixed[s_mixed_n].addr = a;
            snprintf(s_mixed[s_mixed_n].text, sizeof(s_mixed[s_mixed_n].text), "%s", p);
            s_mixed_n++;
            continue;
        }
        // Heuristic 1: file:line headers like "/path/file.c:123"
        const char *colon = strrchr(line, ':');
        if (colon) {
            const char *p = colon + 1; int alldig = 1; if (!*p) alldig = 0; for (; *p; ++p) { if (!isdigit((unsigned char)*p)) { alldig = 0; break; } }
            if (alldig) {
                s_mixed[s_mixed_n].is_src = 1; s_mixed[s_mixed_n].addr = 0xffffffffu;
                // Show only basename to save space
                const char *base = line; for (const char *q=line; *q; ++q) if (*q=='/' || *q=='\\') base = q+1;
                snprintf(s_mixed[s_mixed_n].text, sizeof(s_mixed[s_mixed_n].text), "%s", base);
                s_mixed_n++;
                continue;
            }
        }
        // Heuristic 2: actual C source lines as printed by objdump -S
        // These are typically non-empty, non-address lines; skip function label lines like "<func>:"
        const char *t = line; while (*t=='\t' || *t==' ') t++;
        if (*t) {
            size_t len = strlen(t);
            int is_func_lbl = (t[0]=='<' && len>2 && t[len-1]==':');
            // Also ignore assembler directives that look like labels without address
            if (!is_func_lbl) {
                s_mixed[s_mixed_n].is_src = 1; s_mixed[s_mixed_n].addr = 0xffffffffu;
                snprintf(s_mixed[s_mixed_n].text, sizeof(s_mixed[s_mixed_n].text), "%s", t);
                s_mixed_n++;
                continue;
            }
        }
    }
    pclose(fp);
    return s_mixed_n > 0;
}

static void draw_mixed_overlay(uint32_t *vbuf, int fbw, int fbh, int x, int y, int x_right, uint32_t pc24, int max_lines) {
    // Ensure cache covers pc24
    if (!(pc24 >= s_mixed_start && pc24 < s_mixed_end) || s_mixed_n == 0) {
        if (!fetch_mixed_for_pc(pc24)) {
            // Fallback to internal disasm
            draw_disasm_overlay(vbuf, fbw, fbh, x, y, x_right, pc24, max_lines);
            return;
        }
    }
    // Find current pc line index
    int cur = -1; for (int i=0;i<s_mixed_n;i++) if (!s_mixed[i].is_src && s_mixed[i].addr == pc24) { cur = i; break; }
    int center = (max_lines > 0) ? (max_lines / 2) : 0;
    int start = cur < 0 ? 0 : (cur - center);
    if (start < 0) start = 0;
    if (s_mixed_n > max_lines && start > s_mixed_n - max_lines) start = s_mixed_n - max_lines;
    int drawn = 0;
    int ta = geo_overlay_text_alpha();
    int ta_dim = ta > 32 ? (ta - 32) : ta;
    // Compute column where address starts in our asm format: ">  %06X  %s"
    int adv = geo_glyph_advance_px(' ');
    int addr_left_x = x + (1 + 2) * adv; // marker + two spaces
    for (int i=start; i<s_mixed_n && drawn<max_lines; ++i) {
        const MixedLine *ml = &s_mixed[i];
        uint32_t color = ml->is_src ? 0xffa0ffa0 : 0xffeaeaea;
        char line[256];
        int is_cur = (!ml->is_src && ml->addr == pc24);
        if (is_cur) {
            // Background highlight for current instruction line
            fill_rect_alpha(vbuf, fbw, fbh, x-2, y + drawn*10 - 1, (x_right - x) - 4, 9, 0xff4060a0, 160);
        }
        if (ml->is_src) {
            snprintf(line, sizeof(line), "%s", ml->text);
            geo_draw_text5x7_alpha(vbuf, fbw, fbh, addr_left_x, y + drawn*10, line, is_cur?0xffffffff:color, (uint8_t)(is_cur ? ta : ta_dim));
        } else {
            snprintf(line, sizeof(line), "%c  %06X  %s", (is_cur?'>':' '), (unsigned)ml->addr, ml->text);
            geo_draw_text5x7_alpha(vbuf, fbw, fbh, x, y + drawn*10, line, is_cur?0xffffffff:color, (uint8_t)(is_cur ? ta : ta_dim));
        }
        drawn++;
    }
}

void geo_debugger_draw_overlay(uint32_t *vbuf,
                               int fb_width, int fb_height,
                               int vis_left, int vis_top,
                               int vis_width, int vis_height) {
    if (!vbuf) return;
    // If running and window not visible: draw nothing
    if (!s_paused && !s_window_visible) return;

    int x_vis_left = vis_left;
    int y_vis_top  = vis_top;
    int x_vis_right = x_vis_left + vis_width;
    int y_vis_bottom = y_vis_top + vis_height;
    int x0 = x_vis_left;
    int y0 = y_vis_top;
    int boxw = vis_width;
    int boxh = vis_height;

    uint32_t pc24 = (uint32_t)(m68k_get_reg(NULL, M68K_REG_PC)) & 0x00ffffffu;
    int ta = geo_overlay_text_alpha();
    int ta_dim = ta > 32 ? (ta - 32) : ta;

    // If paused and window hidden, draw a minimal pause hint and return
    if (s_paused && !s_window_visible) {
        const char *msg = "DEBUGGER PAUSED - PRESS T TO CONTINUE";
        int x0 = x_vis_left;
        int y0 = y_vis_top;
        int boxw = vis_width;
        int ta = geo_overlay_text_alpha();
        int msg_w = geo_text5x7_width(msg) + 12; if (msg_w > boxw) msg_w = boxw;
        // Header-style bar at top-left
        fill_rect_alpha(vbuf, fb_width, fb_height, x0, y0, msg_w, 12, 0xff101020, (uint8_t)geo_overlay_alpha_get());
        geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, x0 + 6, y0 + 2, msg, 0xffffffff, (uint8_t)ta);
        return;
    }

    // Otherwise draw full overlay (paused or running with window visible)

    // Paused: full overlay and mixed view
    // Alpha background across the full visible area (respects shared alpha)
    {
        int bg_alpha = geo_overlay_alpha_get();
        for (int y=0; y<boxh; ++y) {
            int py = y0 + y; if (py < 0 || py >= fb_height) continue;
            uint32_t *row = vbuf + py * fb_width;
            for (int x=0; x<boxw; ++x) {
                int px = x0 + x; if (px < 0 || px >= fb_width) continue;
                uint32_t *p = &row[px];
                *p = geo_blend_over(*p, 0xff101020, (uint8_t)bg_alpha);
            }
        }
    }

    // Compact 68K register view at top (paused mode), wrapped to visible width
    const int row_px = 10;
    int reg_x = x0 + 6;
    int reg_y = y0 + 2;
    int reg_maxw = (x_vis_right - 6) - reg_x;

    uint16_t sr = (uint16_t)(m68k_get_reg(NULL, M68K_REG_SR) & 0xFFFF);
    int ipl = (sr >> 8) & 0x7;
    char flagsbuf[6];
    flagsbuf[0] = (sr & 0x0010) ? 'X' : '-';
    flagsbuf[1] = (sr & 0x0008) ? 'N' : '-';
    flagsbuf[2] = (sr & 0x0004) ? 'Z' : '-';
    flagsbuf[3] = (sr & 0x0002) ? 'V' : '-';
    flagsbuf[4] = (sr & 0x0001) ? 'C' : '-';
    flagsbuf[5] = '\0';
    char topln[96];
    snprintf(topln, sizeof(topln), "PC=%06X SR=%04X %c %c IPL=%d %s",
             (unsigned)pc24, (unsigned)sr,
             (sr & 0x8000) ? 'T' : 't', (sr & 0x2000) ? 'S' : 's', ipl, flagsbuf);
    geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, reg_x, reg_y, topln, 0xffffffff, (uint8_t)ta);
    reg_y += row_px;

    char dgrp[8][14]; const char *ditems[8];
    for (int i=0;i<8;i++){ unsigned v=(unsigned)m68k_get_reg(NULL, M68K_REG_D0 + i); snprintf(dgrp[i], sizeof(dgrp[i]), "D%d=%08X ", i, v); ditems[i]=dgrp[i]; }
    reg_y = draw_groups_wrapped(vbuf, fb_width, fb_height, reg_x, reg_y, reg_maxw,
                                 (const char**)ditems, 8, 0xffeaeaea, (uint8_t)ta, row_px);

    char agrp[8][14]; const char *aitems[8];
    for (int i=0;i<8;i++){ unsigned v=(unsigned)m68k_get_reg(NULL, M68K_REG_A0 + i); snprintf(agrp[i], sizeof(agrp[i]), "A%d=%08X ", i, v); aitems[i]=agrp[i]; }
    reg_y = draw_groups_wrapped(vbuf, fb_width, fb_height, reg_x, reg_y, reg_maxw,
                                 (const char**)aitems, 8, 0xffeaeaea, (uint8_t)ta, row_px);

    // (No extra CCR line: flags included on top line)

    // Mixed source/asm or fallback disassembly below; center current line in remaining space
    int header_h = (reg_y - y0) + 2;
    int bottom_h = 12; // space for footer shortcuts
    int max_lines = (boxh - header_h - bottom_h) / row_px; if (max_lines < 0) max_lines = 0;
    draw_mixed_overlay(vbuf, fb_width, fb_height, x0 + 6, y0 + header_h, x_vis_right - 6, pc24, max_lines);

    // Controls hint at bottom line
    int footer_y = y_vis_bottom - row_px - 2;
    if (footer_y < y0) footer_y = y0;
    geo_draw_text5x7_alpha(vbuf, fb_width, fb_height, x0 + 6, footer_y, "\\:HIDE  T:RUN  S:ASM STEP  N:C STEP", 0xffa0ffa0, (uint8_t)ta_dim);
}
