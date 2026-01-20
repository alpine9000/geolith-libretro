#include "geo_ui.h"

#include "geo_debugger.h"
#include "geo_profiler.h"
#include "geo_text.h"

#include "libretro.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "geo_ports.h"

// Key state tracking
static int kb_t=0,kb_s=0,kb_n=0,kb_b=0,kb_bs=0,kb_f10=0,kb_quote=0,kb_o=0;
static int pkb_t=0,pkb_s=0,pkb_n=0,pkb_b=0,pkb_bs=0,pkb_f10=0,pkb_quote=0,pkb_o=0;

// Profiler overlay visibility and saved state for mutual exclusion with debugger window
static int prof_overlay_visible = 0;
static int saved_dbg_vis_for_prof = -1;   // -1 = none saved, 0/1 saved state
static int saved_prof_vis_for_dbg = -1;   // -1 = none saved, 0/1 saved state

// UI key edges for overlay alpha and profiler scroll
static int s_prev_comma = 0;
static int s_prev_period = 0;

void geo_ui_kb_event(bool down, unsigned keycode, uint32_t character, uint16_t mod) {
    (void)character; (void)mod;
    switch (keycode) {
        case RETROK_t:    kb_t   = down ? 1 : 0; break;
        case RETROK_s:    kb_s   = down ? 1 : 0; break;
        case RETROK_n:    kb_n   = down ? 1 : 0; break;
        case RETROK_b:    kb_b   = down ? 1 : 0; break;
        case RETROK_BACKSLASH: kb_bs = down ? 1 : 0; break;
        case RETROK_F10:  kb_f10 = down ? 1 : 0; break;
        case RETROK_QUOTE: kb_quote = down ? 1 : 0; break;
        case RETROK_o:   kb_o   = down ? 1 : 0; break;
        default: break;
    }
}

void geo_ui_handle_input(geo_ui_input_state_t input_state_cb,
                         void (*notify)(const char *msg, int frames)) {
    // Poll keyboard state as fallback
    int pol_t  = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_t) ? 1 : 0;
    int pol_s  = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_s) ? 1 : 0;
    int pol_n  = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_n) ? 1 : 0;
    int pol_b  = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_b) ? 1 : 0;
    int pol_bs = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_BACKSLASH) ? 1 : 0;
    int pol_f10= input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_F10) ? 1 : 0;
    int pol_quote= input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_QUOTE) ? 1 : 0;
    int pol_o = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_o) ? 1 : 0;
    kb_t   = kb_t   || pol_t;
    kb_s   = kb_s   || pol_s;
    kb_n   = kb_n   || pol_n;
    kb_b   = kb_b   || pol_b;
    kb_bs  = kb_bs  || pol_bs;
    kb_f10 = kb_f10 || pol_f10;
    kb_quote = kb_quote || pol_quote;
    kb_o = kb_o || pol_o;

    // F10 toggles profiling collection only
    int edge_f10 = kb_f10 && !pkb_f10;
    if (edge_f10) {
        int pe = geo_profiler_get_enabled();
        geo_profiler_set_enabled(!pe);
        if (!pe) { if (notify) notify("Profiler: ON  —  press ' to show/hide overlay", 180); }
        else      { if (notify) notify("Profiler: OFF", 90); }
    }

    // Backslash toggles debugger window visibility, mutual exclusion with profiler overlay
    int edge_bs = kb_bs && !pkb_bs;
    if (edge_bs) {
        int vis = geo_debugger_window_is_visible();
        if (!vis) {
            if (prof_overlay_visible) { saved_prof_vis_for_dbg = 1; prof_overlay_visible = 0; }
            geo_debugger_window_set_visible(1);
            if (notify) notify("Debugger window: ON", 60);
        } else {
            geo_debugger_window_set_visible(0);
            if (saved_prof_vis_for_dbg == 1) { prof_overlay_visible = 1; saved_prof_vis_for_dbg = -1; }
            if (notify) notify("Debugger window: OFF", 60);
        }
    }

    // Apostrophe toggles profiler overlay visibility, mutual exclusion with debugger window
    int edge_quote = kb_quote && !pkb_quote;
    if (edge_quote) {
        if (!prof_overlay_visible) {
            if (geo_debugger_window_is_visible()) { saved_dbg_vis_for_prof = 1; geo_debugger_window_set_visible(0); }
            else saved_dbg_vis_for_prof = 0;
            prof_overlay_visible = 1;
        } else {
            prof_overlay_visible = 0;
            if (saved_dbg_vis_for_prof == 1) { geo_debugger_window_set_visible(1); }
            saved_dbg_vis_for_prof = -1;
        }
    }

    // Launch external GDB in a new terminal window
    int pol_g = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_g) ? 1 : 0;
    static int prev_g = 0;
    int edge_g = pol_g && !prev_g;
    if (edge_g) {
        // Launch SDL e9k-debugger as a child process (detached)
        const char *elf = getenv("GEO_PROF_ELF");
        const char *src = getenv("GEO_PROF_SRC_BASE");
        const char *bin = getenv("GEO_DEBUGGER_BIN");
        if (!bin || !*bin) bin = "e9k-debugger";
        char *args[10]; int ai=0;
        args[ai++] = (char*)bin;
        if (elf && *elf) { args[ai++] = "--elf"; args[ai++] = (char*)elf; }
        if (src && *src) { args[ai++] = "--src"; args[ai++] = (char*)src; }
        args[ai++] = "--port"; char pbuf[16]; snprintf(pbuf, sizeof(pbuf), "%d", GEO_RSP_PORT_DEFAULT); args[ai++] = pbuf;
        args[ai] = NULL;
        pid_t pid = fork();
        int launched = 0;
        if (pid == 0) {
            execvp(args[0], args);
            _exit(127);
        } else if (pid > 0) {
            launched = 1; // Parent continues; child has its own SDL window
        }
        if (notify) notify(launched?"Launching e9k-debugger...":"Failed to launch e9k-debugger", 120);
    }
    prev_g = pol_g;

    // In-emulator debugger keys
    int edge_t = kb_t && !pkb_t;
    int edge_s = kb_s && !pkb_s;
    int edge_n = kb_n && !pkb_n;
    int edge_b = kb_b && !pkb_b;
    if (edge_t) {
        if (geo_debugger_is_paused() && !geo_debugger_window_is_visible()) {
            geo_debugger_toggle_break();
        } else {
            if (prof_overlay_visible) { saved_prof_vis_for_dbg = 1; prof_overlay_visible = 0; }
            geo_debugger_window_set_visible(1);
            geo_debugger_toggle_break();
        }
    }
    if (edge_s) { geo_debugger_window_set_visible(1); geo_debugger_step_instr_cmd(); }
    if (edge_n) { geo_debugger_window_set_visible(1); geo_debugger_step_next_line_cmd(); }
    if (edge_b) { geo_debugger_window_set_visible(1); geo_debugger_ui_update(0,0,0,0,0,1, notify); }
    int edge_l = kb_o && !pkb_o;
    if (edge_l) { geo_debugger_list_breakpoints(notify); }

    // Overlay alpha hotkeys
    int k_minus = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_MINUS) ? 1 : 0;
    int k_equals = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_EQUALS) ? 1 : 0;
    int k_kp_minus = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_KP_MINUS) ? 1 : 0;
    int k_kp_plus  = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_KP_PLUS) ? 1 : 0;
    int alpha_changed = 0;
    if (k_minus) { geo_overlay_alpha_adjust(-8); alpha_changed = 1; }
    if (k_equals) { geo_overlay_alpha_adjust(+8); alpha_changed = 1; }
    if (k_kp_minus) { geo_overlay_alpha_adjust(-8); alpha_changed = 1; }
    if (k_kp_plus)  { geo_overlay_alpha_adjust(+8); alpha_changed = 1; }
    if (alpha_changed && notify) { char abuf[64]; int a = geo_overlay_alpha_get(); snprintf(abuf, sizeof(abuf), "Overlay alpha: %d", a); notify(abuf, 60); }

    // Profiler scroll keys
    int now_comma = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_COMMA) ? 1 : 0;
    if (now_comma && !s_prev_comma) { int sc = geo_profiler_get_scroll(); if (sc > 0) geo_profiler_render_reset(); }
    s_prev_comma = now_comma;
    int now_period = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_PERIOD) ? 1 : 0;
    if (now_period && !s_prev_period) { /* handled internally in profiler overlay */ }
    s_prev_period = now_period;

    // Update previous key states
    pkb_t = kb_t; pkb_s = kb_s; pkb_n = kb_n; pkb_b = kb_b; pkb_bs = kb_bs; pkb_f10 = kb_f10; pkb_quote = kb_quote;
    pkb_o = kb_o;
    // Reset latched states for next frame
    kb_t = kb_s = kb_n = kb_b = kb_bs = kb_f10 = kb_quote = kb_o = 0;
}

void geo_ui_draw_overlays(uint32_t *present_buf, int present_w, int present_h,
                          int vis_w, int vis_h) {
    (void)present_h; (void)present_w;
    // Debugger overlay decides what to show (full overlay, or paused hint)
    geo_debugger_draw_overlay(present_buf, present_w, present_h, 0, 0, vis_w, vis_h);
    // Profiler overlay shows only when toggled on and debugger window is hidden
    if (prof_overlay_visible && !geo_debugger_window_is_visible()) {
        geo_profiler_draw_overlay(present_buf, present_w, present_h, 0, 0, vis_w, vis_h);
    }
}
