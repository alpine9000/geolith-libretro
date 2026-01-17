#include "geo_rsp.h"
#include <stdlib.h>
#include "geo_rspstub.h"
#include "m68k/m68k.h"
#include "geo_debugger.h"
#include "geo_ports.h"

static uint32_t ops_read_reg(int idx){
    if (idx>=0 && idx<8) return (uint32_t)m68k_get_reg(NULL, M68K_REG_D0+idx);
    if (idx>=8 && idx<16) return (uint32_t)m68k_get_reg(NULL, M68K_REG_A0+(idx-8));
    if (idx==16) return (uint32_t)m68k_get_reg(NULL, M68K_REG_SR) & 0xFFFFu;
    if (idx==17) return (uint32_t)m68k_get_reg(NULL, M68K_REG_PC);
    return 0;
}
static void ops_write_reg(int idx, uint32_t v){
    if (idx>=0 && idx<8) { m68k_set_reg(M68K_REG_D0+idx, v); return; }
    if (idx>=8 && idx<16) { m68k_set_reg(M68K_REG_A0+(idx-8), v); return; }
    if (idx==16) { m68k_set_reg(M68K_REG_SR, v & 0xFFFFu); return; }
    if (idx==17) { m68k_set_reg(M68K_REG_PC, v); return; }
}
static int ops_read_mem(uint32_t addr, uint8_t *buf, size_t len){ for(size_t i=0;i<len;i++) buf[i]=(uint8_t)m68k_read_memory_8((unsigned)(addr+i)); return 0; }
static int ops_write_mem(uint32_t addr, const uint8_t *buf, size_t len){ for(size_t i=0;i<len;i++) m68k_write_memory_8((unsigned)(addr+i), buf[i]); return 0; }
static void ops_continue(void){ geo_debugger_continue(); }
static void ops_step(void){ geo_debugger_step_instr_cmd(); }
static void ops_break(void){ geo_debugger_break_immediate(); }
static void ops_add_bp(uint32_t addr){ geo_debugger_add_breakpoint(addr & 0x00ffffffu); }
static void ops_del_bp(uint32_t addr){ geo_debugger_remove_breakpoint(addr & 0x00ffffffu); }

int geo_rsp_start(void){
    int port = GEO_RSP_PORT_DEFAULT; // fixed RSP port
    geo_rspstub_ops_t ops = { ops_read_reg, ops_write_reg, ops_read_mem, ops_write_mem, ops_continue, ops_step, ops_break, ops_add_bp, ops_del_bp };
    return geo_rspstub_start(port, &ops);
}
void geo_rsp_stop(void){ geo_rspstub_stop(); }
void geo_rsp_poll(uint32_t pc, uint32_t sr, int paused){ (void)pc; (void)sr; geo_rspstub_poll(paused?1:0); }
