// Minimal GDB RSP stub adapter API (transport included).
#ifndef THIRD_PARTY_GDBSTUB_H
#define THIRD_PARTY_GDBSTUB_H

#include <stdint.h>
#include <stddef.h>

typedef struct gdbstub_ops {
  // Register file: index mapping is target-defined (we'll use m68k: d0-7,a0-7,ps,pc)
  uint32_t (*read_reg)(int index);
  void     (*write_reg)(int index, uint32_t value);

  // Memory access
  int (*read_mem)(uint32_t addr, uint8_t *buf, size_t len);
  int (*write_mem)(uint32_t addr, const uint8_t *buf, size_t len);

  // Execution control
  void (*resume_continue)(void);
  void (*resume_step)(void);
  void (*request_break)(void);

  // Breakpoints
  void (*add_sw_break)(uint32_t addr);
  void (*del_sw_break)(uint32_t addr);
} gdbstub_ops_t;

// Start/stop the stub on 127.0.0.1:port. Returns actual bound port (>=0) or -1.
// Starts on the exact port provided; returns port on success, -1 on failure.
int  gdbstub_start(int port, const gdbstub_ops_t *ops);
void gdbstub_stop(void);

// Poll from emulation thread to send stop replies after step/break; paused=1 if currently paused.
void gdbstub_poll(int paused);

// Diagnostics: return recent packet log lines; returns count.
int  gdbstub_log_lines(char out[][128], int max_lines);
int  gdbstub_client_connected(void);

#endif
