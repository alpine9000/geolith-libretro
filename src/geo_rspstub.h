#ifndef GEO_RSPSTUB_H
#define GEO_RSPSTUB_H

#include <stdint.h>
#include <stddef.h>

typedef struct geo_rspstub_ops {
  uint32_t (*read_reg)(int index);
  void     (*write_reg)(int index, uint32_t value);
  int      (*read_mem)(uint32_t addr, uint8_t *buf, size_t len);
  int      (*write_mem)(uint32_t addr, const uint8_t *buf, size_t len);
  void     (*resume_continue)(void);
  void     (*resume_step)(void);
  void     (*request_break)(void);
  void     (*add_sw_break)(uint32_t addr);
  void     (*del_sw_break)(uint32_t addr);
} geo_rspstub_ops_t;

int  geo_rspstub_start(int port, const geo_rspstub_ops_t *ops);
void geo_rspstub_stop(void);
void geo_rspstub_poll(int paused);

#endif // GEO_RSPSTUB_H

