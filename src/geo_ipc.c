#include "geo_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <pthread.h>

#include "geo_debugger.h"
#include "geo_ports.h"
#include "geo_profiler.h"
#include "geo_text.h"

// Very small TCP server for control commands
static int s_listen_fd = -1;
static int s_client_fd = -1;
static pthread_t s_thread;
static int s_run = 0;

typedef enum { CMD_NONE=0, CMD_TOGGLE_BREAK, CMD_STEP_INSTR, CMD_STEP_LINE, CMD_TOGGLE_PROF, CMD_TOGGLE_BP_PC, CMD_SET_ALPHA } cmd_kind_t;
typedef struct { cmd_kind_t k; int v; } cmd_t;

#define QCAP 64
static cmd_t s_q[QCAP];
static volatile unsigned s_q_head = 0, s_q_tail = 0; // single producer (thread), single consumer (main)

static void q_push(cmd_t c){ unsigned n = (s_q_head + 1u) % QCAP; if (n != s_q_tail){ s_q[s_q_head] = c; s_q_head = n; } }
static int q_pop(cmd_t *out){ if (s_q_tail == s_q_head) return 0; *out = s_q[s_q_tail]; s_q_tail = (s_q_tail + 1u) % QCAP; return 1; }

static int set_nonblock(int fd){ int fl=fcntl(fd,F_GETFL,0); if(fl<0) return -1; return fcntl(fd,F_SETFL, fl|O_NONBLOCK); }

static void close_client(void){ if (s_client_fd>=0){ close(s_client_fd); s_client_fd=-1; } }

static void handle_line(const char *line){
    // Very naive JSON command parser
    if (strstr(line, "\"cmd\":\"toggle_break\"")) { q_push((cmd_t){CMD_TOGGLE_BREAK,0}); return; }
    if (strstr(line, "\"cmd\":\"step_instr\"")) { q_push((cmd_t){CMD_STEP_INSTR,0}); return; }
    if (strstr(line, "\"cmd\":\"step_next_line\"")) { q_push((cmd_t){CMD_STEP_LINE,0}); return; }
    if (strstr(line, "\"cmd\":\"toggle_profiler\"")) { q_push((cmd_t){CMD_TOGGLE_PROF,0}); return; }
    if (strstr(line, "\"cmd\":\"toggle_bp_at_pc\"")) { q_push((cmd_t){CMD_TOGGLE_BP_PC,0}); return; }
    if (strstr(line, "\"cmd\":\"set_alpha\"")) {
        const char *p = strstr(line, "\"value\":"); int v=0; if (p){ v = atoi(p+8); }
        cmd_t c = {CMD_SET_ALPHA, v}; q_push(c); return;
    }
}

static void* srv_thread(void *arg){ (void)arg; s_run = 1; char buf[1024]; char line[1024]; size_t lpos=0;
    while (s_run) {
        if (s_client_fd < 0) {
            struct sockaddr_in caddr; socklen_t clen = sizeof(caddr);
            int cfd = accept(s_listen_fd, (struct sockaddr*)&caddr, &clen);
            if (cfd >= 0) { set_nonblock(cfd); s_client_fd = cfd; lpos=0; }
            else { usleep(2000); }
            continue;
        }
        ssize_t n = recv(s_client_fd, buf, sizeof(buf), 0);
        if (n > 0) {
            for (ssize_t i=0;i<n;i++) {
                char ch = buf[i];
                if (ch == '\n' || ch == '\r') { line[lpos] = '\0'; if (lpos>0) handle_line(line); lpos = 0; }
                else if (lpos < sizeof(line)-1) { line[lpos++] = ch; }
            }
        } else if (n == 0) {
            close_client();
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) close_client(); else usleep(1000);
        }
    }
    close_client();
    return NULL;
}

int geo_ipc_start(void){
    if (s_run) return 0;
    s_run = 1; // prevent double-start races before thread sets it
    int port = GEO_IPC_PORT_DEFAULT; // fixed IPC port
    s_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_listen_fd < 0) {
        fprintf(stderr, "IPC: socket(AF_INET,SOCK_STREAM) failed: errno=%d (%s)\n", errno, strerror(errno));
        s_run = 0;
        return -1;
    }
    int yes = 1; setsockopt(s_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr)); addr.sin_family=AF_INET; addr.sin_port=htons((uint16_t)port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(s_listen_fd,(struct sockaddr*)&addr,sizeof(addr))<0){
        fprintf(stderr, "IPC: bind(fd=%d, addr=127.0.0.1, port=%d) failed: errno=%d (%s)\n", s_listen_fd, port, errno, strerror(errno));
        close(s_listen_fd); s_listen_fd=-1; s_run = 0; return -1; }
    if (listen(s_listen_fd,1)<0){
        fprintf(stderr, "IPC: listen(fd=%d,backlog=1) failed: errno=%d (%s)\n", s_listen_fd, errno, strerror(errno));
        close(s_listen_fd); s_listen_fd=-1; s_run = 0; return -1; }
    set_nonblock(s_listen_fd);
    pthread_create(&s_thread, NULL, srv_thread, NULL);
    fprintf(stderr, "IPC: listening 127.0.0.1:%d fd=%d\n", port, s_listen_fd);
    return port;
}

void geo_ipc_stop(void){ if (!s_run) return; s_run=0; pthread_join(s_thread,NULL); if (s_listen_fd>=0){ close(s_listen_fd); s_listen_fd=-1; } close_client(); }

static void send_json(const char *s){ if (s_client_fd>=0) { send(s_client_fd, s, (int)strlen(s), 0); send(s_client_fd, "\n", 1, 0); } }

void geo_ipc_update(uint32_t pc, uint32_t sr, int paused, int profiler_enabled){
    char out[256]; snprintf(out, sizeof(out), "{\"state\":{\"pc\":\"0x%06X\",\"sr\":\"0x%04X\",\"paused\":%s,\"profiler\":%s}}",
                            (unsigned)(pc & 0x00ffffffu), (unsigned)(sr & 0xffffu), paused?"true":"false", profiler_enabled?"true":"false");
    send_json(out);
}

void geo_ipc_apply_pending(void){
    cmd_t c; while (q_pop(&c)) {
        switch (c.k) {
            case CMD_TOGGLE_BREAK: geo_debugger_toggle_break(); break;
            case CMD_STEP_INSTR: geo_debugger_step_instr_cmd(); break;
            case CMD_STEP_LINE: geo_debugger_step_next_line_cmd(); break;
            case CMD_TOGGLE_PROF: { int pe=geo_profiler_get_enabled(); geo_profiler_set_enabled(!pe); } break;
            case CMD_TOGGLE_BP_PC: geo_debugger_ui_update(0,0,0,0,0,1,NULL); break;
            case CMD_SET_ALPHA: geo_overlay_alpha_set(c.v); break;
            default: break;
        }
    }
}
