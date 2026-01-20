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
#include <stdarg.h>

#include <pthread.h>

#include "geo_ports.h"
#include "geo_profiler.h"
#include "geo_text.h"
#include "geo_notify.h"

// Very small TCP server for control commands
static int s_listen_fd = -1;
static int s_client_fd = -1;
static pthread_t s_thread;
static int s_run = 0;
static int s_streaming = 0;

typedef enum { CMD_NONE=0, CMD_PROFILER_START, CMD_PROFILER_STOP, CMD_PROFILER_STATE } cmd_kind_t;
typedef struct { cmd_kind_t k; int v; } cmd_t;

#define QCAP 64
static cmd_t s_q[QCAP];
static volatile unsigned s_q_head = 0, s_q_tail = 0; // single producer (thread), single consumer (main)

static void q_push(cmd_t c){ unsigned n = (s_q_head + 1u) % QCAP; if (n != s_q_tail){ s_q[s_q_head] = c; s_q_head = n; } }
static int q_pop(cmd_t *out){ if (s_q_tail == s_q_head) return 0; *out = s_q[s_q_tail]; s_q_tail = (s_q_tail + 1u) % QCAP; return 1; }

static int set_nonblock(int fd){ int fl=fcntl(fd,F_GETFL,0); if(fl<0) return -1; return fcntl(fd,F_SETFL, fl|O_NONBLOCK); }

static void close_client(void){ if (s_client_fd>=0){ close(s_client_fd); s_client_fd=-1; } }

static void log_geo_cmd(const char *phase, const char *txt){
    if (!txt) return;
    char buf[256];
    int len = snprintf(buf, sizeof(buf), "GEO IPC %s: %.200s", phase, txt);
    if (len < 0) len = 0;
    buf[sizeof(buf) - 1] = '\0';
    printf("%s\n", buf);
    geo_notify(buf, 90);
}

static void send_json(const char *s){ if (s_client_fd>=0) { send(s_client_fd, s, (int)strlen(s), 0); send(s_client_fd, "\n", 1, 0); } }

static void send_buf(const char *buf, size_t len){
    if (s_client_fd < 0 || !buf || len == 0) return;
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = send(s_client_fd, buf + pos, (int)(len - pos), 0);
        if (n > 0) {
            pos += (size_t)n;
            continue;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
        }
        break;
    }
}

static int append_printf(char *buf, size_t bufsize, size_t *pos, const char *fmt, ...) {
    if (*pos >= bufsize) return 0;
    va_list ap; va_start(ap, fmt);
    int res = vsnprintf(buf + *pos, bufsize - *pos, fmt, ap);
    va_end(ap);
    if (res < 0 || (size_t)res >= bufsize - *pos) {
        *pos = bufsize - 1;
        buf[*pos] = '\0';
        return 0;
    }
    *pos += (size_t)res;
    return 1;
}

static void append_literal(char *buf, size_t bufsize, size_t *pos, const char *s) {
    if (!s) return;
    while (*s && *pos + 1 < bufsize) {
        buf[(*pos)++] = *s++;
    }
}

static void append_json_byte(char *buf, size_t bufsize, size_t *pos, uint8_t byte) {
    if (*pos >= bufsize) return;
    if (byte >= 0x20 && byte <= 0x7e && byte != '"' && byte != '\\') {
        buf[(*pos)++] = (char)byte;
        return;
    }
    static const char hex[] = "0123456789ABCDEF";
    if (*pos + 6 > bufsize) return;
    buf[(*pos)++] = '\\';
    buf[(*pos)++] = 'u';
    buf[(*pos)++] = '0';
    buf[(*pos)++] = '0';
    buf[(*pos)++] = hex[(byte >> 4) & 0x0f];
    buf[(*pos)++] = hex[byte & 0x0f];
}

static void send_cmd_response(const char *cmd, const char *status){
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"cmd\":\"%s\",\"result\":\"%s\"}", cmd, status);
    send_json(buf);
}

void geo_ipc_send_debug_byte(uint8_t byte) {
    if (s_client_fd < 0) return;
    char buf[128];
    size_t pos = 0;
    append_literal(buf, sizeof(buf), &pos, "{\"event\":\"debug\",\"byte\":");
    append_printf(buf, sizeof(buf), &pos, "%u", byte);
    append_literal(buf, sizeof(buf), &pos, ",\"char\":\"");
    append_json_byte(buf, sizeof(buf), &pos, byte);
    append_literal(buf, sizeof(buf), &pos, "\"}\n");
    send_buf(buf, pos);
}

static void send_profiler_stream_frame(void) {
    if (!s_streaming) return;
    size_t pending = geo_profiler_stream_pending();
    if (pending == 0) return;
    geo_profiler_stream_hit_t *hits = (geo_profiler_stream_hit_t*)calloc(pending, sizeof(geo_profiler_stream_hit_t));
    if (!hits) return;
    size_t count = geo_profiler_stream_collect(hits, 0);
    if (count == 0) { free(hits); return; }
    geo_profiler_capture_stream_hits(hits, count);
    const char *enabled = geo_profiler_get_enabled() ? "enabled" : "disabled";
    char prefix[256];
    int plen = snprintf(prefix, sizeof(prefix), "{\"stream\":\"profiler\",\"enabled\":\"%s\",\"hits\":[", enabled);
    if (plen < 0) { free(hits); return; }
    send_buf(prefix, (size_t)plen);
    for (size_t i = 0; i < count; ++i) {
        char chunk[128];
        int len = 0;
        if (i > 0) {
            chunk[len++] = ',';
        }
        len += snprintf(chunk + len, (size_t)(sizeof(chunk) - len),
                        "{\"pc\":\"0x%06X\",\"samples\":%llu,\"cycles\":%llu}",
                        hits[i].pc & 0x00ffffffu,
                        (unsigned long long)hits[i].samples,
                        (unsigned long long)hits[i].cycles);
        if (len <= 0) break;
        send_buf(chunk, (size_t)len);
    }
    send_buf("]}\n", 3);
    free(hits);
}

static void handle_line(const char *line){
    // Very naive JSON command parser
    if (strstr(line, "\"cmd\":\"profiler_start\"")) {
        int stream = 1;
        if (strstr(line, "\"stream\":false")) stream = 0;
        q_push((cmd_t){CMD_PROFILER_START, stream});
        return;
    }
    if (strstr(line, "\"cmd\":\"profiler_stop\"")) { log_geo_cmd("recv", line); q_push((cmd_t){CMD_PROFILER_STOP,0}); return; }
    if (strstr(line, "\"cmd\":\"profiler_state\"")) { q_push((cmd_t){CMD_PROFILER_STATE,0}); return; }
}

static void* srv_thread(void *arg){ (void)arg; s_run = 1; char buf[1024]; char line[1024]; size_t lpos=0;
    while (s_run) {
        if (s_client_fd < 0) {
            struct sockaddr_in caddr; socklen_t clen = sizeof(caddr);
            int cfd = accept(s_listen_fd, (struct sockaddr*)&caddr, &clen);
            if (cfd >= 0) { set_nonblock(cfd); s_client_fd = cfd; lpos=0; log_geo_cmd("status", "client connected"); }
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

void geo_ipc_apply_pending(void){
    cmd_t c; while (q_pop(&c)) {
        switch (c.k) {
            case CMD_PROFILER_START: {
                if (!geo_profiler_get_enabled()) {
                    geo_profiler_reset();
                    geo_profiler_set_enabled(1);
                }
                s_streaming = c.v ? 1 : 0;
                geo_profiler_stream_enable(s_streaming);
                send_cmd_response("profiler_start", "enabled");
                break;
            }
                break;
            case CMD_PROFILER_STOP:
                geo_profiler_set_enabled(0);
                s_streaming = 0;
                geo_profiler_stream_enable(0);
                send_cmd_response("profiler_stop", "disabled");
                break;
            case CMD_PROFILER_STATE: {
                const char *state = geo_profiler_get_enabled() ? "enabled" : "disabled";
                send_cmd_response("profiler_state", state);
                break;
            }
            default: break;
        }
    }
    send_profiler_stream_frame();
}
