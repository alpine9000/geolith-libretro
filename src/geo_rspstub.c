#include "geo_rspstub.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef GEO_RSP_LOG
#define GEO_RSP_LOG 0
#endif

static int s_lfd=-1, s_cfd=-1;
static pthread_t s_thr;
static int s_run=0;
static volatile int s_running=0; // set on continue/step, cleared when we send S05
static int s_noack=0;
static geo_rspstub_ops_t s_ops;

static void logline(const char *pfx, const char *s){
#if GEO_RSP_LOG
  fprintf(stderr, "RSP %s%s\n", pfx?pfx:"", s?s:"");
#else
  (void)pfx; (void)s;
#endif
}

static int send_all(int fd, const void *buf, size_t n){
  const char* p=(const char*)buf; size_t off=0;
  while(off<n){ ssize_t w=send(fd,p+off,n-off,0); if(w>0){ off+=(size_t)w; continue;} if(w==0) return -1; if(errno==EAGAIN||errno==EWOULDBLOCK){ usleep(1000); continue;} return -1; }
  return 0;
}

static int send_packet(const char *payload){
  if (s_cfd<0) return -1;
  unsigned char csum=0; for(const char*p=payload;*p;++p) csum+=(unsigned char)*p;
  char hdr='$'; char tail[4]; snprintf(tail,sizeof(tail),"#%02x", csum);
  if(send_all(s_cfd,&hdr,1)<0) return -1;
  if(send_all(s_cfd,payload,strlen(payload))<0) return -1;
  if(send_all(s_cfd,tail,3)<0) return -1;
  logline("-> ", payload);
  return 0;
}

static int ci_starts(const char*s,const char*p){ size_t n=strlen(p); for(size_t i=0;i<n;i++){ char a=s[i],b=p[i]; if(!a) return 0; if(a>='A'&&a<='Z') a=(char)(a-'A'+'a'); if(b>='A'&&b<='Z') b=(char)(b-'A'+'a'); if(a!=b) return 0; } return 1; }
static int hex2int(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return 10+(c-'a'); if(c>='A'&&c<='F')return 10+(c-'A'); return -1; }
static void be32(char*out,uint32_t v){ static const char*hex="0123456789abcdef"; unsigned char b[4]; b[0]=v>>24; b[1]=v>>16; b[2]=v>>8; b[3]=v; for(int i=0;i<4;i++){ out[i*2]=hex[b[i]>>4]; out[i*2+1]=hex[b[i]&0xF]; } }

static int read_packet(char *out, size_t cap){
  if(s_cfd<0) return -1; char ch; int n=0;
  // wait for '$'
  for(;;){ ssize_t r=recv(s_cfd,&ch,1,0); if(r<=0) return -1; if(ch=='$') break; if(ch==0x03 && s_ops.request_break) s_ops.request_break(); }
  // payload
  for(;;){ ssize_t r=recv(s_cfd,&ch,1,0); if(r<=0) return -1; if(ch=='#') break; if(n<(int)cap-1){ out[n++]=ch; } }
  // checksum (ignore, always ack)
  char d[2]; for(int i=0;i<2;i++){ ssize_t r=recv(s_cfd,&d[i],1,0); if(r<=0) return -1; }
  if(!s_noack){ char ack='+'; send_all(s_cfd,&ack,1); }
  out[n]='\0'; logline("<- ", out); return n;
}

static void handle_cmd(const char *pkt){
  if(!pkt||!*pkt){ send_packet(""); return; }
  if(pkt[0]=='?'){ send_packet("S05"); return; }
  if(ci_starts(pkt,"qSupported")){ send_packet("PacketSize=4000;swbreak+;vContSupported+;QStartNoAckMode+"); return; }
  if(ci_starts(pkt,"vCont?")){ send_packet("vCont;c;s"); return; }
  if(ci_starts(pkt,"vCont;")){ char a=pkt[6]; if(a=='c'||a=='C'){ if(s_ops.resume_continue) s_ops.resume_continue(); s_running=1; return; } if(a=='s'||a=='S'){ if(s_ops.resume_step) s_ops.resume_step(); s_running=1; return; } send_packet(""); return; }
  if(ci_starts(pkt,"vMustReplyEmpty")){ send_packet(""); return; }
  if(ci_starts(pkt,"QStartNoAckMode")){ s_noack=1; send_packet("OK"); return; }
  if(ci_starts(pkt,"qAttached")){ send_packet("1"); return; }
  if(pkt[0]=='H'){ send_packet("OK"); return; }
  if(ci_starts(pkt,"qTStatus")){ send_packet(""); return; }
  if(ci_starts(pkt,"qC")){ send_packet("QC1"); return; }
  if(ci_starts(pkt,"qfThreadInfo")){ send_packet("m1"); return; }
  if(ci_starts(pkt,"qsThreadInfo")){ send_packet("l"); return; }

  // Target description (m68k core registers)
  if(ci_starts(pkt,"qXfer:features:read:")){
    static const char tdesc[] =
      "<?xml version=\"1.0\"?>\n"
      "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
      "<target>\n"
      "  <architecture>m68k</architecture>\n"
      "  <feature name=\"org.gnu.gdb.m68k.core\">\n"
      "    <reg name=\"d0\" bitsize=\"32\" type=\"uint32\" regnum=\"0\"/>\n"
      "    <reg name=\"d1\" bitsize=\"32\" type=\"uint32\" regnum=\"1\"/>\n"
      "    <reg name=\"d2\" bitsize=\"32\" type=\"uint32\" regnum=\"2\"/>\n"
      "    <reg name=\"d3\" bitsize=\"32\" type=\"uint32\" regnum=\"3\"/>\n"
      "    <reg name=\"d4\" bitsize=\"32\" type=\"uint32\" regnum=\"4\"/>\n"
      "    <reg name=\"d5\" bitsize=\"32\" type=\"uint32\" regnum=\"5\"/>\n"
      "    <reg name=\"d6\" bitsize=\"32\" type=\"uint32\" regnum=\"6\"/>\n"
      "    <reg name=\"d7\" bitsize=\"32\" type=\"uint32\" regnum=\"7\"/>\n"
      "    <reg name=\"a0\" bitsize=\"32\" type=\"data_ptr\" regnum=\"8\"/>\n"
      "    <reg name=\"a1\" bitsize=\"32\" type=\"data_ptr\" regnum=\"9\"/>\n"
      "    <reg name=\"a2\" bitsize=\"32\" type=\"data_ptr\" regnum=\"10\"/>\n"
      "    <reg name=\"a3\" bitsize=\"32\" type=\"data_ptr\" regnum=\"11\"/>\n"
      "    <reg name=\"a4\" bitsize=\"32\" type=\"data_ptr\" regnum=\"12\"/>\n"
      "    <reg name=\"a5\" bitsize=\"32\" type=\"data_ptr\" regnum=\"13\"/>\n"
      "    <reg name=\"a6\" bitsize=\"32\" type=\"data_ptr\" regnum=\"14\"/>\n"
      "    <reg name=\"a7\" bitsize=\"32\" type=\"data_ptr\" regnum=\"15\"/>\n"
      "    <reg name=\"sr\" bitsize=\"32\" type=\"uint32\" regnum=\"16\"/>\n"
      "    <reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\" regnum=\"17\"/>\n"
      "  </feature>\n"
      "</target>\n";
    const char *p = pkt + strlen("qXfer:features:read:");
    const char *colon = strchr(p, ':');
    if (!colon) { send_packet("E01"); return; }
    size_t objlen = (size_t)(colon - p);
    if (objlen != strlen("target.xml") || strncmp(p, "target.xml", objlen) != 0){ send_packet("E01"); return; }
    unsigned off=0,len=0; if (sscanf(colon+1, "%x,%x", &off, &len) != 2) { send_packet("E01"); return; }
    size_t tlen = strlen(tdesc);
    if (off > tlen) off = (unsigned)tlen;
    size_t remain = tlen - off;
    if (len > remain) len = (unsigned)remain;
    char *buf = (char*)malloc(len + 2);
    if (!buf) { send_packet("E01"); return; }
    buf[0] = ((off + len) >= tlen) ? 'l' : 'm';
    memcpy(buf+1, tdesc + off, len);
    buf[len+1] = '\0';
    send_packet(buf);
    free(buf);
    return;
  }

  if(pkt[0]=='g'){
    char buf[(16+2)*8+1]; int pos=0; char t[9]; t[8]='\0';
    for(int i=0;i<8;i++){ be32(t, s_ops.read_reg? s_ops.read_reg(i):0); memcpy(&buf[pos],t,8); pos+=8; }
    for(int i=0;i<8;i++){ be32(t, s_ops.read_reg? s_ops.read_reg(8+i):0); memcpy(&buf[pos],t,8); pos+=8; }
    { char x[9]; x[8]='\0'; be32(x, s_ops.read_reg? s_ops.read_reg(16):0); memcpy(&buf[pos],x,8); pos+=8; }
    { be32(t, s_ops.read_reg? s_ops.read_reg(17):0); memcpy(&buf[pos],t,8); pos+=8; }
    buf[pos]='\0'; send_packet(buf); return; }

  if(pkt[0]=='p'){ int idx=strtol(pkt+1,NULL,16); char t[9]; t[8]='\0'; be32(t, s_ops.read_reg? s_ops.read_reg(idx):0); send_packet(t); return; }

  if(pkt[0]=='P'){
    const char*e=strchr(pkt,'='); if(!e){ send_packet("E01"); return;}
    int idx=strtol(pkt+1,NULL,16); uint8_t b[4]={0};
    for(int i=0;i<8;i+=2){ int hi=hex2int(e[1+i]); int lo=hex2int(e[1+i+1]); if(hi<0||lo<0){ send_packet("E02"); return;} b[i/2]=(uint8_t)((hi<<4)|lo);} uint32_t v=(b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]; if(s_ops.write_reg) s_ops.write_reg(idx,v); send_packet("OK"); return; }

  if(pkt[0]=='m'){
    uint32_t a=0,l=0; if(sscanf(pkt+1, "%x,%x", &a,&l)!=2){ send_packet("E01"); return;} if(l>1024) l=1024; char out[2048+1]; int pos=0; for(uint32_t i=0;i<l;i++){ uint8_t v=0; if(s_ops.read_mem) s_ops.read_mem(a+i,&v,1); static const char*hex="0123456789abcdef"; out[pos++]=hex[(v>>4)&0xF]; out[pos++]=hex[v&0xF]; } out[pos]='\0'; send_packet(out); return; }

  if(pkt[0]=='M'){
    uint32_t a=0,l=0; if(sscanf(pkt+1, "%x,%x:", &a,&l)!=2){ send_packet("E01"); return;} const char *d=strchr(pkt,':'); if(!d){ send_packet("E01"); return;} d++; uint8_t b[1024]; if(l>sizeof(b)) l=sizeof(b); for(uint32_t i=0;i<l;i++){ int hi=hex2int(d[i*2]); int lo=hex2int(d[i*2+1]); if(hi<0||lo<0){ send_packet("E02"); return;} b[i]=(uint8_t)((hi<<4)|lo);} if(s_ops.write_mem) s_ops.write_mem(a,b,l); send_packet("OK"); return; }

  if(pkt[0]=='c'){ if(pkt[1]){ uint32_t a=0; sscanf(pkt+1, "%x", &a); if(s_ops.write_reg) s_ops.write_reg(17,a); } if(s_ops.resume_continue) s_ops.resume_continue(); s_running=1; return; }
  if(pkt[0]=='s'){ if(pkt[1]){ uint32_t a=0; sscanf(pkt+1, "%x", &a); if(s_ops.write_reg) s_ops.write_reg(17,a); } if(s_ops.resume_step) s_ops.resume_step(); s_running=1; return; }

  if(pkt[0]=='z' && ci_starts(pkt,"z0,")){ uint32_t a=0; unsigned k=0; sscanf(pkt+3, "%x,%u", &a, &k); if(s_ops.del_sw_break) s_ops.del_sw_break(a); send_packet("OK"); return; }
  if(pkt[0]=='Z' && ci_starts(pkt,"Z0,")){ uint32_t a=0; unsigned k=0; sscanf(pkt+3, "%x,%u", &a, &k); if(s_ops.add_sw_break) s_ops.add_sw_break(a); send_packet("OK"); return; }

  // Default empty reply
  send_packet("");
}

static void* thr(void*arg) {
  (void)arg;
  s_run = 1;
  for (;;) {
    if (!s_run) break;
    if (s_cfd < 0) {
      struct sockaddr_in c;
      socklen_t cl = sizeof(c);
      int cfd = accept(s_lfd, (struct sockaddr*)&c, &cl);
      if (cfd >= 0) {
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        s_cfd = cfd;
        s_noack = 0;
        logline("* ", "client connected");
        s_running = 0;
        if (s_ops.request_break) s_ops.request_break();
        send_packet("S05");
      } else {
        usleep(2000);
      }
      continue;
    }
    char pkt[4096];
    int n = read_packet(pkt, sizeof(pkt));
    if (n < 0) {
      if (s_cfd >= 0) {
        close(s_cfd);
        s_cfd = -1;
        logline("* ", "client disconnected");
        // Keep the core running when the debugger disconnects.
        if (s_ops.resume_continue) {
          s_ops.resume_continue();
        }
        s_running = 0;
      }
      continue;
    }
    handle_cmd(pkt);
  }
  if (s_cfd >= 0) {
    close(s_cfd);
    s_cfd = -1;
  }
  return NULL;
}

int geo_rspstub_start(int port, const geo_rspstub_ops_t *ops){
  if(s_run) return port;
  if(ops) s_ops=*ops;
  s_lfd=socket(AF_INET,SOCK_STREAM,0);
  if(s_lfd<0){ fprintf(stderr, "RSP: socket(AF_INET,SOCK_STREAM) failed: errno=%d (%s)\n", errno, strerror(errno)); return -1; }
  s_run = 1;
  int yes=1; int rso = setsockopt(s_lfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
  if (rso!=0) fprintf(stderr, "RSP: setsockopt(fd=%d,SO_REUSEADDR) ret=%d errno=%d (%s)\n", s_lfd, rso, errno, strerror(errno));
  struct sockaddr_in a; memset(&a,0,sizeof(a)); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons((uint16_t)port);
  if (bind(s_lfd,(struct sockaddr*)&a,sizeof(a))!=0){ fprintf(stderr, "RSP: bind(fd=%d, addr=127.0.0.1, port=%d) failed: errno=%d (%s)\n", s_lfd, port, errno, strerror(errno)); close(s_lfd); s_lfd=-1; s_run = 0; return -1; }
  if (listen(s_lfd,1)!=0){ fprintf(stderr, "RSP: listen(fd=%d,backlog=1) failed: errno=%d (%s)\n", s_lfd, errno, strerror(errno)); close(s_lfd); s_lfd=-1; s_run = 0; return -1; }
  fprintf(stderr, "RSP: listening 127.0.0.1:%d fd=%d\n", port, s_lfd);
  pthread_create(&s_thr,NULL,thr,NULL);
  return port;
}

void geo_rspstub_stop(void){
  int was_run = s_run; s_run = 0;
  if (s_lfd>=0){ close(s_lfd); s_lfd = -1; }
  if (s_cfd>=0){ shutdown(s_cfd, SHUT_RDWR); close(s_cfd); s_cfd = -1; }
  if (was_run) pthread_join(s_thr, NULL);
}

void geo_rspstub_poll(int paused){ if(s_cfd>=0 && paused && s_running){ send_packet("S05"); s_running=0; } }
