#include <stdlib.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "mbus_i.h"


#define FLOW_EXPIRE 3000000 // µs

LIST_HEAD(peer_list, peer);

LIST_HEAD(mbus_gateway_flow_list, mbus_gateway_flow);


typedef struct mbus_gateway_flow {
  mbus_flow_t mgf_flow;

  uint16_t mgf_peer_flow;
  uint8_t mgf_peer_addr;
  uint8_t mgf_type;
  struct peer *mgf_peer;

  LIST_ENTRY(mbus_gateway_flow) mgf_peer_link;

  mbus_timer_t mgf_timer;

} mbus_gateway_flow_t;


typedef struct mbus_gateway {
  struct peer_list g_peers;
  mbus_t *g_mbus;
  int g_port;
} gateway_t;


typedef struct peer {
  LIST_ENTRY(peer) p_link;
  int p_fd;
  gateway_t *p_gw;
  struct mbus_gateway_flow_list p_flows;
  mbus_con_t *p_mc;
} peer_t;


static void
send_to_peer(peer_t *p, const uint8_t *pkt, size_t len)
{
  uint8_t out[len + 1];
  out[0] = len;
  memcpy(out + 1, pkt, len);
  if(write(p->p_fd, out, len + 1) != len + 1) {}
}

mbus_gateway_flow_t *
peer_find_flow(peer_t *p, uint8_t peer_addr,
               uint8_t remote_addr, uint16_t flow_id)
{
  mbus_gateway_flow_t *mgf;
  LIST_FOREACH(mgf, &p->p_flows, mgf_peer_link) {
    if(remote_addr == mgf->mgf_flow.mf_remote_addr &&
       peer_addr == mgf->mgf_peer_addr &&
       flow_id == mgf->mgf_peer_flow)
      return mgf;
  }
  return NULL;
}


static void
mgf_send_close_to_bus(mbus_t *m, mbus_gateway_flow_t *mgf)
{
  uint8_t pkt[4];
  mbus_flow_write_header(pkt, m, &mgf->mgf_flow, 0);
  pkt[3] = 0x80; // Close
  m->m_send(m, pkt, 4, NULL);
}

static void
mgf_send_close_to_peer(mbus_gateway_flow_t *mgf)
{
  uint8_t pkt[4];
  const uint16_t flow = mgf->mgf_peer_flow;
  pkt[0] = mgf->mgf_peer_addr;
  pkt[1] = ((flow >> 3) & 0x60) | mgf->mgf_flow.mf_remote_addr;
  pkt[2] = flow;
  pkt[3] = 0x80; // Close
  send_to_peer(mgf->mgf_peer, pkt, sizeof(pkt));
}

static void
mgf_destroy(mbus_t *m, mbus_gateway_flow_t *mgf, const char *reason)
{
  mbus_log(m, "GW: Destroyed flow bus:%d/%d peer:%d/%d %s",
           mgf->mgf_flow.mf_remote_addr,
           mgf->mgf_flow.mf_flow,
           mgf->mgf_peer_addr,
           mgf->mgf_peer_flow,
           reason);

  mbus_flow_remove(&mgf->mgf_flow);
  mbus_timer_disarm(&mgf->mgf_timer);
  LIST_REMOVE(mgf, mgf_peer_link);

  free(mgf);
}


static void
gateway_flow_input(struct mbus *m, struct mbus_flow *mf,
                   const uint8_t *pkt, size_t len)
{
  mbus_gateway_flow_t *mgf = (mbus_gateway_flow_t *)mf;
  uint8_t dup[3 + len];
  memcpy(dup + 3, pkt, len);

  const uint16_t flow = mgf->mgf_peer_flow;
  dup[0] = mgf->mgf_peer_addr;
  dup[1] = ((flow >> 3) & 0x60) | mgf->mgf_flow.mf_remote_addr;
  dup[2] = flow;

  send_to_peer(mgf->mgf_peer, dup, 3 + len);

  if(mgf->mgf_timer.mt_cb)
    mbus_timer_arm(m, &mgf->mgf_timer, mbus_get_ts() + FLOW_EXPIRE);
}




static void
gateway_flow_timeout(mbus_t *m, void *opaque, int64_t expire)
{
  mbus_gateway_flow_t *mgf = opaque;
  mgf_destroy(m, mgf, "timeout");
}


static void
peer_process_packet(peer_t *p, const uint8_t *pkt, size_t len)
{
  if(len < 2)
    return;

  gateway_t *g = p->p_gw;
  mbus_t *m = g->g_mbus;

  uint32_t dst_addr = pkt[0];
  if(dst_addr >= 32) {
    // Multicast
    m->m_send(m, pkt, len, NULL);
    return;
  }

  if(len < 3)
    return;

  const uint16_t flow = pkt[2] | ((pkt[1] << 3) & 0x300);
  const uint8_t src_addr = pkt[1] & 0x1f;
  const int init = pkt[1] & 0x80;

  mbus_gateway_flow_t *mgf = peer_find_flow(p, src_addr, dst_addr, flow);

  if(init) {
    if(mgf != NULL) {
      if(mgf->mgf_type == 3)
        mgf_send_close_to_bus(m, mgf);
      mgf_destroy(m, mgf, "reinit");
    }

    mgf = calloc(1, sizeof(mbus_gateway_flow_t));
    mgf->mgf_type = pkt[3];
    mgf->mgf_flow.mf_remote_addr = dst_addr;
    mgf->mgf_flow.mf_input = gateway_flow_input;
    mgf->mgf_peer_flow = flow;
    mgf->mgf_peer_addr = src_addr;
    mgf->mgf_peer = p;
    LIST_INSERT_HEAD(&p->p_flows, mgf, mgf_peer_link);
    mbus_flow_create(m, &mgf->mgf_flow);

    mgf->mgf_timer.mt_opaque = mgf;

    if(mgf->mgf_type != 3) // Guaranteed delivery -> no timeouts
      mgf->mgf_timer.mt_cb = gateway_flow_timeout;

    mbus_log(m, "GW: Created flow bus:%d/%d peer:%d/%d type:%d",
             mgf->mgf_flow.mf_remote_addr,
             mgf->mgf_flow.mf_flow,
             mgf->mgf_peer_addr,
             mgf->mgf_peer_flow,
             mgf->mgf_type);

  } else {
    if(mgf == NULL)
      return;
  }

  if(mgf->mgf_timer.mt_cb)
    mbus_timer_arm(m, &mgf->mgf_timer, mbus_get_ts() + FLOW_EXPIRE);

  uint8_t dup[len];
  memcpy(dup, pkt, len);
  mbus_flow_write_header(dup, m, &mgf->mgf_flow, init);
  m->m_send(m, dup, len, NULL);
}

static void
peer_raw_mode(peer_t *p)
{
  gateway_t *g = p->p_gw;
  mbus_t *m = g->g_mbus;

  uint8_t plen;
  uint8_t pkt[256];

  while(1) {
    if(recv(p->p_fd, &plen, 1, MSG_WAITALL) != 1)
      break;
    if(recv(p->p_fd, pkt, plen, MSG_WAITALL) != plen)
      break;
    pthread_mutex_lock(&m->m_mutex);
    peer_process_packet(p, pkt, plen);
    pthread_mutex_unlock(&m->m_mutex);
  }

  pthread_mutex_lock(&m->m_mutex);

  mbus_gateway_flow_t *mgf;

  while((mgf = LIST_FIRST(&p->p_flows)) != NULL) {
    if(mgf->mgf_type == 3)
      mgf_send_close_to_bus(m, mgf);
    mgf_destroy(m, mgf, "Peer disconnected");
  }

  pthread_mutex_unlock(&m->m_mutex);
}

static void *
peer_thread(void *arg)
{
  peer_t *p = arg;

  mbus_t *m = p->p_gw->g_mbus;
  uint8_t hdr = m->m_connect_flowtype;

  if(write(p->p_fd, &hdr, 1) == 1) {
    peer_raw_mode(p);
  }

  mbus_log(m, "GW: Peer disconnected");
  pthread_mutex_lock(&m->m_mutex);
  LIST_REMOVE(p, p_link);
  pthread_mutex_unlock(&m->m_mutex);
  close(p->p_fd);
  free(p);
  return NULL;
}

mbus_error_t
mbus_gateway0(gateway_t *g)
{
  struct sockaddr_in localaddr = {
    .sin_family = AF_INET,
    .sin_port = htons(g->g_port),
  };

  mbus_t *m = g->g_mbus;
  int lfd = socket(AF_INET, SOCK_STREAM, 0);

  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (const int[]){1}, sizeof(int));

  if(bind(lfd, (struct sockaddr *)&localaddr, sizeof(localaddr)) < 0) {
    perror("bind");
    return MBUS_ERR_OPERATION_FAILED;
  }

  listen(lfd, 100);


  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);


  while(1) {
    struct sockaddr_in remote;
    socklen_t slen = sizeof(remote);

    int pfd = accept(lfd, (struct sockaddr *)&remote, &slen);
    if(pfd == -1) {
      return MBUS_ERR_OPERATION_FAILED;
    }

    int smol = 2048;
    int r;

    r = setsockopt(pfd, SOL_SOCKET, SO_RCVBUF, &smol, sizeof(smol));
    if(r < 0)
      perror("SO_RCVBUF");
    r = setsockopt(pfd, SOL_SOCKET, SO_SNDBUF, &smol, sizeof(smol));
    if(r < 0)
      perror("SO_SNDBUF");

    int val = 1;
    setsockopt(pfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

    peer_t *p = calloc(1, sizeof(peer_t));

    mbus_log(m, "* GW: New peer connected");

    p->p_fd = pfd;
    p->p_gw = g;

    pthread_mutex_lock(&m->m_mutex);
    LIST_INSERT_HEAD(&g->g_peers, p, p_link);
    pthread_mutex_unlock(&m->m_mutex);

    pthread_create(&tid, &attr, peer_thread, p);
  }
  return 0;
}


static void *
gateway_thread(void *arg)
{
  mbus_gateway0(arg);
  return NULL;
}


mbus_error_t
mbus_gateway(mbus_t *m, int local_port, int background)
{
  gateway_t *g = calloc(1, sizeof(gateway_t));
  g->g_mbus = m;
  m->m_gateway = g;
  g->g_port = local_port;

  if(!background)
    return mbus_gateway0(g);

  pthread_t tid;
  pthread_create(&tid, NULL, gateway_thread, g);
  return 0;
}


void
mbus_gateway_recv_multicast(struct mbus *m, const uint8_t *pkt, size_t len)
{
  gateway_t *g = m->m_gateway;

  peer_t *p;
  LIST_FOREACH(p, &g->g_peers, p_link) {
    send_to_peer(p, pkt, len);
  }
}

void
mbus_gateway_disconnect(struct mbus *m)
{
  gateway_t *g = m->m_gateway;
  if(g == NULL)
    return;
  mbus_gateway_flow_t *mgf, *n;
  peer_t *p;
  LIST_FOREACH(p, &g->g_peers, p_link) {
    for(mgf = LIST_FIRST(&p->p_flows); mgf != NULL; mgf = n) {
      n = LIST_NEXT(mgf, mgf_peer_link);
      if(mgf->mgf_type == 3) {
        mgf_send_close_to_peer(mgf);
        mgf_destroy(m, mgf, "Primary connection lost");
      }
    }
  }
}
