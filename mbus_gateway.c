#include <stdlib.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "mbus_i.h"


LIST_HEAD(peer_list, peer);
LIST_HEAD(xlate_state_list, xlate_state);

typedef struct xlate_state {
  struct peer *xs_peer;
  LIST_ENTRY(xlate_state) xs_peer_link;

  LIST_ENTRY(xlate_state) xs_gateway_link;

  int64_t xs_deadline;
  uint8_t xs_bus_id;
  uint8_t xs_peer_id;

  uint8_t xs_addr;

} xlate_state_t;



typedef struct mbus_gateway {
  struct peer_list g_peers;
  mbus_t *g_mbus;

  struct xlate_state_list g_rpc_states;
  struct xlate_state_list g_pcs_states;

  int g_port;

} gateway_t;



typedef struct peer {
  LIST_ENTRY(peer) p_link;
  int p_fd;
  gateway_t *p_gw;
  struct xlate_state_list p_rpc_states;
  struct xlate_state_list p_pcs_states;

} peer_t;


static void
xlate_state_destroy(xlate_state_t *xs)
{
  LIST_REMOVE(xs, xs_gateway_link);
  LIST_REMOVE(xs, xs_peer_link);
  free(xs);
}



static void
peer_process_packet(peer_t *p, const uint8_t *pkt, size_t len)
{
  gateway_t *g = p->p_gw;
  mbus_t *m = g->g_mbus;

  xlate_state_t *xs;

  if(len < 2)
    return;

  uint8_t bus_addr = pkt[0] & 0xf;

  if(pkt[1] & 0x80) {
    // PCS
    const uint8_t flowid = pkt[3];
    if(pkt[2] & 1) {
      // SYN -> Create state

      LIST_FOREACH(xs, &g->g_pcs_states, xs_gateway_link) {
        if(xs->xs_addr == bus_addr && xs->xs_bus_id == flowid) {
          // Flow already exist, drop
          return;
        }
      }
      xs = calloc(1, sizeof(xlate_state_t));
      printf("* GW: New PCS state target:%d flow:%x\n", bus_addr, flowid);
      xs->xs_peer = p;
      xs->xs_addr = bus_addr;
      xs->xs_bus_id = flowid;
      xs->xs_deadline = mbus_get_ts() + 5000000;
      LIST_INSERT_HEAD(&p->p_pcs_states, xs, xs_peer_link);
      LIST_INSERT_HEAD(&g->g_pcs_states, xs, xs_gateway_link);

      m->m_send(m, xs->xs_addr, pkt + 1, len - 1, NULL);
      return;
    } else {

      LIST_FOREACH(xs, &p->p_pcs_states, xs_peer_link) {
        if(xs->xs_addr == bus_addr && xs->xs_bus_id == flowid) {
          xs->xs_deadline = mbus_get_ts() + 5000000;
          m->m_send(m, xs->xs_addr, pkt + 1, len - 1, NULL);
          return;
        }
      }
    }
    return;
  }

  uint8_t opcode = pkt[1] & 0x0f;

  if(opcode == MBUS_OP_RPC_RESOLVE ||
     opcode == MBUS_OP_RPC_INVOKE) {
    // rewrite txid

    if(len < 3)
      return;

    uint8_t rewrite[len];
    xs = calloc(1, sizeof(xlate_state_t));

    xs->xs_peer = p;
    xs->xs_addr = bus_addr;

    LIST_INSERT_HEAD(&p->p_rpc_states, xs, xs_peer_link);
    LIST_INSERT_HEAD(&g->g_rpc_states, xs, xs_gateway_link);

    xs->xs_deadline = mbus_get_ts() + 5000000;

    xs->xs_bus_id = ++m->m_txid_gen[xs->xs_addr & 0xf];
    xs->xs_peer_id = pkt[2];
    memcpy(rewrite, pkt, len);
    rewrite[2] = xs->xs_bus_id;
    m->m_send(m, xs->xs_addr, rewrite + 1, len - 1, NULL);
  } else if(opcode == MBUS_OP_DSIG_EMIT) {
    m->m_send(m, bus_addr, pkt + 1, len - 1, NULL);
  }

}


static void *
peer_thread(void *arg)
{
  peer_t *p = arg;
  gateway_t *g = p->p_gw;
  mbus_t *m = g->g_mbus;

  uint8_t plen;
  uint8_t pkt[256];

  while(1) {
    if(read(p->p_fd, &plen, 1) != 1)
      break;

    if(read(p->p_fd, pkt, plen) != plen)
      break;

    pthread_mutex_lock(&m->m_mutex);
    peer_process_packet(p, pkt, plen);
    pthread_mutex_unlock(&m->m_mutex);
  }

  printf("* GW: Peer disconnected\n");

  pthread_mutex_lock(&m->m_mutex);

  xlate_state_t *xs;

  while((xs = LIST_FIRST(&p->p_rpc_states)) != NULL) {
    xlate_state_destroy(xs);
  }

  while((xs = LIST_FIRST(&p->p_pcs_states)) != NULL) {
    xlate_state_destroy(xs);
  }

  LIST_REMOVE(p, p_link);
  pthread_mutex_unlock(&m->m_mutex);
  close(p->p_fd);
  free(p);
  return NULL;
}


static void
expire_list(struct xlate_state_list *xsl, int64_t now)
{
  xlate_state_t *xs, *xs_n;

  for(xs = LIST_FIRST(xsl); xs != NULL; xs = xs_n) {
    xs_n = LIST_NEXT(xs, xs_gateway_link);
    if(now > xs->xs_deadline) {
      xlate_state_destroy(xs);
    }
  }
}


static void *
janitor(void *arg)
{
  gateway_t *g = arg;

  while(1) {
    sleep(1);
    int64_t now = mbus_get_ts();
    expire_list(&g->g_rpc_states, now);
    expire_list(&g->g_pcs_states, now);
  }

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

  pthread_create(&tid, &attr, janitor, g);

  while(1) {
    struct sockaddr_in remote;
    socklen_t slen = sizeof(remote);

    int pfd = accept(lfd, (struct sockaddr *)&remote, &slen);
    if(pfd == -1) {
      return MBUS_ERR_OPERATION_FAILED;
    }
    peer_t *p = calloc(1, sizeof(peer_t));

    printf("* GW: New peer connected\n");

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



static void
send_to_peer(peer_t *p, const uint8_t *pkt, size_t len)
{
  uint8_t out[len + 1];
  out[0] = len;
  memcpy(out + 1, pkt, len);
  if(write(p->p_fd, out, len + 1) != len + 1) {}
}



int
mbus_gateway_intercept(mbus_t *m, const uint8_t *pkt, size_t len)
{
  xlate_state_t *xs;
  gateway_t *g = m->m_gateway;

  if(len < 3)
    return 0;

  const uint8_t src_addr = (pkt[0] >> 4) & 0x0f;


  if(pkt[1] & 0x80) {
    // PCS
    const uint8_t flowid = pkt[3];

    LIST_FOREACH(xs, &g->g_pcs_states, xs_gateway_link) {
      if(xs->xs_addr == src_addr && xs->xs_bus_id == flowid) {
        send_to_peer(xs->xs_peer, pkt, len);
        return 1;
      }
    }
    return 0;
  }

  const uint8_t opcode = pkt[1] & 0x0f;
  if(opcode == MBUS_OP_DSIG_EMIT) {
    peer_t *p;
    LIST_FOREACH(p, &g->g_peers, p_link) {
      send_to_peer(p, pkt, len);
    }
    return 0;
  }

  if(opcode == MBUS_OP_RPC_RESOLVE_REPLY ||
     opcode == MBUS_OP_RPC_REPLY ||
     opcode == MBUS_OP_RPC_ERR) {

    LIST_FOREACH(xs, &g->g_rpc_states, xs_gateway_link) {
      if(xs->xs_bus_id == pkt[2] && src_addr == xs->xs_addr) {
        peer_t *p = xs->xs_peer;
        uint8_t out[len + 1];
        memcpy(out + 1, pkt, len);
        out[3] = xs->xs_peer_id;
        out[0] = len;

        xlate_state_destroy(xs);

        if(write(p->p_fd, out, len + 1) != len + 1) {}
        return 1;
      }
    }
  }
  return 0;
}
