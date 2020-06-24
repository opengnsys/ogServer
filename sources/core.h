#ifndef _OG_CORE_H
#define _OG_CORE_H

extern int socket_rest, socket_agent_rest;
extern struct ev_loop *og_loop;

int og_socket_server_init(const char *port);
void og_server_accept_cb(struct ev_loop *loop, struct ev_io *io, int events);

#endif
