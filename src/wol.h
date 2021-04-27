#ifndef _OG_WOL_H_
#define _OG_WOL_H_

#define OG_WOL_SEQUENCE		6
#define OG_WOL_MACADDR_LEN	6
#define OG_WOL_REPEAT		16

#include "list.h"
#include <ev.h>
#include <stdbool.h>

struct wol_msg {
	char secuencia_FF[OG_WOL_SEQUENCE];
	char macbin[OG_WOL_REPEAT][OG_WOL_MACADDR_LEN];
};

int wol_socket_open(void);
bool wake_up_send(int sd, struct sockaddr_in *client,
		  const struct wol_msg *msg, const struct in_addr *addr);
bool wake_up_broadcast(int sd, struct sockaddr_in *client,
		       const struct wol_msg *msg);

struct og_client_wol {
	struct list_head	list;
	struct in_addr		addr;
	struct ev_timer		timer;
};

struct og_client_wol *og_client_wol_create(const struct in_addr *addr);
struct og_client_wol *og_client_wol_find(const struct in_addr *addr);
void og_client_wol_refresh(struct og_client_wol *cli_wol);
void og_client_wol_destroy(struct og_client_wol *cli_wol);
const char *og_client_wol_status(const struct og_client_wol *wol);

#endif
