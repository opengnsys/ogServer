#ifndef _OG_WOL_H_
#define _OG_WOL_H_

#define OG_WOL_SEQUENCE		6
#define OG_WOL_MACADDR_LEN	6
#define OG_WOL_REPEAT		16

#include <stdbool.h>

struct wol_msg {
	char secuencia_FF[OG_WOL_SEQUENCE];
	char macbin[OG_WOL_REPEAT][OG_WOL_MACADDR_LEN];
};

bool wake_up_send(int sd, struct sockaddr_in *client,
		  const struct wol_msg *msg, const struct in_addr *addr);
bool wake_up_broadcast(int sd, struct sockaddr_in *client,
		       const struct wol_msg *msg);

#endif
