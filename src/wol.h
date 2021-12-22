#ifndef _OG_WOL_H_
#define _OG_WOL_H_

#define OG_WOL_SEQUENCE		6
#define OG_WOL_MACADDR_LEN	6
#define OG_WOL_REPEAT		16
#define OG_WOL_PORT		9

#include "list.h"
#include <ev.h>
#include <stdbool.h>

struct wol_msg {
	char wol_sequence_ff[OG_WOL_SEQUENCE];
	char mac_addr[OG_WOL_REPEAT][OG_WOL_MACADDR_LEN];
};

int wol_socket_open(void);
int wake_up(int s, const struct in_addr *addr, const struct in_addr *netmask,
	    const char *mac, uint32_t wol_delivery_type);

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
