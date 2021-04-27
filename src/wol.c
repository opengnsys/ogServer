/*
 * Copyright (C) 2020 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, version 3.
 */
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "wol.h"
#include "rest.h"
#include "cfg.h"
#include "ogAdmServer.h"

int wol_socket_open(void)
{
	unsigned int on = 1;
	int ret, s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		syslog(LOG_ERR, "cannot create socket for magic packet\n");
		return -1;
	}
	ret = setsockopt(s, SOL_SOCKET, SO_BROADCAST, (unsigned int *) &on,
			 sizeof(on));
	if (ret < 0) {
		syslog(LOG_ERR, "cannot set broadcast socket\n");
		return -1;
	}

	return s;
}

bool wake_up_send(int sd, struct sockaddr_in *client,
		  const struct wol_msg *msg, const struct in_addr *addr)
{
	int ret;

	client->sin_addr.s_addr = addr->s_addr;

	ret = sendto(sd, msg, sizeof(*msg), 0,
		     (struct sockaddr *)client, sizeof(*client));
	if (ret < 0) {
		syslog(LOG_ERR, "failed to send wol\n");
		return false;
	}

	return true;
}

bool wake_up_broadcast(int sd, struct sockaddr_in *client,
		       const struct wol_msg *msg)
{
	struct sockaddr_in *broadcast_addr, addr = {};
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) < 0) {
		syslog(LOG_ERR, "cannot get list of addresses\n");
		return false;
	}

	addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_INET ||
		    strcmp(ifa->ifa_name, ogconfig.wol.interface) != 0)
			continue;

		broadcast_addr =
			(struct sockaddr_in *)ifa->ifa_ifu.ifu_broadaddr;
		addr.sin_addr.s_addr = broadcast_addr->sin_addr.s_addr;
		break;
	}
	freeifaddrs(ifaddr);

	return wake_up_send(sd, client, msg, &addr.sin_addr);
}

#define OG_WOL_CLIENT_TIMEOUT	60

static void og_client_wol_timer_cb(struct ev_loop *loop, ev_timer *timer,
                                   int events)
{
	struct og_client_wol *cli_wol;

	cli_wol = container_of(timer, struct og_client_wol, timer);

	syslog(LOG_ERR, "timeout WakeOnLAN request for client %s\n",
	       inet_ntoa(cli_wol->addr));
	list_del(&cli_wol->list);
	free(cli_wol);
}

struct og_client_wol *og_client_wol_create(const struct in_addr *addr)
{
	struct og_client_wol *cli_wol;

	cli_wol = calloc(1, sizeof(struct og_client_wol));
	if (!cli_wol)
		return NULL;

	cli_wol->addr = *addr;

	ev_timer_init(&cli_wol->timer, og_client_wol_timer_cb,
		      OG_WOL_CLIENT_TIMEOUT, 0.);
	ev_timer_start(og_loop, &cli_wol->timer);

	return cli_wol;
}

void og_client_wol_refresh(struct og_client_wol *cli_wol)
{
	ev_timer_again(og_loop, &cli_wol->timer);
}

void og_client_wol_destroy(struct og_client_wol *cli_wol)
{
	ev_timer_stop(og_loop, &cli_wol->timer);
	list_del(&cli_wol->list);
	free(cli_wol);
}

const char *og_client_wol_status(const struct og_client_wol *wol)
{
	return "WOL_SENT";
}
