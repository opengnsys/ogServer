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
#include "ogAdmServer.h"

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
		    strcmp(ifa->ifa_name, interface) != 0)
			continue;

		broadcast_addr =
			(struct sockaddr_in *)ifa->ifa_ifu.ifu_broadaddr;
		addr.sin_addr.s_addr = broadcast_addr->sin_addr.s_addr;
		break;
	}
	freeifaddrs(ifaddr);

	return wake_up_send(sd, client, msg, &addr.sin_addr);
}
