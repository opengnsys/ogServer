/*
 * Copyright (C) 2020 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, version 3.
 */

#include "ogAdmServer.h"
#include "dbi.h"
#include "utils.h"
#include "list.h"
#include "rest.h"
#include "client.h"
#include "json.h"
#include "schedule.h"
#include "core.h"
#include "cfg.h"
#include <syslog.h>
#include <getopt.h>

static struct option og_server_opts[] = {
	{ "config-file", 1, 0, 'f' },
	{ NULL },
};

#define OG_SERVER_CFG_JSON	"/opt/opengnsys/cfg/ogserver.json"

struct og_server_cfg cfg;

int main(int argc, char *argv[])
{
	char config_file[PATH_MAX + 1] = OG_SERVER_CFG_JSON;
	struct ev_io ev_io_server_rest, ev_io_agent_rest;
	int val;

	og_loop = ev_default_loop(0);

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		exit(EXIT_FAILURE);

	openlog("ogserver", LOG_PID, LOG_DAEMON);

	while (1) {
		val = getopt_long(argc, argv, "f:l:d:", og_server_opts, NULL);
		if (val < 0)
			break;

		switch (val) {
		case 'f':
			snprintf(config_file, sizeof(config_file), "%s", optarg);
			break;
		case 'l':
		case 'd':
			/* ignore, legacy options */
			break;
		case '?':
			return EXIT_FAILURE;
		default:
			break;
		}
	}

	if (parse_json_config(config_file, &cfg) < 0)
		return EXIT_FAILURE;

	from_json_to_legacy(&cfg);

	socket_rest = og_socket_server_init(cfg.rest.port);
	if (socket_rest < 0) {
		syslog(LOG_ERR, "Cannot open REST API server socket\n");
		exit(EXIT_FAILURE);
	}

	ev_io_init(&ev_io_server_rest, og_server_accept_cb, socket_rest, EV_READ);
	ev_io_start(og_loop, &ev_io_server_rest);

	socket_agent_rest = og_socket_server_init("8889");
	if (socket_agent_rest < 0) {
		syslog(LOG_ERR, "Cannot open ogClient server socket\n");
		exit(EXIT_FAILURE);
	}

	ev_io_init(&ev_io_agent_rest, og_server_accept_cb, socket_agent_rest, EV_READ);
	ev_io_start(og_loop, &ev_io_agent_rest);

	if (og_dbi_schedule_get() < 0) {
		syslog(LOG_ERR, "Cannot connect to database\n");
		exit(EXIT_FAILURE);
	}

	og_schedule_next(og_loop);

	syslog(LOG_INFO, "Waiting for connections\n");

	while (1)
		ev_loop(og_loop, 0);

	exit(EXIT_SUCCESS);
}
