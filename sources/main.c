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
#include <syslog.h>

int main(int argc, char *argv[])
{
	struct ev_io ev_io_server_rest, ev_io_agent_rest;
	int i;

	og_loop = ev_default_loop(0);

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		exit(EXIT_FAILURE);

	openlog("ogAdmServer", LOG_PID, LOG_DAEMON);

	if (!validacionParametros(argc, argv, 1)) // Valida parámetros de ejecución
		exit(EXIT_FAILURE);

	if (!tomaConfiguracion(szPathFileCfg)) { // Toma parametros de configuracion
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < MAXIMOS_CLIENTES; i++) {
		tbsockets[i].ip[0] = '\0';
		tbsockets[i].cli = NULL;
	}

	socket_rest = og_socket_server_init("8888");
	if (socket_rest < 0)
		exit(EXIT_FAILURE);

	ev_io_init(&ev_io_server_rest, og_server_accept_cb, socket_rest, EV_READ);
	ev_io_start(og_loop, &ev_io_server_rest);

	socket_agent_rest = og_socket_server_init("8889");
	if (socket_agent_rest < 0)
		exit(EXIT_FAILURE);

	ev_io_init(&ev_io_agent_rest, og_server_accept_cb, socket_agent_rest, EV_READ);
	ev_io_start(og_loop, &ev_io_agent_rest);

	if (og_dbi_schedule_get() < 0)
		exit(EXIT_FAILURE);

	og_schedule_next(og_loop);

	syslog(LOG_INFO, "Waiting for connections\n");

	while (1)
		ev_loop(og_loop, 0);

	exit(EXIT_SUCCESS);
}
