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
#include "wol.h"
#include "client.h"
#include "json.h"
#include "schedule.h"
#include <syslog.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <jansson.h>
#include <time.h>

static void og_client_release(struct ev_loop *loop, struct og_client *cli)
{
	list_del(&cli->list);
	ev_io_stop(loop, &cli->io);
	close(cli->io.fd);
	free(cli);
}

static int og_client_payload_too_large(struct og_client *cli)
{
	char buf[] = "HTTP/1.1 413 Payload Too Large\r\n"
		     "Content-Length: 0\r\n\r\n";

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return -1;
}

static int og_client_state_recv_hdr_rest(struct og_client *cli)
{
	char *ptr;

	ptr = strstr(cli->buf, "\r\n\r\n");
	if (!ptr)
		return 0;

	cli->msg_len = ptr - cli->buf + 4;

	ptr = strstr(cli->buf, "Content-Length: ");
	if (ptr) {
		sscanf(ptr, "Content-Length: %i[^\r\n]", &cli->content_length);
		if (cli->content_length < 0)
			return -1;
		cli->msg_len += cli->content_length;
	}

	ptr = strstr(cli->buf, "Authorization: ");
	if (ptr)
		sscanf(ptr, "Authorization: %63[^\r\n]", cli->auth_token);

	return 1;
}

static int og_client_recv(struct og_client *cli, int events)
{
	struct ev_io *io = &cli->io;
	int ret;

	if (events & EV_ERROR) {
		syslog(LOG_ERR, "unexpected error event from client %s:%hu\n",
			       inet_ntoa(cli->addr.sin_addr),
			       ntohs(cli->addr.sin_port));
		return 0;
	}

	ret = recv(io->fd, cli->buf + cli->buf_len,
		   sizeof(cli->buf) - cli->buf_len, 0);
	if (ret <= 0) {
		if (ret < 0) {
			syslog(LOG_ERR, "error reading from client %s:%hu (%s)\n",
			       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port),
			       strerror(errno));
		}
		return ret;
	}

	return ret;
}

static void og_client_read_cb(struct ev_loop *loop, struct ev_io *io, int events)
{
	struct og_client *cli;
	int ret;

	cli = container_of(io, struct og_client, io);

	ret = og_client_recv(cli, events);
	if (ret <= 0)
		goto close;

	ev_timer_again(loop, &cli->timer);

	cli->buf_len += ret;
	if (cli->buf_len >= sizeof(cli->buf)) {
		syslog(LOG_ERR, "client request from %s:%hu is too long\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		og_client_payload_too_large(cli);
		goto close;
	}

	switch (cli->state) {
	case OG_CLIENT_RECEIVING_HEADER:
		ret = og_client_state_recv_hdr_rest(cli);
		if (ret < 0)
			goto close;
		if (!ret)
			return;

		cli->state = OG_CLIENT_RECEIVING_PAYLOAD;
		/* Fall through. */
	case OG_CLIENT_RECEIVING_PAYLOAD:
		/* Still not enough data to process request. */
		if (cli->buf_len < cli->msg_len)
			return;

		cli->state = OG_CLIENT_PROCESSING_REQUEST;
		/* fall through. */
	case OG_CLIENT_PROCESSING_REQUEST:
		ret = og_client_state_process_payload_rest(cli);
		if (ret < 0) {
			syslog(LOG_ERR, "Failed to process HTTP request from %s:%hu\n",
			       inet_ntoa(cli->addr.sin_addr),
			       ntohs(cli->addr.sin_port));
		}
		goto close;
	default:
		syslog(LOG_ERR, "unknown state, critical internal error\n");
		goto close;
	}
	return;
close:
	ev_timer_stop(loop, &cli->timer);
	og_client_release(loop, cli);
}

enum og_agent_state {
	OG_AGENT_RECEIVING_HEADER	= 0,
	OG_AGENT_RECEIVING_PAYLOAD,
	OG_AGENT_PROCESSING_RESPONSE,
};

static int og_agent_state_recv_hdr_rest(struct og_client *cli)
{
	char *ptr;

	ptr = strstr(cli->buf, "\r\n\r\n");
	if (!ptr)
		return 0;

	cli->msg_len = ptr - cli->buf + 4;

	ptr = strstr(cli->buf, "Content-Length: ");
	if (ptr) {
		sscanf(ptr, "Content-Length: %i[^\r\n]", &cli->content_length);
		if (cli->content_length < 0)
			return -1;
		cli->msg_len += cli->content_length;
	}

	return 1;
}

static void og_agent_reset_state(struct og_client *cli)
{
	cli->state = OG_AGENT_RECEIVING_HEADER;
	cli->buf_len = 0;
	cli->content_length = 0;
	memset(cli->buf, 0, sizeof(cli->buf));
}

static void og_agent_deliver_pending_cmd(struct og_client *cli)
{
	const struct og_cmd *cmd;

	cmd = og_cmd_find(inet_ntoa(cli->addr.sin_addr));
	if (!cmd)
		return;

	og_send_request(cmd->method, cmd->type, &cmd->params, cmd->json);
	cli->last_cmd_id = cmd->id;

	og_cmd_free(cmd);
}

static void og_agent_read_cb(struct ev_loop *loop, struct ev_io *io, int events)
{
	struct og_client *cli;
	int ret;

	cli = container_of(io, struct og_client, io);

	ret = og_client_recv(cli, events);
	if (ret <= 0)
		goto close;

	ev_timer_again(loop, &cli->timer);

	cli->buf_len += ret;
	if (cli->buf_len >= sizeof(cli->buf)) {
		syslog(LOG_ERR, "client request from %s:%hu is too long\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		goto close;
	}

	switch (cli->state) {
	case OG_AGENT_RECEIVING_HEADER:
		ret = og_agent_state_recv_hdr_rest(cli);
		if (ret < 0)
			goto close;
		if (!ret)
			return;

		cli->state = OG_AGENT_RECEIVING_PAYLOAD;
		/* Fall through. */
	case OG_AGENT_RECEIVING_PAYLOAD:
		/* Still not enough data to process request. */
		if (cli->buf_len < cli->msg_len)
			return;

		cli->state = OG_AGENT_PROCESSING_RESPONSE;
		/* fall through. */
	case OG_AGENT_PROCESSING_RESPONSE:
		ret = og_agent_state_process_response(cli);
		if (ret < 0) {
			syslog(LOG_ERR, "Failed to process HTTP request from %s:%hu\n",
			       inet_ntoa(cli->addr.sin_addr),
			       ntohs(cli->addr.sin_port));
			goto close;
		} else if (ret == 0) {
			og_agent_deliver_pending_cmd(cli);
		}

		og_agent_reset_state(cli);
		break;
	default:
		syslog(LOG_ERR, "unknown state, critical internal error\n");
		goto close;
	}
	return;
close:
	ev_timer_stop(loop, &cli->timer);
	og_client_release(loop, cli);
}

static void og_client_timer_cb(struct ev_loop *loop, ev_timer *timer, int events)
{
	struct og_client *cli;

	cli = container_of(timer, struct og_client, timer);
	if (cli->agent) {
		ev_timer_again(loop, &cli->timer);
		return;
	}
	syslog(LOG_ERR, "timeout request for client %s:%hu\n",
	       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));

	og_client_release(loop, cli);
}

static void og_agent_send_refresh(struct og_client *cli)
{
	struct og_msg_params params;
	int err;

	params.ips_array[0] = inet_ntoa(cli->addr.sin_addr);
	params.ips_array_len = 1;

	err = og_send_request(OG_METHOD_GET, OG_CMD_REFRESH, &params, NULL);
	if (err < 0) {
		syslog(LOG_ERR, "Can't send refresh to: %s\n",
		       params.ips_array[0]);
	} else {
		syslog(LOG_INFO, "Sent refresh to: %s\n",
		       params.ips_array[0]);
	}
}

/* Shut down connection if there is no complete message after 10 seconds. */
#define OG_CLIENT_TIMEOUT       10

/* Agent client operation might take longer, shut down after 30 seconds. */
#define OG_AGENT_CLIENT_TIMEOUT 30

#define OG_TCP_KEEPALIVE_IDLE	60
#define OG_TCP_KEEPALIVE_INTL	30
#define OG_TCP_KEEPALIVE_CNT	4

int socket_rest, socket_agent_rest;

void og_server_accept_cb(struct ev_loop *loop, struct ev_io *io, int events)
{
	int intl = OG_TCP_KEEPALIVE_INTL, cnt = OG_TCP_KEEPALIVE_CNT;
	int on = 1, idle = OG_TCP_KEEPALIVE_IDLE;
	struct sockaddr_in client_addr;
	socklen_t addrlen = sizeof(client_addr);
	struct og_client_wol *cli_wol;
	struct og_client *cli;
	int client_sd;

	if (events & EV_ERROR)
		return;

	client_sd = accept(io->fd, (struct sockaddr *)&client_addr, &addrlen);
	if (client_sd < 0) {
		syslog(LOG_ERR, "cannot accept client connection\n");
		return;
	}

	setsockopt(client_sd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(int));
	setsockopt(client_sd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));
	setsockopt(client_sd, IPPROTO_TCP, TCP_KEEPINTVL, &intl, sizeof(int));
	setsockopt(client_sd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(int));

	cli_wol = og_client_wol_find(&client_addr.sin_addr);
	if (cli_wol)
		og_client_wol_destroy(cli_wol);

	cli = (struct og_client *)calloc(1, sizeof(struct og_client));
	if (!cli) {
		close(client_sd);
		return;
	}
	memcpy(&cli->addr, &client_addr, sizeof(client_addr));

	if (io->fd == socket_agent_rest) {
		cli->agent = true;
		ev_io_init(&cli->io, og_agent_read_cb, client_sd, EV_READ);
	} else {
		ev_io_init(&cli->io, og_client_read_cb, client_sd, EV_READ);
	}

	ev_io_start(loop, &cli->io);
	if (io->fd == socket_agent_rest) {
		ev_timer_init(&cli->timer, og_client_timer_cb,
			      OG_AGENT_CLIENT_TIMEOUT, 0.);
	} else {
		ev_timer_init(&cli->timer, og_client_timer_cb,
			      OG_CLIENT_TIMEOUT, 0.);
	}
	ev_timer_start(loop, &cli->timer);
	og_client_add(cli);

	if (io->fd == socket_agent_rest) {
		og_agent_send_refresh(cli);
	}
}

int og_socket_server_init(const char *port)
{
	struct sockaddr_in local;
	int sd, on = 1;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd < 0) {
		syslog(LOG_ERR, "cannot create main socket\n");
		return -1;
	}
	setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int));

	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_family = AF_INET;
	local.sin_port = htons(atoi(port));

	if (bind(sd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		close(sd);
		syslog(LOG_ERR, "cannot bind socket\n");
		return -1;
	}

	listen(sd, 250);

	return sd;
}
