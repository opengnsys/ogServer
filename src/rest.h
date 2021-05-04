#ifndef OG_REST_H
#define OG_REST_H

#include <ev.h>

extern struct ev_loop *og_loop;

enum og_client_state {
	OG_CLIENT_RECEIVING_HEADER	= 0,
	OG_CLIENT_RECEIVING_PAYLOAD,
	OG_CLIENT_PROCESSING_REQUEST,
};

enum og_client_status {
	OG_CLIENT_STATUS_OGLIVE,
	OG_CLIENT_STATUS_BUSY,
	OG_CLIENT_STATUS_VIRTUAL,
};

enum og_cmd_type {
	OG_CMD_UNSPEC,
	OG_CMD_WOL,
	OG_CMD_PROBE,
	OG_CMD_SHELL_RUN,
	OG_CMD_SESSION,
	OG_CMD_POWEROFF,
	OG_CMD_REFRESH,
	OG_CMD_REBOOT,
	OG_CMD_STOP,
	OG_CMD_HARDWARE,
	OG_CMD_SOFTWARE,
	OG_CMD_IMAGE_CREATE,
	OG_CMD_IMAGE_RESTORE,
	OG_CMD_SETUP,
	OG_CMD_RUN_SCHEDULE,
	OG_CMD_IMAGES,
	OG_CMD_MAX
};

#define OG_MSG_REQUEST_MAXLEN	131072

struct og_client {
	struct list_head	list;
	struct ev_io		io;
	struct ev_timer		timer;
	struct sockaddr_in	addr;
	enum og_client_state	state;
	char			buf[OG_MSG_REQUEST_MAXLEN];
	unsigned int		buf_len;
	unsigned int		msg_len;
	bool			agent;
	int			content_length;
	char			auth_token[64];
	enum og_client_status	status;
	enum og_cmd_type	last_cmd;
	unsigned int		last_cmd_id;
	bool			autorun;
};

void og_client_add(struct og_client *cli);

static inline int og_client_socket(const struct og_client *cli)
{
	return cli->io.fd;
}

#include "json.h"

int og_client_state_process_payload_rest(struct og_client *cli);

enum og_rest_method {
	OG_METHOD_GET	= 0,
	OG_METHOD_POST,
	OG_METHOD_NO_HTTP
};

int og_send_request(enum og_rest_method method, enum og_cmd_type type,
		    const struct og_msg_params *params,
		    const json_t *data);

struct og_cmd {
	uint32_t		id;
	struct list_head	list;
	uint32_t		client_id;
	const char		*ip;
	const char		*mac;
	enum og_cmd_type	type;
	enum og_rest_method	method;
	struct og_msg_params	params;
	json_t			*json;
};

const struct og_cmd *og_cmd_find(const char *client_ip);
void og_cmd_free(const struct og_cmd *cmd);

#endif
