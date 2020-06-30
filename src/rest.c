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
#include "cfg.h"
#include "schedule.h"
#include <ev.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <jansson.h>
#include <dirent.h>
#include <time.h>

struct ev_loop *og_loop;

static TRAMA *og_msg_alloc(char *data, unsigned int len)
{
	TRAMA *ptrTrama;

	ptrTrama = calloc(1, sizeof(TRAMA));
	if (!ptrTrama) {
		syslog(LOG_ERR, "OOM\n");
		return NULL;
	}

	initParametros(ptrTrama, len);
	memcpy(ptrTrama, "@JMMLCAMDJ_MCDJ", LONGITUD_CABECERATRAMA);
	memcpy(ptrTrama->parametros, data, len);
	ptrTrama->lonprm = len;

	return ptrTrama;
}

static void og_msg_free(TRAMA *ptrTrama)
{
	free(ptrTrama->parametros);
	free(ptrTrama);
}

static bool og_send_cmd(char *ips_array[], int ips_array_len,
			const char *state, TRAMA *ptrTrama)
{
	int i, idx;

	for (i = 0; i < ips_array_len; i++) {
		if (clienteDisponible(ips_array[i], &idx)) { // Si el cliente puede recibir comandos
			int sock = tbsockets[idx].cli ? tbsockets[idx].cli->io.fd : -1;

			strcpy(tbsockets[idx].estado, state); // Actualiza el estado del cliente
			if (sock >= 0 && !mandaTrama(&sock, ptrTrama)) {
				syslog(LOG_ERR, "failed to send response to %s:%s\n",
				       ips_array[i], strerror(errno));
			}
		}
	}
	return true;
}

#define OG_REST_PARAM_ADDR			(1UL << 0)
#define OG_REST_PARAM_MAC			(1UL << 1)
#define OG_REST_PARAM_WOL_TYPE			(1UL << 2)
#define OG_REST_PARAM_RUN_CMD			(1UL << 3)
#define OG_REST_PARAM_DISK			(1UL << 4)
#define OG_REST_PARAM_PARTITION			(1UL << 5)
#define OG_REST_PARAM_REPO			(1UL << 6)
#define OG_REST_PARAM_NAME			(1UL << 7)
#define OG_REST_PARAM_ID			(1UL << 8)
#define OG_REST_PARAM_CODE			(1UL << 9)
#define OG_REST_PARAM_TYPE			(1UL << 10)
#define OG_REST_PARAM_PROFILE			(1UL << 11)
#define OG_REST_PARAM_CACHE			(1UL << 12)
#define OG_REST_PARAM_CACHE_SIZE		(1UL << 13)
#define OG_REST_PARAM_PART_0			(1UL << 14)
#define OG_REST_PARAM_PART_1			(1UL << 15)
#define OG_REST_PARAM_PART_2			(1UL << 16)
#define OG_REST_PARAM_PART_3			(1UL << 17)
#define OG_REST_PARAM_SYNC_SYNC			(1UL << 18)
#define OG_REST_PARAM_SYNC_DIFF			(1UL << 19)
#define OG_REST_PARAM_SYNC_REMOVE		(1UL << 20)
#define OG_REST_PARAM_SYNC_COMPRESS		(1UL << 21)
#define OG_REST_PARAM_SYNC_CLEANUP		(1UL << 22)
#define OG_REST_PARAM_SYNC_CACHE		(1UL << 23)
#define OG_REST_PARAM_SYNC_CLEANUP_CACHE	(1UL << 24)
#define OG_REST_PARAM_SYNC_REMOVE_DST		(1UL << 25)
#define OG_REST_PARAM_SYNC_DIFF_ID		(1UL << 26)
#define OG_REST_PARAM_SYNC_DIFF_NAME		(1UL << 27)
#define OG_REST_PARAM_SYNC_PATH			(1UL << 28)
#define OG_REST_PARAM_SYNC_METHOD		(1UL << 29)
#define OG_REST_PARAM_ECHO			(1UL << 30)
#define OG_REST_PARAM_TASK			(1UL << 31)
#define OG_REST_PARAM_TIME_YEARS		(1UL << 32)
#define OG_REST_PARAM_TIME_MONTHS		(1UL << 33)
#define OG_REST_PARAM_TIME_WEEKS		(1UL << 34)
#define OG_REST_PARAM_TIME_WEEK_DAYS		(1UL << 35)
#define OG_REST_PARAM_TIME_DAYS			(1UL << 36)
#define OG_REST_PARAM_TIME_HOURS		(1UL << 37)
#define OG_REST_PARAM_TIME_AM_PM		(1UL << 38)
#define OG_REST_PARAM_TIME_MINUTES		(1UL << 39)

static LIST_HEAD(client_list);

void og_client_add(struct og_client *cli)
{
	list_add(&cli->list, &client_list);
}

static struct og_client *og_client_find(const char *ip)
{
	struct og_client *client;
	struct in_addr addr;
	int res;

	res = inet_aton(ip, &addr);
	if (!res) {
		syslog(LOG_ERR, "Invalid IP string: %s\n", ip);
		return NULL;
	}

	list_for_each_entry(client, &client_list, list) {
		if (client->addr.sin_addr.s_addr == addr.s_addr && client->agent) {
			return client;
		}
	}

	return NULL;
}

static const char *og_client_status(const struct og_client *cli)
{
	if (cli->last_cmd != OG_CMD_UNSPEC)
		return "BSY";

	switch (cli->status) {
	case OG_CLIENT_STATUS_BUSY:
		return "BSY";
	case OG_CLIENT_STATUS_OGLIVE:
		return "OPG";
	case OG_CLIENT_STATUS_VIRTUAL:
		return "VDI";
	default:
		return "OFF";
	}
}

static bool og_msg_params_validate(const struct og_msg_params *params,
				   const uint64_t flags)
{
	return (params->flags & flags) == flags;
}

static int og_json_parse_clients(json_t *element, struct og_msg_params *params)
{
	unsigned int i;
	json_t *k;

	if (json_typeof(element) != JSON_ARRAY)
		return -1;

	for (i = 0; i < json_array_size(element); i++) {
		k = json_array_get(element, i);
		if (json_typeof(k) != JSON_STRING)
			return -1;

		params->ips_array[params->ips_array_len++] =
			json_string_value(k);

		params->flags |= OG_REST_PARAM_ADDR;
	}

	return 0;
}

static int og_json_parse_sync_params(json_t *element,
				     struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "sync")) {
			err = og_json_parse_string(value, &params->sync_setup.sync);
			params->flags |= OG_REST_PARAM_SYNC_SYNC;
		} else if (!strcmp(key, "diff")) {
			err = og_json_parse_string(value, &params->sync_setup.diff);
			params->flags |= OG_REST_PARAM_SYNC_DIFF;
		} else if (!strcmp(key, "remove")) {
			err = og_json_parse_string(value, &params->sync_setup.remove);
			params->flags |= OG_REST_PARAM_SYNC_REMOVE;
		} else if (!strcmp(key, "compress")) {
			err = og_json_parse_string(value, &params->sync_setup.compress);
			params->flags |= OG_REST_PARAM_SYNC_COMPRESS;
		} else if (!strcmp(key, "cleanup")) {
			err = og_json_parse_string(value, &params->sync_setup.cleanup);
			params->flags |= OG_REST_PARAM_SYNC_CLEANUP;
		} else if (!strcmp(key, "cache")) {
			err = og_json_parse_string(value, &params->sync_setup.cache);
			params->flags |= OG_REST_PARAM_SYNC_CACHE;
		} else if (!strcmp(key, "cleanup_cache")) {
			err = og_json_parse_string(value, &params->sync_setup.cleanup_cache);
			params->flags |= OG_REST_PARAM_SYNC_CLEANUP_CACHE;
		} else if (!strcmp(key, "remove_dst")) {
			err = og_json_parse_string(value, &params->sync_setup.remove_dst);
			params->flags |= OG_REST_PARAM_SYNC_REMOVE_DST;
		} else if (!strcmp(key, "diff_id")) {
			err = og_json_parse_string(value, &params->sync_setup.diff_id);
			params->flags |= OG_REST_PARAM_SYNC_DIFF_ID;
		} else if (!strcmp(key, "diff_name")) {
			err = og_json_parse_string(value, &params->sync_setup.diff_name);
			params->flags |= OG_REST_PARAM_SYNC_DIFF_NAME;
		} else if (!strcmp(key, "path")) {
			err = og_json_parse_string(value, &params->sync_setup.path);
			params->flags |= OG_REST_PARAM_SYNC_PATH;
		} else if (!strcmp(key, "method")) {
			err = og_json_parse_string(value, &params->sync_setup.method);
			params->flags |= OG_REST_PARAM_SYNC_METHOD;
		}

		if (err != 0)
			return err;
	}
	return err;
}

static int og_json_parse_partition_setup(json_t *element,
					 struct og_msg_params *params)
{
	unsigned int i;
	json_t *k;

	if (json_typeof(element) != JSON_ARRAY)
		return -1;

	for (i = 0; i < json_array_size(element) && i < OG_PARTITION_MAX; ++i) {
		k = json_array_get(element, i);

		if (json_typeof(k) != JSON_OBJECT)
			return -1;

		if (og_json_parse_partition(k, &params->partition_setup[i],
					    OG_PARAM_PART_NUMBER |
					    OG_PARAM_PART_CODE |
					    OG_PARAM_PART_FILESYSTEM |
					    OG_PARAM_PART_SIZE |
					    OG_PARAM_PART_FORMAT) < 0)
			return -1;

		params->flags |= (OG_REST_PARAM_PART_0 << i);
	}
	return 0;
}

static int og_json_parse_time_params(json_t *element,
				     struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "years")) {
			err = og_json_parse_uint(value, &params->time.years);
			params->flags |= OG_REST_PARAM_TIME_YEARS;
		} else if (!strcmp(key, "months")) {
			err = og_json_parse_uint(value, &params->time.months);
			params->flags |= OG_REST_PARAM_TIME_MONTHS;
		} else if (!strcmp(key, "weeks")) {
			err = og_json_parse_uint(value, &params->time.weeks);
			params->flags |= OG_REST_PARAM_TIME_WEEKS;
		} else if (!strcmp(key, "week_days")) {
			err = og_json_parse_uint(value, &params->time.week_days);
			params->flags |= OG_REST_PARAM_TIME_WEEK_DAYS;
		} else if (!strcmp(key, "days")) {
			err = og_json_parse_uint(value, &params->time.days);
			params->flags |= OG_REST_PARAM_TIME_DAYS;
		} else if (!strcmp(key, "hours")) {
			err = og_json_parse_uint(value, &params->time.hours);
			params->flags |= OG_REST_PARAM_TIME_HOURS;
		} else if (!strcmp(key, "am_pm")) {
			err = og_json_parse_uint(value, &params->time.am_pm);
			params->flags |= OG_REST_PARAM_TIME_AM_PM;
		} else if (!strcmp(key, "minutes")) {
			err = og_json_parse_uint(value, &params->time.minutes);
			params->flags |= OG_REST_PARAM_TIME_MINUTES;
		}
		if (err != 0)
			return err;
	}

	return err;
}

static const char *og_cmd_to_uri[OG_CMD_MAX] = {
	[OG_CMD_WOL]		= "wol",
	[OG_CMD_PROBE]		= "probe",
	[OG_CMD_SHELL_RUN]	= "shell/run",
	[OG_CMD_SESSION]	= "session",
	[OG_CMD_POWEROFF]	= "poweroff",
	[OG_CMD_REFRESH]	= "refresh",
	[OG_CMD_REBOOT]		= "reboot",
	[OG_CMD_STOP]		= "stop",
	[OG_CMD_HARDWARE]	= "hardware",
	[OG_CMD_SOFTWARE]	= "software",
	[OG_CMD_IMAGE_CREATE]	= "image/create",
	[OG_CMD_IMAGE_RESTORE]	= "image/restore",
	[OG_CMD_SETUP]		= "setup",
	[OG_CMD_RUN_SCHEDULE]	= "run/schedule",
};

static bool og_client_is_busy(const struct og_client *cli,
			      enum og_cmd_type type)
{
	switch (type) {
	case OG_CMD_REBOOT:
	case OG_CMD_POWEROFF:
	case OG_CMD_STOP:
		break;
	default:
		if (cli->last_cmd != OG_CMD_UNSPEC)
			return true;
		break;
	}

	return false;
}

int og_send_request(enum og_rest_method method, enum og_cmd_type type,
		    const struct og_msg_params *params,
		    const json_t *data)
{
	const char *content_type = "Content-Type: application/json";
	char content [OG_MSG_REQUEST_MAXLEN - 700] = {};
	char buf[OG_MSG_REQUEST_MAXLEN] = {};
	unsigned int content_length;
	char method_str[5] = {};
	struct og_client *cli;
	const char *uri;
	unsigned int i;
	int client_sd;

	if (method == OG_METHOD_GET)
		snprintf(method_str, 5, "GET");
	else if (method == OG_METHOD_POST)
		snprintf(method_str, 5, "POST");
	else
		return -1;

	if (!data)
		content_length = 0;
	else
		content_length = json_dumpb(data, content,
					    OG_MSG_REQUEST_MAXLEN - 700,
					    JSON_COMPACT);

	uri = og_cmd_to_uri[type];
	snprintf(buf, OG_MSG_REQUEST_MAXLEN,
		 "%s /%s HTTP/1.1\r\nContent-Length: %d\r\n%s\r\n\r\n%s",
		 method_str, uri, content_length, content_type, content);

	for (i = 0; i < params->ips_array_len; i++) {
		cli = og_client_find(params->ips_array[i]);
		if (!cli)
			continue;

		if (og_client_is_busy(cli, type))
			continue;

		client_sd = cli->io.fd;
		if (client_sd < 0) {
			syslog(LOG_INFO, "Client %s not conected\n",
			       params->ips_array[i]);
			continue;
		}

		if (send(client_sd, buf, strlen(buf), 0) < 0)
			continue;

		cli->last_cmd = type;
	}

	return 0;
}

static int og_cmd_post_clients(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_POST, OG_CMD_PROBE, params, NULL);
}

struct og_buffer {
	char	*data;
	int	len;
};

static int og_json_dump_clients(const char *buffer, size_t size, void *data)
{
	struct og_buffer *og_buffer = (struct og_buffer *)data;

	memcpy(og_buffer->data + og_buffer->len, buffer, size);
	og_buffer->len += size;

	return 0;
}

static int og_cmd_get_clients(json_t *element, struct og_msg_params *params,
			      char *buffer_reply)
{
	json_t *root, *array, *addr, *state, *object;
	struct og_client *client;
	struct og_buffer og_buffer = {
		.data	= buffer_reply,
	};

	array = json_array();
	if (!array)
		return -1;

	list_for_each_entry(client, &client_list, list) {
		if (!client->agent)
			continue;

		object = json_object();
		if (!object) {
			json_decref(array);
			return -1;
		}
		addr = json_string(inet_ntoa(client->addr.sin_addr));
		if (!addr) {
			json_decref(object);
			json_decref(array);
			return -1;
		}
		json_object_set_new(object, "addr", addr);
		state = json_string(og_client_status(client));
		if (!state) {
			json_decref(object);
			json_decref(array);
			return -1;
		}
		json_object_set_new(object, "state", state);
		json_array_append_new(array, object);
	}
	root = json_pack("{s:o}", "clients", array);
	if (!root) {
		json_decref(array);
		return -1;
	}

	json_dump_callback(root, og_json_dump_clients, &og_buffer, 0);
	json_decref(root);

	return 0;
}

static int og_json_parse_target(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;

	if (json_typeof(element) != JSON_OBJECT) {
		return -1;
	}

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "addr")) {
			if (json_typeof(value) != JSON_STRING)
				return -1;

			params->ips_array[params->ips_array_len] =
				json_string_value(value);

			params->flags |= OG_REST_PARAM_ADDR;
		} else if (!strcmp(key, "mac")) {
			if (json_typeof(value) != JSON_STRING)
				return -1;

			params->mac_array[params->ips_array_len] =
				json_string_value(value);

			params->flags |= OG_REST_PARAM_MAC;
		}
	}

	return 0;
}

static int og_json_parse_targets(json_t *element, struct og_msg_params *params)
{
	unsigned int i;
	json_t *k;
	int err;

	if (json_typeof(element) != JSON_ARRAY)
		return -1;

	for (i = 0; i < json_array_size(element); i++) {
		k = json_array_get(element, i);

		if (json_typeof(k) != JSON_OBJECT)
			return -1;

		err = og_json_parse_target(k, params);
		if (err < 0)
			return err;

		params->ips_array_len++;
	}
	return 0;
}

static int og_json_parse_type(json_t *element, struct og_msg_params *params)
{
	const char *type;

	if (json_typeof(element) != JSON_STRING)
		return -1;

	params->wol_type = json_string_value(element);

	type = json_string_value(element);
	if (!strcmp(type, "unicast"))
		params->wol_type = "2";
	else if (!strcmp(type, "broadcast"))
		params->wol_type = "1";

	params->flags |= OG_REST_PARAM_WOL_TYPE;

	return 0;
}

static int og_cmd_wol(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_targets(value, params);
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_type(value, params);
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_MAC |
					    OG_REST_PARAM_WOL_TYPE))
		return -1;

	if (!Levanta((char **)params->ips_array, (char **)params->mac_array,
		     params->ips_array_len, (char *)params->wol_type))
		return -1;

	return 0;
}

static int og_json_parse_run(json_t *element, struct og_msg_params *params)
{
	if (json_typeof(element) != JSON_STRING)
		return -1;

	snprintf(params->run_cmd, sizeof(params->run_cmd), "%s",
		 json_string_value(element));

	params->flags |= OG_REST_PARAM_RUN_CMD;

	return 0;
}

static int og_cmd_run_post(json_t *element, struct og_msg_params *params)
{
	json_t *value, *clients;
	const char *key;
	unsigned int i;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);
		else if (!strcmp(key, "run"))
			err = og_json_parse_run(value, params);
		else if (!strcmp(key, "echo")) {
			err = og_json_parse_bool(value, &params->echo);
			params->flags |= OG_REST_PARAM_ECHO;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_RUN_CMD |
					    OG_REST_PARAM_ECHO))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	err = og_send_request(OG_METHOD_POST, OG_CMD_SHELL_RUN, params, clients);
	if (err < 0)
		return err;

	for (i = 0; i < params->ips_array_len; i++) {
		char filename[4096];
		FILE *f;

		sprintf(filename, "/tmp/_Seconsola_%s", params->ips_array[i]);
		f = fopen(filename, "wt");
		fclose(f);
	}

	return 0;
}

static int og_cmd_run_get(json_t *element, struct og_msg_params *params,
			  char *buffer_reply)
{
	struct og_buffer og_buffer = {
		.data	= buffer_reply,
	};
	json_t *root, *value, *array;
	const char *key;
	unsigned int i;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	array = json_array();
	if (!array)
		return -1;

	for (i = 0; i < params->ips_array_len; i++) {
		json_t *object, *output, *addr;
		char data[4096] = {};
		char filename[4096];
		int fd, numbytes;

		sprintf(filename, "/tmp/_Seconsola_%s", params->ips_array[i]);

		fd = open(filename, O_RDONLY);
		if (!fd)
			return -1;

		numbytes = read(fd, data, sizeof(data));
		if (numbytes < 0) {
			close(fd);
			return -1;
		}
		data[sizeof(data) - 1] = '\0';
		close(fd);

		object = json_object();
		if (!object) {
			json_decref(array);
			return -1;
		}
		addr = json_string(params->ips_array[i]);
		if (!addr) {
			json_decref(object);
			json_decref(array);
			return -1;
		}
		json_object_set_new(object, "addr", addr);

		output = json_string(data);
		if (!output) {
			json_decref(object);
			json_decref(array);
			return -1;
		}
		json_object_set_new(object, "output", output);

		json_array_append_new(array, object);
	}

	root = json_pack("{s:o}", "clients", array);
	if (!root)
		return -1;

	json_dump_callback(root, og_json_dump_clients, &og_buffer, 0);
	json_decref(root);

	return 0;
}

static int og_cmd_session(json_t *element, struct og_msg_params *params)
{
	json_t *clients, *value;
	const char *key;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	return og_send_request(OG_METHOD_POST, OG_CMD_SESSION, params, clients);
}

static int og_cmd_poweroff(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_POST, OG_CMD_POWEROFF, params, NULL);
}

static int og_cmd_refresh(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_GET, OG_CMD_REFRESH, params, NULL);
}

static int og_cmd_reboot(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_POST, OG_CMD_REBOOT, params, NULL);
}

#define OG_TFTP_TMPL_PATH "/opt/opengnsys/tftpboot/menu.lst/templates"

static int og_cmd_get_modes(json_t *element, struct og_msg_params *params,
			    char *buffer_reply)
{
	struct og_buffer og_buffer = {
		.data = buffer_reply
	};
	json_t *root, *modes;
	struct dirent *dent;
	DIR *d = NULL;

	root = json_object();
	if (!root)
		return -1;

	modes = json_array();
	if (!modes) {
		json_decref(root);
		return -1;
	}

	d = opendir(OG_TFTP_TMPL_PATH);
	if (!d) {
		json_decref(modes);
		json_decref(root);
		syslog(LOG_ERR, "Cannot open directory %s\n",
		       OG_TFTP_TMPL_PATH);
		return -1;
	}

	dent = readdir(d);
	while (dent) {
		if (dent->d_type != DT_REG) {
			dent = readdir(d);
			continue;
		}
		json_array_append_new(modes, json_string(dent->d_name));
		dent = readdir(d);
	}

	json_object_set_new(root, "modes", modes);
	json_dump_callback(root, og_json_dump_clients, &og_buffer, 0);
	json_decref(root);

	return 0;
}

static int og_cmd_stop(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_POST, OG_CMD_STOP, params, NULL);
}

static int og_cmd_hardware(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_GET, OG_CMD_HARDWARE, params, NULL);
}

static int og_cmd_software(json_t *element, struct og_msg_params *params)
{
	json_t *clients, *value;
	const char *key;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);
		else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		}
		else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	return og_send_request(OG_METHOD_POST, OG_CMD_SOFTWARE, params, clients);
}

static int og_cmd_create_image(json_t *element, struct og_msg_params *params)
{
	json_t *value, *clients;
	const char *key;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "repository")) {
			err = og_json_parse_string(value, &params->repository);
			params->flags |= OG_REST_PARAM_REPO;
		} else if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else if (!strcmp(key, "code")) {
			err = og_json_parse_string(value, &params->code);
			params->flags |= OG_REST_PARAM_CODE;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_CODE |
					    OG_REST_PARAM_ID |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	return og_send_request(OG_METHOD_POST, OG_CMD_IMAGE_CREATE, params,
			       clients);
}

static int og_cmd_restore_image(json_t *element, struct og_msg_params *params)
{
	json_t *clients, *value;
	const char *key;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "repository")) {
			err = og_json_parse_string(value, &params->repository);
			params->flags |= OG_REST_PARAM_REPO;
		} else if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &params->type);
			params->flags |= OG_REST_PARAM_TYPE;
		} else if (!strcmp(key, "profile")) {
			err = og_json_parse_string(value, &params->profile);
			params->flags |= OG_REST_PARAM_PROFILE;
		} else if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO |
					    OG_REST_PARAM_TYPE |
					    OG_REST_PARAM_PROFILE |
					    OG_REST_PARAM_ID))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	return og_send_request(OG_METHOD_POST, OG_CMD_IMAGE_RESTORE, params,
			       clients);
}

static int og_cmd_setup(json_t *element, struct og_msg_params *params)
{
	json_t *value, *clients;
	const char *key;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "cache")) {
			err = og_json_parse_string(value, &params->cache);
			params->flags |= OG_REST_PARAM_CACHE;
		} else if (!strcmp(key, "cache_size")) {
			err = og_json_parse_string(value, &params->cache_size);
			params->flags |= OG_REST_PARAM_CACHE_SIZE;
		} else if (!strcmp(key, "partition_setup")) {
			err = og_json_parse_partition_setup(value, params);
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_CACHE |
					    OG_REST_PARAM_CACHE_SIZE |
					    OG_REST_PARAM_PART_0 |
					    OG_REST_PARAM_PART_1 |
					    OG_REST_PARAM_PART_2 |
					    OG_REST_PARAM_PART_3))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	return og_send_request(OG_METHOD_POST, OG_CMD_SETUP, params, clients);
}

static int og_cmd_run_schedule(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_GET, OG_CMD_RUN_SCHEDULE, params,
			       NULL);
}

static int og_cmd_create_basic_image(json_t *element, struct og_msg_params *params)
{
	char buf[4096] = {};
	int err = 0, len;
	const char *key;
	json_t *value;
	TRAMA *msg;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		} else if (!strcmp(key, "code")) {
			err = og_json_parse_string(value, &params->code);
			params->flags |= OG_REST_PARAM_CODE;
		} else if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "repository")) {
			err = og_json_parse_string(value, &params->repository);
			params->flags |= OG_REST_PARAM_REPO;
		} else if (!strcmp(key, "sync_params")) {
			err = og_json_parse_sync_params(value, params);
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_CODE |
					    OG_REST_PARAM_ID |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO |
					    OG_REST_PARAM_SYNC_SYNC |
					    OG_REST_PARAM_SYNC_DIFF |
					    OG_REST_PARAM_SYNC_REMOVE |
					    OG_REST_PARAM_SYNC_COMPRESS |
					    OG_REST_PARAM_SYNC_CLEANUP |
					    OG_REST_PARAM_SYNC_CACHE |
					    OG_REST_PARAM_SYNC_CLEANUP_CACHE |
					    OG_REST_PARAM_SYNC_REMOVE_DST))
		return -1;

	len = snprintf(buf, sizeof(buf),
		       "nfn=CrearImagenBasica\rdsk=%s\rpar=%s\rcpt=%s\ridi=%s\r"
		       "nci=%s\ripr=%s\rrti=\rmsy=%s\rwhl=%s\reli=%s\rcmp=%s\rbpi=%s\r"
		       "cpc=%s\rbpc=%s\rnba=%s\r",
		       params->disk, params->partition, params->code, params->id,
		       params->name, params->repository, params->sync_setup.sync,
		       params->sync_setup.diff, params->sync_setup.remove,
		       params->sync_setup.compress, params->sync_setup.cleanup,
		       params->sync_setup.cache, params->sync_setup.cleanup_cache,
		       params->sync_setup.remove_dst);

	msg = og_msg_alloc(buf, len);
	if (!msg)
		return -1;

	og_send_cmd((char **)params->ips_array, params->ips_array_len,
		    CLIENTE_OCUPADO, msg);

	og_msg_free(msg);

	return 0;
}

static int og_cmd_create_incremental_image(json_t *element, struct og_msg_params *params)
{
	char buf[4096] = {};
	int err = 0, len;
	const char *key;
	json_t *value;
	TRAMA *msg;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);
		else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		} else if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "repository")) {
			err = og_json_parse_string(value, &params->repository);
			params->flags |= OG_REST_PARAM_REPO;
		} else if (!strcmp(key, "sync_params")) {
			err = og_json_parse_sync_params(value, params);
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_ID |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO |
					    OG_REST_PARAM_SYNC_SYNC |
					    OG_REST_PARAM_SYNC_PATH |
					    OG_REST_PARAM_SYNC_DIFF |
					    OG_REST_PARAM_SYNC_DIFF_ID |
					    OG_REST_PARAM_SYNC_DIFF_NAME |
					    OG_REST_PARAM_SYNC_REMOVE |
					    OG_REST_PARAM_SYNC_COMPRESS |
					    OG_REST_PARAM_SYNC_CLEANUP |
					    OG_REST_PARAM_SYNC_CACHE |
					    OG_REST_PARAM_SYNC_CLEANUP_CACHE |
					    OG_REST_PARAM_SYNC_REMOVE_DST))
		return -1;

	len = snprintf(buf, sizeof(buf),
		       "nfn=CrearSoftIncremental\rdsk=%s\rpar=%s\ridi=%s\rnci=%s\r"
		       "rti=%s\ripr=%s\ridf=%s\rncf=%s\rmsy=%s\rwhl=%s\reli=%s\rcmp=%s\r"
		       "bpi=%s\rcpc=%s\rbpc=%s\rnba=%s\r",
		       params->disk, params->partition, params->id, params->name,
		       params->sync_setup.path, params->repository, params->sync_setup.diff_id,
		       params->sync_setup.diff_name, params->sync_setup.sync,
		       params->sync_setup.diff, params->sync_setup.remove_dst,
		       params->sync_setup.compress, params->sync_setup.cleanup,
		       params->sync_setup.cache, params->sync_setup.cleanup_cache,
		       params->sync_setup.remove_dst);

	msg = og_msg_alloc(buf, len);
	if (!msg)
		return -1;

	og_send_cmd((char **)params->ips_array, params->ips_array_len,
		    CLIENTE_OCUPADO, msg);

	og_msg_free(msg);

	return 0;
}

static int og_cmd_restore_basic_image(json_t *element, struct og_msg_params *params)
{
	char buf[4096] = {};
	int err = 0, len;
	const char *key;
	json_t *value;
	TRAMA *msg;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		} else if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "repository")) {
			err = og_json_parse_string(value, &params->repository);
			params->flags |= OG_REST_PARAM_REPO;
		} else if (!strcmp(key, "profile")) {
			err = og_json_parse_string(value, &params->profile);
			params->flags |= OG_REST_PARAM_PROFILE;
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &params->type);
			params->flags |= OG_REST_PARAM_TYPE;
		} else if (!strcmp(key, "sync_params")) {
			err = og_json_parse_sync_params(value, params);
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_ID |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO |
					    OG_REST_PARAM_PROFILE |
					    OG_REST_PARAM_TYPE |
					    OG_REST_PARAM_SYNC_PATH |
					    OG_REST_PARAM_SYNC_METHOD |
					    OG_REST_PARAM_SYNC_SYNC |
					    OG_REST_PARAM_SYNC_DIFF |
					    OG_REST_PARAM_SYNC_REMOVE |
					    OG_REST_PARAM_SYNC_COMPRESS |
					    OG_REST_PARAM_SYNC_CLEANUP |
					    OG_REST_PARAM_SYNC_CACHE |
					    OG_REST_PARAM_SYNC_CLEANUP_CACHE |
					    OG_REST_PARAM_SYNC_REMOVE_DST))
		return -1;

	len = snprintf(buf, sizeof(buf),
		       "nfn=RestaurarImagenBasica\rdsk=%s\rpar=%s\ridi=%s\rnci=%s\r"
			   "ipr=%s\rifs=%s\rrti=%s\rmet=%s\rmsy=%s\rtpt=%s\rwhl=%s\r"
			   "eli=%s\rcmp=%s\rbpi=%s\rcpc=%s\rbpc=%s\rnba=%s\r",
		       params->disk, params->partition, params->id, params->name,
			   params->repository, params->profile, params->sync_setup.path,
			   params->sync_setup.method, params->sync_setup.sync, params->type,
			   params->sync_setup.diff, params->sync_setup.remove,
		       params->sync_setup.compress, params->sync_setup.cleanup,
		       params->sync_setup.cache, params->sync_setup.cleanup_cache,
		       params->sync_setup.remove_dst);

	msg = og_msg_alloc(buf, len);
	if (!msg)
		return -1;

	og_send_cmd((char **)params->ips_array, params->ips_array_len,
		    CLIENTE_OCUPADO, msg);

	og_msg_free(msg);

	return 0;
}

static int og_cmd_restore_incremental_image(json_t *element, struct og_msg_params *params)
{
	char buf[4096] = {};
	int err = 0, len;
	const char *key;
	json_t *value;
	TRAMA *msg;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &params->disk);
			params->flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &params->partition);
			params->flags |= OG_REST_PARAM_PARTITION;
		} else if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "repository")) {
			err = og_json_parse_string(value, &params->repository);
			params->flags |= OG_REST_PARAM_REPO;
		} else if (!strcmp(key, "profile")) {
			err = og_json_parse_string(value, &params->profile);
			params->flags |= OG_REST_PARAM_PROFILE;
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &params->type);
			params->flags |= OG_REST_PARAM_TYPE;
		} else if (!strcmp(key, "sync_params")) {
			err = og_json_parse_sync_params(value, params);
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_ID |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO |
					    OG_REST_PARAM_PROFILE |
					    OG_REST_PARAM_TYPE |
					    OG_REST_PARAM_SYNC_DIFF_ID |
					    OG_REST_PARAM_SYNC_DIFF_NAME |
					    OG_REST_PARAM_SYNC_PATH |
					    OG_REST_PARAM_SYNC_METHOD |
					    OG_REST_PARAM_SYNC_SYNC |
					    OG_REST_PARAM_SYNC_DIFF |
					    OG_REST_PARAM_SYNC_REMOVE |
					    OG_REST_PARAM_SYNC_COMPRESS |
					    OG_REST_PARAM_SYNC_CLEANUP |
					    OG_REST_PARAM_SYNC_CACHE |
					    OG_REST_PARAM_SYNC_CLEANUP_CACHE |
					    OG_REST_PARAM_SYNC_REMOVE_DST))
		return -1;

	len = snprintf(buf, sizeof(buf),
		       "nfn=RestaurarSoftIncremental\rdsk=%s\rpar=%s\ridi=%s\rnci=%s\r"
			   "ipr=%s\rifs=%s\ridf=%s\rncf=%s\rrti=%s\rmet=%s\rmsy=%s\r"
			   "tpt=%s\rwhl=%s\reli=%s\rcmp=%s\rbpi=%s\rcpc=%s\rbpc=%s\r"
			   "nba=%s\r",
		       params->disk, params->partition, params->id, params->name,
			   params->repository, params->profile, params->sync_setup.diff_id,
			   params->sync_setup.diff_name, params->sync_setup.path,
			   params->sync_setup.method, params->sync_setup.sync, params->type,
			   params->sync_setup.diff, params->sync_setup.remove,
		       params->sync_setup.compress, params->sync_setup.cleanup,
		       params->sync_setup.cache, params->sync_setup.cleanup_cache,
		       params->sync_setup.remove_dst);

	msg = og_msg_alloc(buf, len);
	if (!msg)
		return -1;

	og_send_cmd((char **)params->ips_array, params->ips_array_len,
		    CLIENTE_OCUPADO, msg);

	og_msg_free(msg);

	return 0;
}

static LIST_HEAD(cmd_list);

const struct og_cmd *og_cmd_find(const char *client_ip)
{
	struct og_cmd *cmd, *next;

	list_for_each_entry_safe(cmd, next, &cmd_list, list) {
		if (strcmp(cmd->ip, client_ip))
			continue;

		list_del(&cmd->list);
		return cmd;
	}

	return NULL;
}

void og_cmd_free(const struct og_cmd *cmd)
{
	struct og_msg_params *params = (struct og_msg_params *)&cmd->params;
	int i;

	for (i = 0; i < params->ips_array_len; i++) {
		free((void *)params->ips_array[i]);
		free((void *)params->mac_array[i]);
	}
	free((void *)params->wol_type);

	if (cmd->json)
		json_decref(cmd->json);

	free((void *)cmd->ip);
	free((void *)cmd->mac);
	free((void *)cmd);
}

static void og_cmd_init(struct og_cmd *cmd, enum og_rest_method method,
			enum og_cmd_type type, json_t *root)
{
	cmd->type = type;
	cmd->method = method;
	cmd->params.ips_array[0] = strdup(cmd->ip);
	cmd->params.ips_array_len = 1;
	cmd->json = root;
}

static int og_cmd_legacy_wol(const char *input, struct og_cmd *cmd)
{
	char wol_type[2] = {};

	if (sscanf(input, "mar=%s", wol_type) != 1) {
		syslog(LOG_ERR, "malformed database legacy input\n");
		return -1;
	}

	og_cmd_init(cmd, OG_METHOD_NO_HTTP, OG_CMD_WOL, NULL);
	cmd->params.mac_array[0] = strdup(cmd->mac);
	cmd->params.wol_type = strdup(wol_type);

	return 0;
}

static int og_cmd_legacy_shell_run(const char *input, struct og_cmd *cmd)
{
	json_t *root, *script, *echo;

	script = json_string(input + 4);
	echo = json_boolean(false);

	root = json_object();
	if (!root)
		return -1;
	json_object_set_new(root, "run", script);
	json_object_set_new(root, "echo", echo);

	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_SHELL_RUN, root);

	return 0;
}

static int og_cmd_legacy_session(const char *input, struct og_cmd *cmd)
{
	char part_str[OG_DB_SMALLINT_MAXLEN + 1];
	char disk_str[OG_DB_SMALLINT_MAXLEN + 1];
	json_t *root, *disk, *partition;

	if (sscanf(input, "dsk=%s\rpar=%s\r", disk_str, part_str) != 2)
		return -1;
	partition = json_string(part_str);
	disk = json_string(disk_str);

	root = json_object();
	if (!root)
		return -1;
	json_object_set_new(root, "partition", partition);
	json_object_set_new(root, "disk", disk);

	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_SESSION, root);

	return 0;
}

static int og_cmd_legacy_poweroff(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_POWEROFF, NULL);

	return 0;
}

static int og_cmd_legacy_refresh(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_GET, OG_CMD_REFRESH, NULL);

	return 0;
}

static int og_cmd_legacy_reboot(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_REBOOT, NULL);

	return 0;
}

static int og_cmd_legacy_stop(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_STOP, NULL);

	return 0;
}

static int og_cmd_legacy_hardware(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_GET, OG_CMD_HARDWARE, NULL);

	return 0;
}

static int og_cmd_legacy_software(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_GET, OG_CMD_SOFTWARE, NULL);

	return 0;
}

static int og_cmd_legacy_image_create(const char *input, struct og_cmd *cmd)
{
	json_t *root, *disk, *partition, *code, *image_id, *name, *repo;
	struct og_image_legacy img = {};

	if (sscanf(input, "dsk=%s\rpar=%s\rcpt=%s\ridi=%s\rnci=%s\ripr=%s\r",
		   img.disk, img.part, img.code, img.image_id, img.name,
		   img.repo) != 6)
		return -1;
	image_id = json_string(img.image_id);
	partition = json_string(img.part);
	code = json_string(img.code);
	name = json_string(img.name);
	repo = json_string(img.repo);
	disk = json_string(img.disk);

	root = json_object();
	if (!root)
		return -1;
	json_object_set_new(root, "partition", partition);
	json_object_set_new(root, "repository", repo);
	json_object_set_new(root, "id", image_id);
	json_object_set_new(root, "code", code);
	json_object_set_new(root, "name", name);
	json_object_set_new(root, "disk", disk);

	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_IMAGE_CREATE, root);

	return 0;
}

#define OG_DB_RESTORE_TYPE_MAXLEN	64

static int og_cmd_legacy_image_restore(const char *input, struct og_cmd *cmd)
{
	json_t *root, *disk, *partition, *image_id, *name, *repo;
	char restore_type_str[OG_DB_RESTORE_TYPE_MAXLEN + 1] = {};
	char software_id_str[OG_DB_INT_MAXLEN + 1] = {};
	json_t *software_id, *restore_type;
	struct og_image_legacy img = {};

	if (sscanf(input,
		   "dsk=%s\rpar=%s\ridi=%s\rnci=%s\ripr=%s\rifs=%s\rptc=%s\r",
		   img.disk, img.part, img.image_id, img.name, img.repo,
		   software_id_str, restore_type_str) != 7)
		return -1;

	restore_type = json_string(restore_type_str);
	software_id = json_string(software_id_str);
	image_id = json_string(img.image_id);
	partition = json_string(img.part);
	name = json_string(img.name);
	repo = json_string(img.repo);
	disk = json_string(img.disk);

	root = json_object();
	if (!root)
		return -1;
	json_object_set_new(root, "profile", software_id);
	json_object_set_new(root, "partition", partition);
	json_object_set_new(root, "type", restore_type);
	json_object_set_new(root, "repository", repo);
	json_object_set_new(root, "id", image_id);
	json_object_set_new(root, "name", name);
	json_object_set_new(root, "disk", disk);

	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_IMAGE_RESTORE, root);

	return 0;
}

static int og_cmd_legacy_setup(const char *input, struct og_cmd *cmd)
{
	json_t *root, *disk, *cache, *cache_size, *partition_setup, *object;
	struct og_legacy_partition part_cfg[OG_PARTITION_MAX] = {};
	char cache_size_str [OG_DB_INT_MAXLEN + 1];
	char disk_str [OG_DB_SMALLINT_MAXLEN + 1];
	json_t *part, *code, *fs, *size, *format;
	unsigned int partition_len = 0;
	const char *in_ptr;
	char cache_str[2];

	if (sscanf(input, "dsk=%s\rcfg=dis=%*[^*]*che=%[^*]*tch=%[^!]!",
		   disk_str, cache_str, cache_size_str) != 3)
		return -1;

	in_ptr = strstr(input, "!") + 1;
	while (strlen(in_ptr) > 0) {
		if(sscanf(in_ptr,
			  "par=%[^*]*cpt=%[^*]*sfi=%[^*]*tam=%[^*]*ope=%[^%%]%%",
			  part_cfg[partition_len].partition,
			  part_cfg[partition_len].code,
			  part_cfg[partition_len].filesystem,
			  part_cfg[partition_len].size,
			  part_cfg[partition_len].format) != 5)
			return -1;
		in_ptr = strstr(in_ptr, "%") + 1;
		partition_len++;
	}

	root = json_object();
	if (!root)
		return -1;

	cache_size = json_string(cache_size_str);
	cache = json_string(cache_str);
	partition_setup = json_array();
	disk = json_string(disk_str);

	for (unsigned int i = 0; i < partition_len; ++i) {
		object = json_object();
		if (!object) {
			json_decref(root);
			return -1;
		}

		part = json_string(part_cfg[i].partition);
		fs = json_string(part_cfg[i].filesystem);
		format = json_string(part_cfg[i].format);
		code = json_string(part_cfg[i].code);
		size = json_string(part_cfg[i].size);

		json_object_set_new(object, "partition", part);
		json_object_set_new(object, "filesystem", fs);
		json_object_set_new(object, "format", format);
		json_object_set_new(object, "code", code);
		json_object_set_new(object, "size", size);

		json_array_append_new(partition_setup, object);
	}

	json_object_set_new(root, "partition_setup", partition_setup);
	json_object_set_new(root, "cache_size", cache_size);
	json_object_set_new(root, "cache", cache);
	json_object_set_new(root, "disk", disk);

	og_cmd_init(cmd, OG_METHOD_POST, OG_CMD_SETUP, root);

	return 0;
}

static int og_cmd_legacy_run_schedule(const char *input, struct og_cmd *cmd)
{
	og_cmd_init(cmd, OG_METHOD_GET, OG_CMD_RUN_SCHEDULE, NULL);

	return 0;
}

static int og_cmd_legacy(const char *input, struct og_cmd *cmd)
{
	char legacy_cmd[32] = {};
	int err = -1;

	if (sscanf(input, "nfn=%31s\r", legacy_cmd) != 1) {
		syslog(LOG_ERR, "malformed database legacy input\n");
		return -1;
	}
	input = strchr(input, '\r') + 1;

	if (!strcmp(legacy_cmd, "Arrancar")) {
		err = og_cmd_legacy_wol(input, cmd);
	} else if (!strcmp(legacy_cmd, "EjecutarScript")) {
		err = og_cmd_legacy_shell_run(input, cmd);
	} else if (!strcmp(legacy_cmd, "IniciarSesion")) {
		err = og_cmd_legacy_session(input, cmd);
	} else if (!strcmp(legacy_cmd, "Apagar")) {
		err = og_cmd_legacy_poweroff(input, cmd);
	} else if (!strcmp(legacy_cmd, "Actualizar")) {
		err = og_cmd_legacy_refresh(input, cmd);
	} else if (!strcmp(legacy_cmd, "Reiniciar")) {
		err = og_cmd_legacy_reboot(input, cmd);
	} else if (!strcmp(legacy_cmd, "Purgar")) {
		err = og_cmd_legacy_stop(input, cmd);
	} else if (!strcmp(legacy_cmd, "InventarioHardware")) {
		err = og_cmd_legacy_hardware(input, cmd);
	} else if (!strcmp(legacy_cmd, "InventarioSoftware")) {
		err = og_cmd_legacy_software(input, cmd);
	} else if (!strcmp(legacy_cmd, "CrearImagen")) {
		err = og_cmd_legacy_image_create(input, cmd);
	} else if (!strcmp(legacy_cmd, "RestaurarImagen")) {
		err = og_cmd_legacy_image_restore(input, cmd);
	} else if (!strcmp(legacy_cmd, "Configurar")) {
		err = og_cmd_legacy_setup(input, cmd);
	} else if (!strcmp(legacy_cmd, "EjecutaComandosPendientes") ||
		   !strcmp(legacy_cmd, "Actualizar")) {
		err = og_cmd_legacy_run_schedule(input, cmd);
	}

	return err;
}

static int og_dbi_add_action(const struct og_dbi *dbi, const struct og_task *task,
			     struct og_cmd *cmd)
{
	char start_date_string[24];
	struct tm *start_date;
	const char *msglog;
	dbi_result result;
	time_t now;

	time(&now);
	start_date = localtime(&now);

	sprintf(start_date_string, "%hu/%hhu/%hhu %hhu:%hhu:%hhu",
		start_date->tm_year + 1900, start_date->tm_mon + 1,
		start_date->tm_mday, start_date->tm_hour, start_date->tm_min,
		start_date->tm_sec);
	result = dbi_conn_queryf(dbi->conn,
				"INSERT INTO acciones (idordenador, "
				"tipoaccion, idtipoaccion, descriaccion, ip, "
				"sesion, idcomando, parametros, fechahorareg, "
				"estado, resultado, ambito, idambito, "
				"restrambito, idprocedimiento, idcentro, "
				"idprogramacion) "
				"VALUES (%d, %d, %d, '%s', '%s', %d, %d, '%s', "
				"'%s', %d, %d, %d, %d, '%s', %d, %d, %d)",
				cmd->client_id, EJECUCION_TAREA, task->task_id,
				"", cmd->ip, 0, task->command_id,
				task->params, start_date_string,
				ACCION_INICIADA, ACCION_SINRESULTADO,
				task->type_scope, task->scope, "",
				task->procedure_id, task->center_id,
				task->schedule_id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	cmd->id = dbi_conn_sequence_last(dbi->conn, NULL);
	dbi_result_free(result);

	return 0;
}

static int og_queue_task_command(struct og_dbi *dbi, const struct og_task *task,
				 char *query)
{
	struct og_cmd *cmd;
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn, query);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		cmd = (struct og_cmd *)calloc(1, sizeof(struct og_cmd));
		if (!cmd) {
			dbi_result_free(result);
			return -1;
		}

		cmd->client_id	= dbi_result_get_uint(result, "idordenador");
		cmd->ip		= strdup(dbi_result_get_string(result, "ip"));
		cmd->mac	= strdup(dbi_result_get_string(result, "mac"));

		og_cmd_legacy(task->params, cmd);

		if (task->procedure_id) {
			if (og_dbi_add_action(dbi, task, cmd)) {
				dbi_result_free(result);
				return -1;
			}
		} else {
			cmd->id = task->task_id;
		}

		list_add_tail(&cmd->list, &cmd_list);
	}

	dbi_result_free(result);

	return 0;
}

static int og_queue_task_group_clients(struct og_dbi *dbi, struct og_task *task,
				       char *query)
{

	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn, query);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		uint32_t group_id = dbi_result_get_uint(result, "idgrupo");

		sprintf(query, "SELECT idgrupo FROM gruposordenadores "
				"WHERE grupoid=%d", group_id);
		if (og_queue_task_group_clients(dbi, task, query)) {
			dbi_result_free(result);
			return -1;
		}

		sprintf(query,"SELECT ip, mac, idordenador FROM ordenadores "
			      "WHERE grupoid=%d", group_id);
		if (og_queue_task_command(dbi, task, query)) {
			dbi_result_free(result);
			return -1;
		}

	}

	dbi_result_free(result);

	return 0;
}

static int og_queue_task_group_classrooms(struct og_dbi *dbi,
					  struct og_task *task, char *query)
{

	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn, query);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		uint32_t group_id = dbi_result_get_uint(result, "idgrupo");

		sprintf(query, "SELECT idgrupo FROM grupos "
				"WHERE grupoid=%d AND tipo=%d", group_id, AMBITO_GRUPOSAULAS);
		if (og_queue_task_group_classrooms(dbi, task, query)) {
			dbi_result_free(result);
			return -1;
		}

		sprintf(query,
			"SELECT ip,mac,idordenador "
			"FROM ordenadores INNER JOIN aulas "
			"WHERE ordenadores.idaula=aulas.idaula "
			"AND aulas.grupoid=%d",
			group_id);
		if (og_queue_task_command(dbi, task, query)) {
			dbi_result_free(result);
			return -1;
		}

	}

	dbi_result_free(result);

	return 0;
}

static int og_queue_task_clients(struct og_dbi *dbi, struct og_task *task)
{
	char query[4096];

	switch (task->type_scope) {
		case AMBITO_CENTROS:
			sprintf(query,
				"SELECT ip,mac,idordenador "
				"FROM ordenadores INNER JOIN aulas "
				"WHERE ordenadores.idaula=aulas.idaula "
				"AND idcentro=%d",
				task->scope);
			return og_queue_task_command(dbi, task, query);
		case AMBITO_GRUPOSAULAS:
			sprintf(query,
				"SELECT idgrupo FROM grupos "
				"WHERE idgrupo=%i AND tipo=%d",
				task->scope, AMBITO_GRUPOSAULAS);
			return og_queue_task_group_classrooms(dbi, task, query);
		case AMBITO_AULAS:
			sprintf(query,
				"SELECT ip,mac,idordenador FROM ordenadores "
				"WHERE idaula=%d",
				task->scope);
			return og_queue_task_command(dbi, task, query);
		case AMBITO_GRUPOSORDENADORES:
			sprintf(query,
				"SELECT idgrupo FROM gruposordenadores "
				"WHERE idgrupo = %d",
				task->scope);
			return og_queue_task_group_clients(dbi, task, query);
		case AMBITO_ORDENADORES:
			sprintf(query,
				"SELECT ip, mac, idordenador FROM ordenadores "
				"WHERE idordenador = %d",
				task->scope);
			return og_queue_task_command(dbi, task, query);
	}
	return 0;
}

int og_dbi_queue_procedure(struct og_dbi *dbi, struct og_task *task)
{
	uint32_t procedure_id;
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn,
			"SELECT parametros, procedimientoid, idcomando "
			"FROM procedimientos_acciones "
			"WHERE idprocedimiento=%d ORDER BY orden", task->procedure_id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		procedure_id = dbi_result_get_uint(result, "procedimientoid");
		if (procedure_id > 0) {
			task->procedure_id = procedure_id;
			if (og_dbi_queue_procedure(dbi, task))
				return -1;
			continue;
		}

		task->params	= strdup(dbi_result_get_string(result, "parametros"));
		task->command_id = dbi_result_get_uint(result, "idcomando");
		if (og_queue_task_clients(dbi, task))
			return -1;
	}

	dbi_result_free(result);

	return 0;
}

static int og_dbi_queue_task(struct og_dbi *dbi, uint32_t task_id,
			     uint32_t schedule_id)
{
	struct og_task task = {};
	uint32_t task_id_next;
	const char *msglog;
	dbi_result result;

	task.schedule_id = schedule_id;

	result = dbi_conn_queryf(dbi->conn,
			"SELECT tareas_acciones.orden, "
				"tareas_acciones.idprocedimiento, "
				"tareas_acciones.tareaid, "
				"tareas.idtarea, "
				"tareas.idcentro, "
				"tareas.ambito, "
				"tareas.idambito, "
				"tareas.restrambito "
			" FROM tareas"
				" INNER JOIN tareas_acciones ON tareas_acciones.idtarea=tareas.idtarea"
			" WHERE tareas_acciones.idtarea=%u ORDER BY tareas_acciones.orden ASC", task_id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		task_id_next = dbi_result_get_uint(result, "tareaid");

		if (task_id_next > 0) {
			if (og_dbi_queue_task(dbi, task_id_next, schedule_id))
				return -1;

			continue;
		}
		task.task_id = dbi_result_get_uint(result, "idtarea");
		task.center_id = dbi_result_get_uint(result, "idcentro");
		task.procedure_id = dbi_result_get_uint(result, "idprocedimiento");
		task.type_scope = dbi_result_get_uint(result, "ambito");
		task.scope = dbi_result_get_uint(result, "idambito");
		task.filtered_scope = dbi_result_get_string(result, "restrambito");

		og_dbi_queue_procedure(dbi, &task);
	}

	dbi_result_free(result);

	return 0;
}

static int og_dbi_queue_command(struct og_dbi *dbi, uint32_t task_id,
				uint32_t schedule_id)
{
	struct og_task task = {};
	const char *msglog;
	dbi_result result;
	char query[4096];

	result = dbi_conn_queryf(dbi->conn,
			"SELECT idaccion, idcentro, idordenador, parametros "
			"FROM acciones "
			"WHERE sesion = %u", task_id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		task.task_id = dbi_result_get_uint(result, "idaccion");
		task.center_id = dbi_result_get_uint(result, "idcentro");
		task.scope = dbi_result_get_uint(result, "idordenador");
		task.params = strdup(dbi_result_get_string(result, "parametros"));

		sprintf(query,
			"SELECT ip, mac, idordenador FROM ordenadores "
			"WHERE idordenador = %d",
			task.scope);
		if (og_queue_task_command(dbi, &task, query)) {
			dbi_result_free(result);
			return -1;
		}
	}

	dbi_result_free(result);

	return 0;
}

int og_dbi_update_action(uint32_t id, bool success)
{
	char end_date_string[24];
	struct tm *end_date;
	const char *msglog;
	struct og_dbi *dbi;
	uint8_t status = 2;
	dbi_result result;
	time_t now;

	if (!id)
		return 0;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	time(&now);
	end_date = localtime(&now);

	sprintf(end_date_string, "%hu/%hhu/%hhu %hhu:%hhu:%hhu",
		end_date->tm_year + 1900, end_date->tm_mon + 1,
		end_date->tm_mday, end_date->tm_hour, end_date->tm_min,
		end_date->tm_sec);
	result = dbi_conn_queryf(dbi->conn,
				 "UPDATE acciones SET fechahorafin='%s', "
				 "estado=%d, resultado=%d WHERE idaccion=%d",
				 end_date_string, ACCION_FINALIZADA,
				 status - success, id);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}
	dbi_result_free(result);
	og_dbi_close(dbi);

	return 0;
}

void og_schedule_run(unsigned int task_id, unsigned int schedule_id,
		     enum og_schedule_type type)
{
	struct og_msg_params params = {};
	bool duplicated = false;
	struct og_cmd *cmd, *next;
	struct og_dbi *dbi;
	unsigned int i;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return;
	}

	switch (type) {
	case OG_SCHEDULE_TASK:
		og_dbi_queue_task(dbi, task_id, schedule_id);
		break;
	case OG_SCHEDULE_PROCEDURE:
	case OG_SCHEDULE_COMMAND:
		og_dbi_queue_command(dbi, task_id, schedule_id);
		break;
	}
	og_dbi_close(dbi);

	list_for_each_entry(cmd, &cmd_list, list) {
		for (i = 0; i < params.ips_array_len; i++) {
			if (!strncmp(cmd->ip, params.ips_array[i],
				     OG_DB_IP_MAXLEN)) {
				duplicated = true;
				break;
			}
		}

		if (!duplicated)
			params.ips_array[params.ips_array_len++] = cmd->ip;
		else
			duplicated = false;
	}

	list_for_each_entry_safe(cmd, next, &cmd_list, list) {
		if (cmd->type != OG_CMD_WOL)
			continue;

		if (Levanta((char **)cmd->params.ips_array,
			    (char **)cmd->params.mac_array,
			    cmd->params.ips_array_len,
			    (char *)cmd->params.wol_type))
			og_dbi_update_action(cmd->id, true);

		list_del(&cmd->list);
		og_cmd_free(cmd);
	}

	og_send_request(OG_METHOD_GET, OG_CMD_RUN_SCHEDULE, &params, NULL);
}

static int og_cmd_task_post(json_t *element, struct og_msg_params *params)
{
	struct og_cmd *cmd;
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "task")) {
			err = og_json_parse_string(value, &params->task_id);
			params->flags |= OG_REST_PARAM_TASK;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_TASK))
		return -1;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
			   __func__, __LINE__);
		return -1;
	}

	og_schedule_run(atoi(params->task_id), 0, OG_SCHEDULE_TASK);
	og_dbi_close(dbi);

	list_for_each_entry(cmd, &cmd_list, list)
		params->ips_array[params->ips_array_len++] = cmd->ip;

	return og_send_request(OG_METHOD_GET, OG_CMD_RUN_SCHEDULE, params,
			       NULL);
}

static int og_dbi_scope_get_center(struct og_dbi *dbi, json_t *array)
{
	char center_name[OG_DB_CENTER_NAME_MAXLEN + 1] = {};
	const char *msglog;
	uint32_t center_id;
	dbi_result result;
	json_t *center;

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT nombrecentro, idcentro FROM centros");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		center_id = dbi_result_get_uint(result, "idcentro");
		strncpy(center_name,
			dbi_result_get_string(result, "nombrecentro"),
			OG_DB_CENTER_NAME_MAXLEN);

		center = json_object();
		if (!center) {
			dbi_result_free(result);
			return -1;
		}

		json_object_set_new(center, "name", json_string(center_name));
		json_object_set_new(center, "type", json_string("center"));
		json_object_set_new(center, "id", json_integer(center_id));
		json_object_set_new(center, "scope", json_array());
		json_array_append(array, center);
		json_decref(center);
	}
	dbi_result_free(result);

	return 0;
}

static int og_dbi_scope_get_room(struct og_dbi *dbi, json_t *array,
				 uint32_t center_id)
{
	char room_name[OG_DB_ROOM_NAME_MAXLEN + 1] = {};
	const char *msglog;
	dbi_result result;
	uint32_t room_id;
	json_t *room;

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT idaula, nombreaula FROM aulas WHERE "
				 "idcentro=%d",
				 center_id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		room_id = dbi_result_get_uint(result, "idaula");
		strncpy(room_name,
			dbi_result_get_string(result, "nombreaula"),
			OG_DB_CENTER_NAME_MAXLEN);

		room = json_object();
		if (!room) {
			dbi_result_free(result);
			return -1;
		}

		json_object_set_new(room, "name", json_string(room_name));
		json_object_set_new(room, "type", json_string("room"));
		json_object_set_new(room, "id", json_integer(room_id));
		json_object_set_new(room, "scope", json_array());
		json_array_append(array, room);
		json_decref(room);
	}
	dbi_result_free(result);

	return 0;
}

static int og_dbi_scope_get_computer(struct og_dbi *dbi, json_t *array,
				     uint32_t room_id)
{
	char computer_name[OG_DB_COMPUTER_NAME_MAXLEN + 1] = {};
	uint32_t computer_id;
	const char *msglog;
	dbi_result result;
	json_t *computer;

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT idordenador, nombreordenador, ip "
				 "FROM ordenadores WHERE idaula=%d",
				 room_id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		computer_id = dbi_result_get_uint(result, "idordenador");
		strncpy(computer_name,
			dbi_result_get_string(result, "nombreordenador"),
			OG_DB_CENTER_NAME_MAXLEN);

		computer = json_object();
		if (!computer) {
			dbi_result_free(result);
			return -1;
		}

		json_object_set_new(computer, "name", json_string(computer_name));
		json_object_set_new(computer, "type", json_string("computer"));
		json_object_set_new(computer, "id", json_integer(computer_id));
		json_object_set_new(computer, "scope", json_array());
		json_array_append(array, computer);
		json_decref(computer);
	}
	dbi_result_free(result);

	return 0;
}

static int og_cmd_scope_get(json_t *element, struct og_msg_params *params,
			    char *buffer_reply)
{
	json_t *root, *children_root, *children_center, *children_room,
	       *center_value, *room_value;
	uint32_t center_id, room_id, index1, index2;
	struct og_dbi *dbi;

	struct og_buffer og_buffer = {
		.data = buffer_reply
	};

	root = json_object();
	if (!root)
		return -1;

	children_root = json_array();
	if (!children_root) {
		json_decref(root);
		return -1;
	}

	json_object_set(root, "scope", children_root);

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	if (og_dbi_scope_get_center(dbi, children_root)) {
		og_dbi_close(dbi);
		return -1;
	}

	json_array_foreach(children_root, index1, center_value) {
		center_id = json_integer_value(json_object_get(center_value,"id"));
		children_center = json_object_get(center_value, "scope");
		if (og_dbi_scope_get_room(dbi, children_center, center_id)) {
			og_dbi_close(dbi);
			return -1;
		}

		json_array_foreach(children_center, index2, room_value) {
			room_id = json_integer_value(json_object_get(room_value, "id"));
			children_room = json_object_get(room_value, "scope");
			if (og_dbi_scope_get_computer(dbi, children_room, room_id)) {
				og_dbi_close(dbi);
				return -1;
			}
		}
	}

	og_dbi_close(dbi);

	json_dump_callback(root, og_json_dump_clients, &og_buffer, 0);
	json_decref(root);

	return 0;
}

int og_dbi_schedule_get(void)
{
	uint32_t schedule_id, task_id;
	struct og_schedule_time time;
	struct og_dbi *dbi;
	const char *msglog;
	dbi_result result;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT idprogramacion, tipoaccion, identificador, "
				 "sesion, annos, meses, diario, dias, semanas, horas, "
				 "ampm, minutos FROM programaciones "
				 "WHERE suspendida = 0");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		memset(&time, 0, sizeof(time));
		schedule_id = dbi_result_get_uint(result, "idprogramacion");
		task_id = dbi_result_get_uint(result, "identificador");
		time.years = dbi_result_get_uint(result, "annos");
		time.months = dbi_result_get_uint(result, "meses");
		time.weeks = dbi_result_get_uint(result, "semanas");
		time.week_days = dbi_result_get_uint(result, "dias");
		time.days = dbi_result_get_uint(result, "diario");
		time.hours = dbi_result_get_uint(result, "horas");
		time.am_pm = dbi_result_get_uint(result, "ampm");
		time.minutes = dbi_result_get_uint(result, "minutos");
		time.on_start = true;

		og_schedule_create(schedule_id, task_id, OG_SCHEDULE_TASK,
				   &time);
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	return 0;
}

static int og_dbi_schedule_create(struct og_dbi *dbi,
				  struct og_msg_params *params,
				  uint32_t *schedule_id,
				  enum og_schedule_type schedule_type)
{
	uint8_t suspended = 0;
	uint32_t session = 0;
	const char *msglog;
	dbi_result result;
	uint8_t type;

	switch (schedule_type) {
	case OG_SCHEDULE_TASK:
		type = 3;
		break;
	case OG_SCHEDULE_PROCEDURE:
		type = 2;
		break;
	case OG_SCHEDULE_COMMAND:
		session = atoi(params->task_id);
		type = 1;
		break;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "INSERT INTO programaciones (tipoaccion,"
				 " identificador, nombrebloque, annos, meses,"
				 " semanas, dias, diario, horas, ampm, minutos,"
				 " suspendida, sesion) VALUES (%d, %s, '%s',"
				 " %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)",
				 type, params->task_id, params->name,
				 params->time.years, params->time.months,
				 params->time.weeks, params->time.week_days,
				 params->time.days, params->time.hours,
				 params->time.am_pm, params->time.minutes,
				 suspended, session);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	*schedule_id = dbi_conn_sequence_last(dbi->conn, NULL);

	return 0;
}

static int og_dbi_schedule_update(struct og_dbi *dbi,
				  struct og_msg_params *params)
{
	const char *msglog;
	dbi_result result;
	uint8_t type = 3;

	result = dbi_conn_queryf(dbi->conn,
				 "UPDATE programaciones SET tipoaccion=%d, "
				 "identificador='%s', nombrebloque='%s', "
				 "annos=%d, meses=%d, "
				 "diario=%d, horas=%d, ampm=%d, minutos=%d "
				 "WHERE idprogramacion='%s'",
				 type, params->task_id, params->name,
				 params->time.years, params->time.months,
				 params->time.days, params->time.hours,
				 params->time.am_pm, params->time.minutes,
				 params->id);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	return 0;
}

static int og_dbi_schedule_delete(struct og_dbi *dbi, uint32_t id)
{
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn,
				 "DELETE FROM programaciones WHERE idprogramacion=%d",
				 id);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	return 0;
}

struct og_db_schedule {
	uint32_t		id;
	uint32_t		task_id;
	const char		*name;
	struct og_schedule_time	time;
	uint32_t		week_days;
	uint32_t		weeks;
	uint32_t		suspended;
	uint32_t		session;
};

static int og_dbi_schedule_get_json(struct og_dbi *dbi, json_t *root,
				    const char *task_id, const char *schedule_id)
{
	struct og_db_schedule schedule;
	json_t *obj, *array;
	const char *msglog;
	dbi_result result;
	int err = 0;

	if (task_id) {
		result = dbi_conn_queryf(dbi->conn,
					 "SELECT idprogramacion,"
					 "	 identificador, nombrebloque,"
					 "	 annos, meses, diario, dias,"
					 "	 semanas, horas, ampm,"
					 "	 minutos,suspendida, sesion "
					 "FROM programaciones "
					 "WHERE identificador=%d",
					 atoi(task_id));
	} else if (schedule_id) {
		result = dbi_conn_queryf(dbi->conn,
					 "SELECT idprogramacion,"
					 "	 identificador, nombrebloque,"
					 "	 annos, meses, diario, dias,"
					 "	 semanas, horas, ampm,"
					 "	 minutos,suspendida, sesion "
					 "FROM programaciones "
					 "WHERE idprogramacion=%d",
					 atoi(schedule_id));
	} else {
		result = dbi_conn_queryf(dbi->conn,
					 "SELECT idprogramacion,"
					 "	 identificador, nombrebloque,"
					 "	 annos, meses, diario, dias,"
					 "	 semanas, horas, ampm,"
					 "	 minutos,suspendida, sesion "
					 "FROM programaciones");
	}

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	array = json_array();
	if (!array)
		return -1;

	while (dbi_result_next_row(result)) {
		schedule.id = dbi_result_get_uint(result, "idprogramacion");
		schedule.task_id = dbi_result_get_uint(result, "identificador");
		schedule.name = dbi_result_get_string(result, "nombrebloque");
		schedule.time.years = dbi_result_get_uint(result, "annos");
		schedule.time.months = dbi_result_get_uint(result, "meses");
		schedule.time.days = dbi_result_get_uint(result, "diario");
		schedule.time.hours = dbi_result_get_uint(result, "horas");
		schedule.time.am_pm = dbi_result_get_uint(result, "ampm");
		schedule.time.minutes = dbi_result_get_uint(result, "minutos");
		schedule.week_days = dbi_result_get_uint(result, "dias");
		schedule.weeks = dbi_result_get_uint(result, "semanas");
		schedule.suspended = dbi_result_get_uint(result, "suspendida");
		schedule.session = dbi_result_get_uint(result, "sesion");

		obj = json_object();
		if (!obj) {
			err = -1;
			break;
		}
		json_object_set_new(obj, "id", json_integer(schedule.id));
		json_object_set_new(obj, "task", json_integer(schedule.task_id));
		json_object_set_new(obj, "name", json_string(schedule.name));
		json_object_set_new(obj, "years", json_integer(schedule.time.years));
		json_object_set_new(obj, "months", json_integer(schedule.time.months));
		json_object_set_new(obj, "days", json_integer(schedule.time.days));
		json_object_set_new(obj, "hours", json_integer(schedule.time.hours));
		json_object_set_new(obj, "am_pm", json_integer(schedule.time.am_pm));
		json_object_set_new(obj, "minutes", json_integer(schedule.time.minutes));
		json_object_set_new(obj, "week_days", json_integer(schedule.week_days));
		json_object_set_new(obj, "weeks", json_integer(schedule.weeks));
		json_object_set_new(obj, "suspended", json_integer(schedule.suspended));
		json_object_set_new(obj, "session", json_integer(schedule.session));

		json_array_append_new(array, obj);
	}

	json_object_set_new(root, "schedule", array);

	dbi_result_free(result);

	return err;
}

static int og_task_schedule_create(struct og_msg_params *params)
{
	enum og_schedule_type type;
	uint32_t schedule_id;
	struct og_dbi *dbi;
	int err;

	if (!strcmp(params->type, "task"))
		type = OG_SCHEDULE_TASK;
	else if (!strcmp(params->type, "procedure"))
		type = OG_SCHEDULE_PROCEDURE;
	else if (!strcmp(params->type, "command"))
		type = OG_SCHEDULE_COMMAND;
	else
		return -1;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	err = og_dbi_schedule_create(dbi, params, &schedule_id, type);
	if (err < 0) {
		og_dbi_close(dbi);
		return -1;
	}
	og_schedule_create(schedule_id, atoi(params->task_id), type,
			   &params->time);
	og_schedule_refresh(og_loop);
	og_dbi_close(dbi);

	return 0;
}

static int og_cmd_schedule_create(json_t *element, struct og_msg_params *params)
{
	const char *key;
	json_t *value;
	int err;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "task")) {
			err = og_json_parse_string(value, &params->task_id);
			params->flags |= OG_REST_PARAM_TASK;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "when")) {
			err = og_json_parse_time_params(value, params);
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &params->type);
			params->flags |= OG_REST_PARAM_TYPE;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_TASK |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_TIME_YEARS |
					    OG_REST_PARAM_TIME_MONTHS |
					    OG_REST_PARAM_TIME_WEEKS |
					    OG_REST_PARAM_TIME_WEEK_DAYS |
					    OG_REST_PARAM_TIME_DAYS |
					    OG_REST_PARAM_TIME_HOURS |
					    OG_REST_PARAM_TIME_MINUTES |
					    OG_REST_PARAM_TIME_AM_PM |
					    OG_REST_PARAM_TYPE))
		return -1;

	return og_task_schedule_create(params);
}

static int og_cmd_schedule_update(json_t *element, struct og_msg_params *params)
{
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else if (!strcmp(key, "task")) {
			err = og_json_parse_string(value, &params->task_id);
			params->flags |= OG_REST_PARAM_TASK;
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "when"))
			err = og_json_parse_time_params(value, params);

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ID |
					    OG_REST_PARAM_TASK |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_TIME_YEARS |
					    OG_REST_PARAM_TIME_MONTHS |
					    OG_REST_PARAM_TIME_DAYS |
					    OG_REST_PARAM_TIME_HOURS |
					    OG_REST_PARAM_TIME_MINUTES |
					    OG_REST_PARAM_TIME_AM_PM))
		return -1;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
			   __func__, __LINE__);
		return -1;
	}

	err = og_dbi_schedule_update(dbi, params);
	og_dbi_close(dbi);

	if (err < 0)
		return err;

	og_schedule_update(og_loop, atoi(params->id), atoi(params->task_id),
			   &params->time);
	og_schedule_refresh(og_loop);

	return err;
}

static int og_cmd_schedule_delete(json_t *element, struct og_msg_params *params)
{
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		} else {
			return -1;
		}

		if (err < 0)
			break;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ID))
		return -1;

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
			   __func__, __LINE__);
		return -1;
	}

	err = og_dbi_schedule_delete(dbi, atoi(params->id));
	og_dbi_close(dbi);

	og_schedule_delete(og_loop, atoi(params->id));

	return err;
}

static int og_cmd_schedule_get(json_t *element, struct og_msg_params *params,
			       char *buffer_reply)
{
	struct og_buffer og_buffer = {
		.data	= buffer_reply,
	};
	json_t *schedule_root;
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err;

	if (element) {
		if (json_typeof(element) != JSON_OBJECT)
			return -1;

		json_object_foreach(element, key, value) {
			if (!strcmp(key, "task")) {
				err = og_json_parse_string(value,
							   &params->task_id);
			} else if (!strcmp(key, "id")) {
				err = og_json_parse_string(value, &params->id);
			} else {
				return -1;
			}

			if (err < 0)
				break;
		}
	}

	dbi = og_dbi_open(&dbi_config);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
			   __func__, __LINE__);
		return -1;
	}

	schedule_root = json_object();
	if (!schedule_root) {
		og_dbi_close(dbi);
		return -1;
	}

	err = og_dbi_schedule_get_json(dbi, schedule_root,
				       params->task_id, params->id);
	og_dbi_close(dbi);

	if (err >= 0)
		json_dump_callback(schedule_root, og_json_dump_clients, &og_buffer, 0);

	json_decref(schedule_root);

	return err;
}

static int og_client_method_not_found(struct og_client *cli)
{
	/* To meet RFC 7231, this function MUST generate an Allow header field
	 * containing the correct methods. For example: "Allow: POST\r\n"
	 */
	char buf[] = "HTTP/1.1 405 Method Not Allowed\r\n"
		     "Content-Length: 0\r\n\r\n";

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return -1;
}

static int og_client_bad_request(struct og_client *cli)
{
	char buf[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return -1;
}

static int og_client_not_found(struct og_client *cli)
{
	char buf[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return -1;
}

static int og_client_not_authorized(struct og_client *cli)
{
	char buf[] = "HTTP/1.1 401 Unauthorized\r\n"
		     "WWW-Authenticate: Basic\r\n"
		     "Content-Length: 0\r\n\r\n";

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return -1;
}

static int og_server_internal_error(struct og_client *cli)
{
	char buf[] = "HTTP/1.1 500 Internal Server Error\r\n"
		     "Content-Length: 0\r\n\r\n";

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return -1;
}

#define OG_MSG_RESPONSE_MAXLEN	65536

static int og_client_ok(struct og_client *cli, char *buf_reply)
{
	char buf[OG_MSG_RESPONSE_MAXLEN] = {};
	int err = 0, len;

	len = snprintf(buf, sizeof(buf),
		       "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n%s",
		       strlen(buf_reply), buf_reply);
	if (len >= (int)sizeof(buf))
		err = og_server_internal_error(cli);

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return err;
}

int og_client_state_process_payload_rest(struct og_client *cli)
{
	char buf_reply[OG_MSG_RESPONSE_MAXLEN] = {};
	struct og_msg_params params = {};
	enum og_rest_method method;
	const char *cmd, *body;
	json_error_t json_err;
	json_t *root = NULL;
	int err = 0;

	syslog(LOG_DEBUG, "%s:%hu %.32s ...\n",
	       inet_ntoa(cli->addr.sin_addr),
	       ntohs(cli->addr.sin_port), cli->buf);

	if (!strncmp(cli->buf, "GET", strlen("GET"))) {
		method = OG_METHOD_GET;
		cmd = cli->buf + strlen("GET") + 2;
	} else if (!strncmp(cli->buf, "POST", strlen("POST"))) {
		method = OG_METHOD_POST;
		cmd = cli->buf + strlen("POST") + 2;
	} else
		return og_client_method_not_found(cli);

	body = strstr(cli->buf, "\r\n\r\n") + 4;

	if (strcmp(cli->auth_token, auth_token)) {
		syslog(LOG_ERR, "wrong Authentication key\n");
		return og_client_not_authorized(cli);
	}

	if (cli->content_length) {
		root = json_loads(body, 0, &json_err);
		if (!root) {
			syslog(LOG_ERR, "malformed json line %d: %s\n",
			       json_err.line, json_err.text);
			return og_client_not_found(cli);
		}
	}

	if (!strncmp(cmd, "clients", strlen("clients"))) {
		if (method != OG_METHOD_POST &&
		    method != OG_METHOD_GET)
			return og_client_method_not_found(cli);

		if (method == OG_METHOD_POST && !root) {
			syslog(LOG_ERR, "command clients with no payload\n");
			return og_client_bad_request(cli);
		}
		switch (method) {
		case OG_METHOD_POST:
			err = og_cmd_post_clients(root, &params);
			break;
		case OG_METHOD_GET:
			err = og_cmd_get_clients(root, &params, buf_reply);
			break;
		default:
			return og_client_bad_request(cli);
		}
	} else if (!strncmp(cmd, "wol", strlen("wol"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command wol with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_wol(root, &params);
	} else if (!strncmp(cmd, "shell/run", strlen("shell/run"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command run with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_run_post(root, &params);
	} else if (!strncmp(cmd, "shell/output", strlen("shell/output"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command output with no payload\n");
			return og_client_bad_request(cli);
		}

		err = og_cmd_run_get(root, &params, buf_reply);
	} else if (!strncmp(cmd, "session", strlen("session"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command session with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_session(root, &params);
	} else if (!strncmp(cmd, "scopes", strlen("scopes"))) {
		if (method != OG_METHOD_GET)
			return og_client_method_not_found(cli);

		err = og_cmd_scope_get(root, &params, buf_reply);
	} else if (!strncmp(cmd, "poweroff", strlen("poweroff"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command poweroff with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_poweroff(root, &params);
	} else if (!strncmp(cmd, "reboot", strlen("reboot"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command reboot with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_reboot(root, &params);
	} else if (!strncmp(cmd, "modes", strlen("modes"))) {
		if (method != OG_METHOD_GET)
			return og_client_method_not_found(cli);

		err = og_cmd_get_modes(root, &params, buf_reply);
	} else if (!strncmp(cmd, "stop", strlen("stop"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command stop with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_stop(root, &params);
	} else if (!strncmp(cmd, "refresh", strlen("refresh"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command refresh with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_refresh(root, &params);
	} else if (!strncmp(cmd, "hardware", strlen("hardware"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command hardware with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_hardware(root, &params);
	} else if (!strncmp(cmd, "software", strlen("software"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command software with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_software(root, &params);
	} else if (!strncmp(cmd, "image/create/basic",
			    strlen("image/create/basic"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_create_basic_image(root, &params);
	} else if (!strncmp(cmd, "image/create/incremental",
			    strlen("image/create/incremental"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_create_incremental_image(root, &params);
	} else if (!strncmp(cmd, "image/create", strlen("image/create"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_create_image(root, &params);
	} else if (!strncmp(cmd, "image/restore/basic",
				strlen("image/restore/basic"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_restore_basic_image(root, &params);
	} else if (!strncmp(cmd, "image/restore/incremental",
				strlen("image/restore/incremental"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_restore_incremental_image(root, &params);
	} else if (!strncmp(cmd, "image/restore", strlen("image/restore"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_restore_image(root, &params);
	} else if (!strncmp(cmd, "setup", strlen("setup"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_setup(root, &params);
	} else if (!strncmp(cmd, "run/schedule", strlen("run/schedule"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			return og_client_bad_request(cli);
		}

		err = og_cmd_run_schedule(root, &params);
	} else if (!strncmp(cmd, "task/run", strlen("task/run"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_task_post(root, &params);
	} else if (!strncmp(cmd, "schedule/create",
			    strlen("schedule/create"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_schedule_create(root, &params);
	} else if (!strncmp(cmd, "schedule/delete",
			    strlen("schedule/delete"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_schedule_delete(root, &params);
	} else if (!strncmp(cmd, "schedule/update",
			    strlen("schedule/update"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			return og_client_bad_request(cli);
		}
		err = og_cmd_schedule_update(root, &params);
	} else if (!strncmp(cmd, "schedule/get",
			    strlen("schedule/get"))) {
		if (method != OG_METHOD_POST)
			return og_client_method_not_found(cli);

		err = og_cmd_schedule_get(root, &params, buf_reply);
	} else {
		syslog(LOG_ERR, "unknown command: %.32s ...\n", cmd);
		err = og_client_not_found(cli);
	}

	if (root)
		json_decref(root);

	if (err < 0)
		return og_client_bad_request(cli);

	err = og_client_ok(cli, buf_reply);
	if (err < 0) {
		syslog(LOG_ERR, "HTTP response to %s:%hu is too large\n",
		       inet_ntoa(cli->addr.sin_addr),
		       ntohs(cli->addr.sin_port));
	}

	return err;
}
