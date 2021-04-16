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
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/statvfs.h>

struct ev_loop *og_loop;

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
#define OG_REST_PARAM_NETMASK			(1UL << 40)
#define OG_REST_PARAM_SCOPE			(1UL << 41)
#define OG_REST_PARAM_MODE			(1UL << 42)

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
	switch (cli->last_cmd) {
	case OG_CMD_UNSPEC:
	case OG_CMD_PROBE:
		break;
	default:
		return "BSY";
	}

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

static bool og_flags_validate(const uint64_t flags,
			      const uint64_t required_flags)
{
	return (flags & required_flags) == required_flags;
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
	[OG_CMD_IMAGES]		= "images",
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

	json_decref((json_t *)data);

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
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_POST, OG_CMD_PROBE, params, NULL);
}

struct og_buffer {
	char	*data;
	int	len;
};

#define OG_MSG_RESPONSE_MAXLEN	262144

static int og_json_dump_clients(const char *buffer, size_t size, void *data)
{
	struct og_buffer *og_buffer = (struct og_buffer *)data;

	if (size >= OG_MSG_RESPONSE_MAXLEN - og_buffer->len) {
		syslog(LOG_ERR, "Response JSON body is too large\n");
		return -1;
	}

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

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);

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
	char ips_str[(OG_DB_IP_MAXLEN + 1) * OG_CLIENTS_MAX + 1] = {};
	int ips_str_len = 0;
	const char *msglog;
	struct og_dbi *dbi;
	int err = 0, i = 0;
	dbi_result result;
	const char *key;
	json_t *value;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_type(value, params);
		}

		if (err < 0)
			return err;
	}
	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_WOL_TYPE))
		return -1;

	for (i = 0; i < params->ips_array_len; ++i) {
		ips_str_len += snprintf(ips_str + ips_str_len,
					sizeof(ips_str) - ips_str_len,
					"'%s',", params->ips_array[i]);
	}
	ips_str[ips_str_len - 1] = '\0';

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT ordenadores.ip, ordenadores.mac, "
					"aulas.netmask "
				 "FROM   ordenadores "
				 "INNER JOIN aulas "
					 "ON ordenadores.idaula = aulas.idaula "
				 "WHERE  ordenadores.ip IN (%s)",
				 ips_str);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	for (i = 0; dbi_result_next_row(result); i++) {
		params->ips_array[i] = dbi_result_get_string_copy(result, "ip");
		params->mac_array[i] = dbi_result_get_string_copy(result, "mac");
		params->netmask_array[i] = dbi_result_get_string_copy(result, "netmask");
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	if (i == 0)
		return 0;

	if (!Levanta((char **)params->ips_array, (char **)params->mac_array,
		     (char **)params->netmask_array, i,
		     (char *)params->wol_type))
		return -1;

	for (i = 0; i < params->ips_array_len; ++i) {
		free((void *)params->ips_array[i]);
		free((void *)params->mac_array[i]);
		free((void *)params->netmask_array[i]);
	}

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
			return err;
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

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

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

static int og_cmd_get_session(json_t *element, struct og_msg_params *params,
			      char *buffer_reply)
{
	json_t *value, *root, *array, *item;
	const char *key, *msglog, *os_name;
	unsigned int disk, partition;
	struct og_dbi *dbi;
	dbi_result result;
	int err = 0;

	struct og_buffer og_buffer = {
		.data = buffer_reply
	};

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "client"))
			err = og_json_parse_clients(value, params);
		else
			err = -1;

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT op.numdisk, op.numpar, nom.nombreso "
				 "FROM ordenadores o "
				 "INNER JOIN ordenadores_particiones op "
				 "    ON o.idordenador = op.idordenador "
				 "INNER JOIN nombresos nom "
				 "    ON op.idnombreso = nom.idnombreso "
				 "WHERE o.ip = '%s'",
				 params->ips_array[0]);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	array = json_array();
	if (!array) {
		dbi_result_free(result);
		og_dbi_close(dbi);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		item = json_object();
		if (!item) {
			dbi_result_free(result);
			og_dbi_close(dbi);
			json_decref(array);
			return -1;
		}

		disk = dbi_result_get_uint(result, "numdisk");
		partition = dbi_result_get_uint(result, "numpar");
		os_name = dbi_result_get_string(result, "nombreso");

		json_object_set_new(item, "disk", json_integer(disk));
		json_object_set_new(item, "partition", json_integer(partition));
		json_object_set_new(item, "name", json_string(os_name));
		json_array_append_new(array, item);
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	root = json_object();
	if (!root){
		json_decref(array);
		return -1;
	}

	json_object_set_new(root, "sessions", array);

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);
	return 0;
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
			return err;
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
			return err;
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
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_POST, OG_CMD_REBOOT, params, NULL);
}

#define OG_TFTP_TMPL_PATH_UEFI "/opt/opengnsys/tftpboot/grub/templates"
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

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);
	closedir(d);

	return 0;
}

static int og_change_db_mode(struct og_dbi *dbi, const char *mac,
			     const char * mode)
{
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn,
				 "UPDATE ordenadores SET arranque='%s' "
				 "WHERE mac='%s'",
				 mode, mac);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	dbi_result_free(result);
	return 0;
}

static int og_set_client_mode(struct og_dbi *dbi, const char *mac,
			      const char *mode, const char *template_name)
{
	char filename[PATH_MAX + 1] = "/tmp/mode_params_XXXXXX";
	char cmd_params[16384] = {};
	char params[4096] = "\0";
	const char *msglog;
	dbi_result result;
	unsigned int i;
	int numbytes;
	int status;
	int fd;

	result = dbi_conn_queryf(dbi->conn,
		"SELECT ' LANG=%s', ' ip=', CONCAT_WS(':', ordenadores.ip, (SELECT (@serverip:=ipserveradm) FROM entornos LIMIT 1), aulas.router, aulas.netmask, ordenadores.nombreordenador, ordenadores.netiface, 'none'), ' group=', REPLACE(TRIM(aulas.nombreaula), ' ', '_'), ' ogrepo=', (@repoip:=IFNULL(repositorios.ip, '')), ' oglive=', @serverip, ' oglog=', @serverip, ' ogshare=', @serverip, ' oglivedir=', ordenadores.oglivedir, ' ogprof=', IF(ordenadores.idordenador=aulas.idordprofesor, 'true', 'false'), IF(perfileshard.descripcion<>'', CONCAT(' hardprofile=', REPLACE(TRIM(perfileshard.descripcion), ' ', '_')), ''), IF(aulas.ntp<>'', CONCAT(' ogntp=', aulas.ntp), ''), IF(aulas.dns<>'', CONCAT(' ogdns=', aulas.dns), ''), IF(aulas.proxy<>'', CONCAT(' ogproxy=', aulas.proxy), ''), IF(entidades.ogunit=1 AND NOT centros.directorio='', CONCAT(' ogunit=', centros.directorio), ''), CASE WHEN menus.resolucion IS NULL THEN '' WHEN menus.resolucion <= '999' THEN CONCAT(' vga=', menus.resolucion) WHEN menus.resolucion LIKE '%:%' THEN CONCAT(' video=', menus.resolucion) ELSE menus.resolucion END FROM ordenadores JOIN aulas USING(idaula) JOIN centros USING(idcentro) JOIN entidades USING(identidad) LEFT JOIN repositorios USING(idrepositorio) LEFT JOIN perfileshard USING(idperfilhard) LEFT JOIN menus USING(idmenu) WHERE ordenadores.mac='%s'", getenv("LANG"), mac);

	if (dbi_result_get_numrows(result) != 1) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __FILE__, __LINE__, msglog);
		dbi_result_free(result);
		return -1;
	}
	dbi_result_next_row(result);

	for (i = 1; i <= dbi_result_get_numfields(result); ++i)
		strcat(params, dbi_result_get_string_idx(result, i));

	dbi_result_free(result);

	snprintf(cmd_params, sizeof(cmd_params),
		 "MODE_FILE='%s'\nMAC='%s'\nDATA='%s'\n"
		 "MODE='PERM'\nTEMPLATE_NAME='%s'",
		 mode, mac, params, template_name);

	fd = mkstemp(filename);
	if (fd < 0) {
		syslog(LOG_ERR, "cannot generate temp file (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	numbytes = write(fd, cmd_params, strlen(cmd_params) + 1);
	close(fd);

	if (numbytes < 0) {
		syslog(LOG_ERR, "cannot write file\n");
		unlink(filename);
		return -1;
	}

	if (fork() == 0) {
		execlp("/bin/bash", "/bin/bash",
		       "/opt/opengnsys/bin/setclientmode", filename, NULL);
		syslog(LOG_ERR, "failed script execution (%s:%d)\n",
		       __func__, __LINE__);
		exit(EXIT_FAILURE);
	} else {
		wait(&status);
	}
	unlink(filename);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		syslog(LOG_ERR, "failed script execution (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	if (og_change_db_mode(dbi, mac, mode) < 0) {
		syslog(LOG_ERR, "failed to change db mode (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	return 0;
}

static int og_cmd_post_modes(json_t *element, struct og_msg_params *params)
{
	char ips_str[(OG_DB_IP_MAXLEN + 1) * OG_CLIENTS_MAX + 1] = {};
	char template_file_uefi[PATH_MAX + 1] = {};
	char template_file[PATH_MAX + 1] = {};
	char template_name[PATH_MAX + 1] = {};
	char first_line[PATH_MAX + 1] = {};
	const char *mode_str, *mac;
	int ips_str_len = 0;
	struct og_dbi *dbi;
	uint64_t flags = 0;
	dbi_result result;
	const char *key;
	json_t *value;
	int err = 0;
	FILE *f;
	int i;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "mode")) {
			err = og_json_parse_string(value, &mode_str);
			flags |= OG_REST_PARAM_MODE;
		} else {
			err = -1;
		}

		if (err < 0)
			return err;
	}

	if (!og_flags_validate(flags, OG_REST_PARAM_MODE) ||
	    !og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	snprintf(template_file, sizeof(template_file), "%s/%s",
		 OG_TFTP_TMPL_PATH, mode_str);
	f = fopen(template_file, "r");
	if (!f) {
		syslog(LOG_WARNING, "cannot open file %s (%s:%d). Trying UEFI template instead.\n",
		       template_file, __func__, __LINE__);

		snprintf(template_file_uefi, sizeof(template_file_uefi), "%s/%s",
			 OG_TFTP_TMPL_PATH_UEFI, mode_str);
		f = fopen(template_file_uefi, "r");
		if (!f) {
			syslog(LOG_ERR, "cannot open file %s (%s:%d). No template found.\n",
			       template_file_uefi, __func__, __LINE__);
			return -1;
		}
	}

	if (!fgets(first_line, sizeof(first_line), f)) {
		fclose(f);
		syslog(LOG_ERR, "cannot read file (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	fclose(f);

	if (sscanf(first_line, "##NO-TOCAR-ESTA-LINEA %s", template_name) != 1) {
		syslog(LOG_ERR, "malformed template: %s", first_line);
		return -1;
	}

	for (i = 0; i < params->ips_array_len; ++i) {
		ips_str_len += snprintf(ips_str + ips_str_len,
					sizeof(ips_str) - ips_str_len,
					"'%s',", params->ips_array[i]);
	}
	ips_str[ips_str_len - 1] = '\0';

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT mac FROM ordenadores "
				 "WHERE ip IN (%s)", ips_str);

	while (dbi_result_next_row(result)) {
		mac = dbi_result_get_string(result, "mac");
		err = og_set_client_mode(dbi, mac, mode_str, template_name);
		if (err != 0) {
			dbi_result_free(result);
			og_dbi_close(dbi);
			return -1;
		}
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	return 0;
}

static int og_cmd_get_client_setup(json_t *element,
				   struct og_msg_params *params,
				   char *buffer_reply)
{
	json_t *value, *root, *partitions_array, *partition_json;
	const char *key, *msglog;
	unsigned int len_part;
	struct og_dbi *dbi;
	dbi_result result;
	int err = 0;

	struct og_buffer og_buffer = {
		.data = buffer_reply
	};

	struct {
		int disk;
		int number;
		int code;
		uint64_t size;
		int filesystem;
		int format;
		int os;
		int used_size;
		int image;
		int software;
	} partition;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "client")) {
			err = og_json_parse_clients(value, params);
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	if (params->ips_array_len != 1)
		return -1;

	root = json_object();
	if (!root)
		return -1;

	partitions_array = json_array();
	if (!partitions_array) {
		json_decref(root);
		return -1;
	}
	json_object_set_new(root, "partitions", partitions_array);

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		json_decref(root);
		syslog(LOG_ERR, "cannot open conection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT numdisk, numpar, codpar, tamano, "
				 "       uso, idsistemafichero, idnombreso, "
				 "       idimagen, idperfilsoft "
				 "FROM ordenadores_particiones "
				 "INNER JOIN ordenadores "
				 "ON ordenadores.idordenador = ordenadores_particiones.idordenador "
				 "WHERE ordenadores.ip='%s'",
				 params->ips_array[0]);
	if (!result) {
		json_decref(root);
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	len_part = 0;
	/* partition 0 represents the full disk, hence OG_PARTITION_MAX + 1. */
	while (dbi_result_next_row(result) && len_part < OG_PARTITION_MAX + 1) {
		partition.disk = dbi_result_get_int(result, "numdisk");
		partition.number = dbi_result_get_int(result, "numpar");
		partition.code = dbi_result_get_int(result, "codpar");
		partition.size = dbi_result_get_longlong(result, "tamano");
		partition.used_size = dbi_result_get_int(result, "uso");
		partition.filesystem = dbi_result_get_int(result, "idsistemafichero");
		partition.os = dbi_result_get_int(result, "idnombreso");
		partition.image = dbi_result_get_int(result, "idimagen");
		partition.software = dbi_result_get_int(result, "idperfilsoft");

		partition_json = json_object();
		if (!partition_json) {
			json_decref(root);
			dbi_result_free(result);
			og_dbi_close(dbi);
			return -1;
		}

		json_object_set_new(partition_json, "disk",
				    json_integer(partition.disk));
		json_object_set_new(partition_json, "partition",
				    json_integer(partition.number));
		json_object_set_new(partition_json, "code",
				    json_integer(partition.code));
		json_object_set_new(partition_json, "size",
				    json_integer(partition.size));
		json_object_set_new(partition_json, "used_size",
				    json_integer(partition.used_size));
		json_object_set_new(partition_json, "filesystem",
				    json_integer(partition.filesystem));
		json_object_set_new(partition_json, "os",
				    json_integer(partition.os));
		json_object_set_new(partition_json, "image",
				    json_integer(partition.image));
		json_object_set_new(partition_json, "software",
				    json_integer(partition.software));
		json_array_append_new(partitions_array, partition_json);

		++len_part;
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);
	return 0;
}

static int og_cmd_get_client_info(json_t *element,
				  struct og_msg_params *params,
				  char *buffer_reply)
{
	struct og_computer computer = {};
	json_t *value, *root;
	struct in_addr addr;
	struct og_dbi *dbi;
	const char *key;
	int err = 0;

	struct og_buffer og_buffer = {
		.data = buffer_reply
	};

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "client")) {
			err = og_json_parse_clients(value, params);
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	if (params->ips_array_len != 1)
		return -1;

	if (inet_aton(params->ips_array[0], &addr) == 0)
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open conection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	if (og_dbi_get_computer_info(dbi, &computer, addr)) {
		og_dbi_close(dbi);
		return -1;
	}

	og_dbi_close(dbi);

	root = json_object();
	if (!root)
		return -1;

	json_object_set_new(root, "serial_number",
			    json_string(computer.serial_number));
	json_object_set_new(root, "hardware_id",
			    json_integer(computer.hardware_id));
	json_object_set_new(root, "netdriver", json_string(computer.netdriver));
	json_object_set_new(root, "maintenance", json_boolean(computer.name));
	json_object_set_new(root, "netiface", json_string(computer.netiface));
	json_object_set_new(root, "repo_id", json_integer(computer.repo_id));
	json_object_set_new(root, "livedir", json_string(computer.livedir));
	json_object_set_new(root, "netmask", json_string(computer.netmask));
	json_object_set_new(root, "center", json_integer(computer.center));
	json_object_set_new(root, "remote", json_boolean(computer.remote));
	json_object_set_new(root, "room", json_integer(computer.room));
	json_object_set_new(root, "name", json_string(computer.name));
	json_object_set_new(root, "boot", json_string(computer.boot));
	json_object_set_new(root, "mac", json_string(computer.mac));
	json_object_set_new(root, "id", json_integer(computer.id));
	json_object_set_new(root, "ip", json_string(computer.ip));

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);
	return 0;
}

static int og_cmd_post_client_add(json_t *element,
				  struct og_msg_params *params,
				  char *buffer_reply)
{
	struct og_computer computer = {};
	const char *key, *msglog;
	struct og_dbi *dbi;
	dbi_result result;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "serial_number")) {
			err = og_json_parse_string_copy(value,
							computer.serial_number,
							sizeof(computer.serial_number));
		} else if (!strcmp(key, "hardware_id")) {
			err = og_json_parse_uint(value, &computer.hardware_id);
		} else if (!strcmp(key, "netdriver")) {
			err = og_json_parse_string_copy(value,
							computer.netdriver,
							sizeof(computer.netdriver));
		} else if (!strcmp(key, "maintenance")) {
			err = og_json_parse_bool(value, &computer.maintenance);
		} else if (!strcmp(key, "netiface")) {
			err = og_json_parse_string_copy(value,
							computer.netiface,
							sizeof(computer.netiface));
		} else if (!strcmp(key, "repo_id")) {
			err = og_json_parse_uint(value, &computer.repo_id);
		} else if (!strcmp(key, "livedir")) {
			err = og_json_parse_string_copy(value,
							computer.livedir,
							sizeof(computer.livedir));
		} else if (!strcmp(key, "netmask")) {
			err = og_json_parse_string_copy(value,
							computer.netmask,
							sizeof(computer.netmask));
		} else if (!strcmp(key, "remote")) {
			err = og_json_parse_bool(value, &computer.remote);
		} else if (!strcmp(key, "room")) {
			err = og_json_parse_uint(value, &computer.room);
		} else if (!strcmp(key, "name")) {
			err = og_json_parse_string_copy(value,
							computer.name,
							sizeof(computer.name));
		} else if (!strcmp(key, "boot")) {
			err = og_json_parse_string_copy(value,
							computer.boot,
							sizeof(computer.boot));
		} else if (!strcmp(key, "mac")) {
			err = og_json_parse_string_copy(value,
							computer.mac,
							sizeof(computer.mac));
		} else if (!strcmp(key, "ip")) {
			err = og_json_parse_string_copy(value,
							computer.ip,
							sizeof(computer.ip));
		}

		if (err < 0)
			return err;
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open conection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT ip FROM ordenadores WHERE ip='%s'",
				 computer.ip);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	if (dbi_result_get_numrows(result) > 0) {
		syslog(LOG_ERR, "client with the same IP already exists: %s\n",
		       computer.ip);
		dbi_result_free(result);
		og_dbi_close(dbi);
		return -1;
	}
	dbi_result_free(result);

	result = dbi_conn_queryf(dbi->conn,
				 "INSERT INTO ordenadores("
				 "  nombreordenador,"
				 "  numserie,"
				 "  ip,"
				 "  mac,"
				 "  idaula,"
				 "  idperfilhard,"
				 "  idrepositorio,"
				 "  mascara,"
				 "  arranque,"
				 "  netiface,"
				 "  netdriver,"
				 "  oglivedir,"
				 "  inremotepc,"
				 "  maintenance"
				 ") VALUES ('%s', '%s', '%s', '%s', %u, %u,"
				 "           %u, '%s', '%s', '%s', '%s',"
				 "          '%s', %u, %u)",
				 computer.name, computer.serial_number,
				 computer.ip, computer.mac, computer.room,
				 computer.hardware_id, computer.repo_id,
				 computer.netmask, computer.boot,
				 computer.netiface, computer.netdriver,
				 computer.livedir, computer.remote,
				 computer.maintenance);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to add client to database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	dbi_result_free(result);
	og_dbi_close(dbi);
	return 0;
}

static int og_cmd_post_client_delete(json_t *element,
				     struct og_msg_params *params)
{
	const char *key, *msglog;
	struct og_dbi *dbi;
	dbi_result result;
	unsigned int i;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "clients"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open conection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	for (i = 0; i < params->ips_array_len; i++) {
		result = dbi_conn_queryf(dbi->conn,
					 "DELETE FROM ordenadores WHERE ip='%s'",
					 params->ips_array[i]);

		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			og_dbi_close(dbi);
			return -1;
		}

		dbi_result_free(result);
	}

	og_dbi_close(dbi);
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
			return err;
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
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_GET, OG_CMD_HARDWARE, params, NULL);
}

static int og_cmd_get_hardware(json_t *element, struct og_msg_params *params,
			       char *buffer_reply)
{
	const char *key, *msglog, *hw_item, *hw_type;
	json_t *value, *root, *array, *item;
	struct og_dbi *dbi;
	dbi_result result;
	int err = 0;

	struct og_buffer og_buffer = {
		.data = buffer_reply
	};

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "client"))
			err = og_json_parse_clients(value, params);

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT hardwares.descripcion AS item, "
				 "	 tipohardwares.descripcion AS type "
				 "FROM hardwares "
				 "INNER JOIN perfileshard_hardwares "
				 "    ON hardwares.idhardware = perfileshard_hardwares.idhardware "
				 "INNER JOIN ordenadores "
				 "    ON perfileshard_hardwares.idperfilhard = ordenadores.idperfilhard "
				 "INNER JOIN tipohardwares "
				 "    ON hardwares.idtipohardware = tipohardwares.idtipohardware "
				 "WHERE ordenadores.ip = '%s'",
				 params->ips_array[0]);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	array = json_array();
	if (!array) {
		dbi_result_free(result);
		og_dbi_close(dbi);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		item = json_object();
		if (!item) {
			dbi_result_free(result);
			og_dbi_close(dbi);
			json_decref(array);
			return -1;
		}

		hw_item = dbi_result_get_string(result, "item");
		hw_type = dbi_result_get_string(result, "type");

		json_object_set_new(item, "type", json_string(hw_type));
		json_object_set_new(item, "description", json_string(hw_item));
		json_array_append_new(array, item);
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	root = json_object();
	if (!root){
		json_decref(array);
		return -1;
	}

	json_object_set_new(root, "hardware", array);

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);
	return 0;
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
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION))
		return -1;

	clients = json_copy(element);
	json_object_del(clients, "clients");

	return og_send_request(OG_METHOD_GET, OG_CMD_SOFTWARE, params, clients);
}

static int og_cmd_get_software(json_t *element, struct og_msg_params *params,
			       char *buffer_reply)
{
	json_t *value, *software, *root;
	const char *key, *msglog, *name;
	uint64_t disk, partition;
	uint64_t flags = 0;
	struct og_dbi *dbi;
	dbi_result result;
	int err = 0;

	struct og_buffer og_buffer = {
		.data = buffer_reply
	};

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "client")) {
			err = og_json_parse_clients(value, params);
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_uint64(value, &disk);
			flags |= OG_REST_PARAM_DISK;
		} else if (!strcmp(key, "partition")) {
			err = og_json_parse_uint64(value, &partition);
			flags |= OG_REST_PARAM_PARTITION;
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR) ||
	    !og_flags_validate(flags, OG_REST_PARAM_DISK |
				      OG_REST_PARAM_PARTITION))
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open conection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT s.descripcion "
				 "FROM softwares s "
				 "INNER JOIN perfilessoft_softwares pss "
				 "ON s.idsoftware = pss.idsoftware "
				 "INNER JOIN ordenadores_particiones op "
				 "ON pss.idperfilsoft = op.idperfilsoft "
				 "INNER JOIN ordenadores o "
				 "ON o.idordenador = op.idordenador "
				 "WHERE o.ip='%s' AND "
				 "      op.numdisk=%lu AND "
				 "      op.numpar=%lu",
				 params->ips_array[0], disk, partition);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	software = json_array();
	if (!software) {
		dbi_result_free(result);
		og_dbi_close(dbi);
		return -1;
	}

	while (dbi_result_next_row(result)) {
		name = dbi_result_get_string(result, "descripcion");
		json_array_append_new(software, json_string(name));
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	root = json_object();
	if (!root) {
		json_decref(software);
		return -1;
	}
	json_object_set_new(root, "software", software);

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);
	return 0;
}

#define OG_IMAGE_TYPE_MAXLEN	4

static int og_get_image_stats(const char *name,
			      struct stat *image_stats)
{
	const char *dir = ogconfig.repo.dir;
	char filename[PATH_MAX + 1];

	snprintf(filename, sizeof(filename), "%s/%s.img", dir, name);
	if (stat(filename, image_stats) < 0) {
		syslog(LOG_ERR, "%s image does not exists", name);
		return -1;
	}
	return 0;
}

static json_t *og_json_disk_alloc()
{
	const char *dir = ogconfig.repo.dir;
	struct statvfs buffer;
	json_t *disk_json;
	int ret;

	ret = statvfs(dir, &buffer);
	if (ret)
		return NULL;

	disk_json = json_object();
	if (!disk_json)
		return NULL;

	json_object_set_new(disk_json, "total",
			    json_integer(buffer.f_blocks * buffer.f_frsize));
	json_object_set_new(disk_json, "free",
			    json_integer(buffer.f_bfree * buffer.f_frsize));

	return disk_json;
}

#define OG_PERMS_IRWX (S_IRWXU | S_IRWXG | S_IRWXO)
#define OG_PERMS_MAXLEN 4

static json_t *og_json_image_alloc(struct og_image *image)
{
	char perms_string[OG_PERMS_MAXLEN];
	json_t *image_json;
	char *modified;
	uint16_t perms;

	image_json = json_object();
	if (!image_json)
		return NULL;

	perms = image->image_stats.st_mode & OG_PERMS_IRWX;
	snprintf(perms_string, sizeof(perms_string), "%o", perms);

	modified = ctime(&image->image_stats.st_mtime);
	modified[strlen(modified) - 1] = '\0';

	json_object_set_new(image_json, "name",
			    json_string(image->name));
	json_object_set_new(image_json, "datasize",
			    json_integer(image->datasize));
	json_object_set_new(image_json, "size",
			    json_integer(image->image_stats.st_size));
	json_object_set_new(image_json, "modified",
			    json_string(modified));
	json_object_set_new(image_json, "permissions",
			    json_string(perms_string));
	json_object_set_new(image_json, "software_id",
			    json_integer(image->software_id));
	json_object_set_new(image_json, "type",
			    json_integer(image->type));
	json_object_set_new(image_json, "id",
			    json_integer(image->id));

	return image_json;
}

static int og_cmd_images(char *buffer_reply)
{
	json_t *root, *images, *image_json, *disk_json;
	struct og_buffer og_buffer = {
		.data = buffer_reply
	};
	struct og_image image;
	struct og_dbi *dbi;
	dbi_result result;

	root = json_object();
	if (!root)
		return -1;

	images = json_array();
	if (!images) {
		json_decref(root);
		return -1;
	}

	json_object_set_new(root, "images", images);

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		json_decref(root);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT i.nombreca, o.nombreordenador, "
				 "       i.clonator, i.compressor, "
				 "       i.filesystem, i.datasize, "
				 "       i.idperfilsoft, i.tipo, "
				 "       i.idimagen "
				 "FROM imagenes i "
				 "LEFT JOIN ordenadores o "
				 "ON i.idordenador = o.idordenador");

	while (dbi_result_next_row(result)) {
		image = (struct og_image){0};
		image.datasize = dbi_result_get_ulonglong(result, "datasize");
		image.software_id = dbi_result_get_ulonglong(result, "idperfilsoft");
		image.type = dbi_result_get_ulonglong(result, "tipo");
		image.id = dbi_result_get_ulonglong(result, "idimagen");
		snprintf(image.name, sizeof(image.name), "%s",
			 dbi_result_get_string(result, "nombreca"));

		if (og_get_image_stats(image.name, &image.image_stats)) {
			continue;
		}

		image_json = og_json_image_alloc(&image);
		if (!image_json) {
			dbi_result_free(result);
			og_dbi_close(dbi);
			json_decref(root);
			return -1;
		}

		json_array_append_new(images, image_json);
	}

	dbi_result_free(result);
	og_dbi_close(dbi);

	disk_json = og_json_disk_alloc();
	if (!disk_json) {
		syslog(LOG_ERR, "cannot allocate disk json");
		json_decref(root);
		return -1;
	}

	json_object_set_new(root, "disk", disk_json);

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);

	return 0;
}

static int og_cmd_create_image(json_t *element, struct og_msg_params *params)
{
	char new_image_id[OG_DB_INT_MAXLEN + 1];
	struct og_image image = {};
	json_t *value, *clients;
	struct og_dbi *dbi;
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
		} else if (!strcmp(key, "description")) {
			err = og_json_parse_string_copy(value,
							image.description,
							sizeof(image.description));
		} else if (!strcmp(key, "group_id")) {
			err = og_json_parse_uint64(value, &image.group_id);
		} else if (!strcmp(key, "center_id")) {
			err = og_json_parse_uint64(value, &image.center_id);
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_DISK |
					    OG_REST_PARAM_PARTITION |
					    OG_REST_PARAM_CODE |
					    OG_REST_PARAM_ID |
					    OG_REST_PARAM_NAME |
					    OG_REST_PARAM_REPO))
		return -1;

	/* If there is a description, this means the image is not in the DB. */
	if (image.description[0]) {
		snprintf(image.name, sizeof(image.name), "%s", params->name);

		dbi = og_dbi_open(&ogconfig.db);
		if (!dbi) {
			syslog(LOG_ERR,
			       "cannot open connection database (%s:%d)\n",
			       __func__, __LINE__);
			return -1;
		}

		err = og_dbi_add_image(dbi, &image);

		og_dbi_close(dbi);
		if (err < 0)
			return err;

		snprintf(new_image_id, sizeof(new_image_id), "%u", err);
		params->id = new_image_id;
	}

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
			return err;
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
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &params->type);
			params->flags |= OG_REST_PARAM_TYPE;
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
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR |
					    OG_REST_PARAM_TYPE |
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
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ADDR))
		return -1;

	return og_send_request(OG_METHOD_GET, OG_CMD_RUN_SCHEDULE, params,
			       NULL);
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
		free((void *)params->netmask_array[i]);
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
	const char *msglog;
	struct og_dbi *dbi;
	dbi_result result;

	if (sscanf(input, "mar=%s", wol_type) != 1) {
		syslog(LOG_ERR, "malformed database legacy input\n");
		return -1;
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT aulas.netmask "
				 "FROM   ordenadores "
				 "INNER JOIN aulas "
					 "ON ordenadores.idaula = aulas.idaula "
				 "WHERE  ordenadores.ip = '%s'",
				 cmd->ip);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}
	dbi_result_next_row(result);

	og_cmd_init(cmd, OG_METHOD_NO_HTTP, OG_CMD_WOL, NULL);
	cmd->params.netmask_array[0] = dbi_result_get_string_copy(result,
								  "netmask");
	cmd->params.mac_array[0] = strdup(cmd->mac);
	cmd->params.wol_type = strdup(wol_type);

	dbi_result_free(result);
	og_dbi_close(dbi);

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

	og_cmd_init(cmd, OG_METHOD_GET, OG_CMD_SOFTWARE, root);

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
		   "dsk=%s\rpar=%s\ridi=%s\rnci=%s\r"
		   "ipr=%s\rifs=%s\rptc=%[^\r]\r",
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

#define OG_PARTITION_TABLE_TYPE_MAXLEN 5

static int og_cmd_legacy_setup(const char *input, struct og_cmd *cmd)
{
	json_t *root, *disk, *cache, *cache_size, *partition_setup, *object;
	char part_table_type_str[OG_PARTITION_TABLE_TYPE_MAXLEN + 1];
	struct og_legacy_partition part_cfg[OG_PARTITION_MAX] = {};
	json_t *part_table_type, *part, *code, *fs, *size, *format;
	char cache_size_str [OG_DB_INT_MAXLEN + 1];
	char disk_str [OG_DB_SMALLINT_MAXLEN + 1];
	unsigned int partition_len = 0;
	const char *in_ptr;
	char cache_str[2];

	if (sscanf(input, "ttp=%s\rdsk=%s\rcfg=dis=%*[^*]*che=%[^*]*tch=%[^!]!",
		   part_table_type_str, disk_str, cache_str, cache_size_str) != 4)
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

	part_table_type = json_string(part_table_type_str);
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
	json_object_set_new(root, "type", part_table_type);
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

		task->params = dbi_result_get_string(result, "parametros");
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
		task.params = dbi_result_get_string(result, "parametros");

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

	dbi = og_dbi_open(&ogconfig.db);
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

	dbi = og_dbi_open(&ogconfig.db);
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
			params.ips_array[params.ips_array_len++] = strdup(cmd->ip);
		else
			duplicated = false;
	}

	list_for_each_entry_safe(cmd, next, &cmd_list, list) {
		if (cmd->type != OG_CMD_WOL)
			continue;

		if (Levanta((char **)cmd->params.ips_array,
			    (char **)cmd->params.mac_array,
			    (char **)cmd->params.netmask_array,
			    cmd->params.ips_array_len,
			    (char *)cmd->params.wol_type))
			og_dbi_update_action(cmd->id, true);

		list_del(&cmd->list);
		og_cmd_free(cmd);
	}

	og_send_request(OG_METHOD_GET, OG_CMD_RUN_SCHEDULE, &params, NULL);

	for (i = 0; i < params.ips_array_len; i++)
		free((void *)params.ips_array[i]);
}

static int og_cmd_task_post(json_t *element, struct og_msg_params *params)
{
	struct og_cmd *cmd;
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "task")) {
			err = og_json_parse_string(value, &params->task_id);
			params->flags |= OG_REST_PARAM_TASK;
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_TASK))
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
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

static int og_dbi_scope_get_computer(struct og_dbi *dbi, json_t *array,
				     uint32_t room_id)
{
	const char *computer_name, *computer_ip;
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
		computer_name = dbi_result_get_string(result, "nombreordenador");
		computer_ip = dbi_result_get_string(result, "ip");

		computer = json_object();
		if (!computer) {
			dbi_result_free(result);
			return -1;
		}

		json_object_set_new(computer, "name", json_string(computer_name));
		json_object_set_new(computer, "type", json_string("computer"));
		json_object_set_new(computer, "id", json_integer(computer_id));
		json_object_set_new(computer, "scope", json_array());
		json_object_set_new(computer, "ip", json_string(computer_ip));
		json_array_append(array, computer);
		json_decref(computer);
	}
	dbi_result_free(result);

	return 0;
}

static int og_dbi_scope_get_room(struct og_dbi *dbi, json_t *array,
				 uint32_t center_id)
{
	char room_name[OG_DB_ROOM_NAME_MAXLEN + 1] = {};
	json_t *room, *room_array;
	const char *msglog;
	dbi_result result;
	uint32_t room_id;

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

		room_array = json_object_get(room, "scope");
		if (!room_array) {
			dbi_result_free(result);
			return -1;
		}

		if (og_dbi_scope_get_computer(dbi, room_array, room_id)) {
			dbi_result_free(result);
			return -1;
		}
	}
	dbi_result_free(result);

	return 0;
}

static int og_dbi_scope_get(struct og_dbi *dbi, json_t *array)
{
	char center_name[OG_DB_CENTER_NAME_MAXLEN + 1] = {};
	json_t *center, *array_room;
	const char *msglog;
	uint32_t center_id;
	dbi_result result;

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

		array_room = json_array();
		if (!array_room) {
			dbi_result_free(result);
			json_decref(center);
			return -1;
		}

		json_object_set_new(center, "name", json_string(center_name));
		json_object_set_new(center, "type", json_string("center"));
		json_object_set_new(center, "id", json_integer(center_id));
		json_object_set_new(center, "scope", array_room);
		json_array_append(array, center);
		json_decref(center);

		if (og_dbi_scope_get_room(dbi, array_room, center_id)) {
			dbi_result_free(result);
			return -1;
		}
	}

	dbi_result_free(result);

	return 0;
}

static int og_cmd_scope_get(json_t *element, struct og_msg_params *params,
			    char *buffer_reply)
{
	struct og_buffer og_buffer = {
		.data = buffer_reply
	};
	json_t *root, *array;
	struct og_dbi *dbi;

	root = json_object();
	if (!root)
		return -1;

	array = json_array();
	if (!array) {
		json_decref(root);
		return -1;
	}
	json_object_set_new(root, "scope", array);

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		json_decref(root);
		return -1;
	}

	if (og_dbi_scope_get(dbi, array)) {
		og_dbi_close(dbi);
		json_decref(root);
		return -1;
	}

	og_dbi_close(dbi);

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

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

	dbi = og_dbi_open(&ogconfig.db);
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
		time.check_stale = true;

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

	dbi = og_dbi_open(&ogconfig.db);
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

static uint32_t og_tm_years_mask(struct tm *tm)
{
	int i, j = 0;

	for (i = 2010; i < 2026; i++, j++) {
		if (tm->tm_year + 1900 == i)
			break;
	}

	return (1 << j);
}

static uint32_t og_tm_months_mask(struct tm *tm)
{
	return 1 << tm->tm_mon;
}

static uint16_t og_tm_hours_mask(struct tm *tm)
{
	return tm->tm_hour >= 12 ? 1 << (tm->tm_hour - 12) : 1 << tm->tm_hour;
}

static uint32_t og_tm_ampm(struct tm *tm)
{
	return tm->tm_hour < 12 ? 0 : 1;
}

static uint32_t og_tm_days_mask(struct tm *tm)
{
	return 1 << (tm->tm_mday - 1);
}

static void og_schedule_time_now(struct og_schedule_time *ogtime)
{
	struct tm *tm;
	time_t now;

	now = time(NULL);
	tm = localtime(&now);

	ogtime->years = og_tm_years_mask(tm);
	ogtime->months = og_tm_months_mask(tm);
	ogtime->weeks = 0;
	ogtime->week_days = 0;
	ogtime->days =  og_tm_days_mask(tm);
	ogtime->hours = og_tm_hours_mask(tm);
	ogtime->am_pm = og_tm_ampm(tm);
	ogtime->minutes = tm->tm_min;
}

static int og_cmd_schedule_create(json_t *element, struct og_msg_params *params)
{
	bool when = false;
	const char *key;
	json_t *value;
	int err = 0;

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
			when = true;
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &params->type);
			params->flags |= OG_REST_PARAM_TYPE;
		}

		if (err < 0)
			return err;
	}

	if (!when) {
		params->time.check_stale = false;
		og_schedule_time_now(&params->time);
		params->flags |= OG_REST_PARAM_TIME_YEARS |
				 OG_REST_PARAM_TIME_MONTHS |
				 OG_REST_PARAM_TIME_WEEKS |
				 OG_REST_PARAM_TIME_WEEK_DAYS |
				 OG_REST_PARAM_TIME_DAYS |
				 OG_REST_PARAM_TIME_HOURS |
				 OG_REST_PARAM_TIME_AM_PM |
				 OG_REST_PARAM_TIME_MINUTES;
	} else {
		params->time.check_stale = true;
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
	bool when = false;
	const char *key;
	json_t *value;
	int err = 0;

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
		} else if (!strcmp(key, "when")) {
			err = og_json_parse_time_params(value, params);
			when = true;
		}

		if (err < 0)
			return err;
	}

	if (!when) {
		params->time.check_stale = false;
		og_schedule_time_now(&params->time);
		params->flags |= OG_REST_PARAM_TIME_YEARS |
				 OG_REST_PARAM_TIME_MONTHS |
				 OG_REST_PARAM_TIME_WEEKS |
				 OG_REST_PARAM_TIME_WEEK_DAYS |
				 OG_REST_PARAM_TIME_DAYS |
				 OG_REST_PARAM_TIME_HOURS |
				 OG_REST_PARAM_TIME_AM_PM |
				 OG_REST_PARAM_TIME_MINUTES;
	} else {
		params->time.check_stale = true;
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

	dbi = og_dbi_open(&ogconfig.db);
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
	int err = 0;

	if (json_typeof(element) != JSON_OBJECT)
		return -1;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "id")) {
			err = og_json_parse_string(value, &params->id);
			params->flags |= OG_REST_PARAM_ID;
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_ID))
		return -1;

	dbi = og_dbi_open(&ogconfig.db);
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
	int err = 0;

	if (element) {
		if (json_typeof(element) != JSON_OBJECT)
			return -1;

		json_object_foreach(element, key, value) {
			if (!strcmp(key, "task")) {
				err = og_json_parse_string(value,
							   &params->task_id);
			} else if (!strcmp(key, "id")) {
				err = og_json_parse_string(value, &params->id);
			}

			if (err < 0)
				return err;
		}
	}

	dbi = og_dbi_open(&ogconfig.db);
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
		err = json_dump_callback(schedule_root, og_json_dump_clients,
					 &og_buffer, 0);

	json_decref(schedule_root);

	return err;
}

#define OG_LIVE_JSON_FILE_PATH "/opt/opengnsys/etc/ogliveinfo.json"

static int og_cmd_oglive_list(char *buffer_reply)
{
	struct og_buffer og_buffer = {
		.data = buffer_reply
	};
	json_error_t json_err;
	json_t *root;

	root = json_load_file(OG_LIVE_JSON_FILE_PATH, 0, &json_err);
	if (!root) {
		syslog(LOG_ERR, "malformed json line %d: %s\n",
		       json_err.line, json_err.text);
		return -1;
	}

	if (json_dump_callback(root, og_json_dump_clients, &og_buffer, 0)) {
		json_decref(root);
		return -1;
	}

	json_decref(root);

	return 0;
}

static int og_cmd_post_center_add(json_t *element,
				  struct og_msg_params *params,
				  char *buffer_reply)
{
	const char *key, *msglog;
	struct og_dbi *dbi;
	dbi_result result;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "name")) {
			err = og_json_parse_string(value, &params->name);
			params->flags |= OG_REST_PARAM_NAME;
		} else if (!strcmp(key, "comment")) {
			err = og_json_parse_string(value, &params->comment);
		}

		if (err < 0)
			return err;
	}

	if (!og_msg_params_validate(params, OG_REST_PARAM_NAME))
		return -1;
	if (!params->comment)
		params->comment = "";

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open conection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT nombrecentro FROM centros WHERE nombrecentro='%s'",
				 params->name);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	if (dbi_result_get_numrows(result) > 0) {
		syslog(LOG_ERR, "Center with name %s already exists\n",
		       params->name);
		dbi_result_free(result);
		og_dbi_close(dbi);
		return -1;
	}
	dbi_result_free(result);

	result = dbi_conn_queryf(dbi->conn,
				 "INSERT INTO centros("
				 "  nombrecentro,"
				 "  comentarios,"
				 "  identidad) VALUES ("
				 "'%s', '%s', 1)",
				 params->name, params->comment);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to add center to database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}

	dbi_result_free(result);
	og_dbi_close(dbi);
	return 0;
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

static int og_client_ok(struct og_client *cli, char *buf_reply)
{
	char buf[OG_MSG_RESPONSE_MAXLEN] = {};
	int len;

	len = snprintf(buf, sizeof(buf),
		       "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n%s",
		       strlen(buf_reply), buf_reply);
	if (len >= (int)sizeof(buf)) {
		syslog(LOG_ERR, "HTTP response to %s:%hu is too large\n",
		       inet_ntoa(cli->addr.sin_addr),
		       ntohs(cli->addr.sin_port));
		return og_server_internal_error(cli);
	}

	send(og_client_socket(cli), buf, strlen(buf), 0);

	return 0;
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

	if (strcmp(cli->auth_token, ogconfig.rest.api_token)) {
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
		    method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (method == OG_METHOD_POST && !root) {
			syslog(LOG_ERR, "command clients with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		switch (method) {
		case OG_METHOD_POST:
			err = og_cmd_post_clients(root, &params);
			break;
		case OG_METHOD_GET:
			err = og_cmd_get_clients(root, &params, buf_reply);
			break;
		default:
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
	} else if (!strncmp(cmd, "client/setup",
			    strlen("client/setup"))) {
		if (method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR,
			       "command client partitions with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_get_client_setup(root, &params, buf_reply);
	} else if (!strncmp(cmd, "client/info",
			    strlen("client/info"))) {
		if (method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}
		if (!root) {
			syslog(LOG_ERR,
			       "command client info with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_get_client_info(root, &params, buf_reply);
	} else if (!strncmp(cmd, "client/add", strlen("client/add"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR,
			       "command client info with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_post_client_add(root, &params, buf_reply);
	} else if (!strncmp(cmd, "client/delete", strlen("client/delete"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR,
			       "command client delete with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_post_client_delete(root, &params);
	} else if (!strncmp(cmd, "wol", strlen("wol"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command wol with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_wol(root, &params);
	} else if (!strncmp(cmd, "shell/run", strlen("shell/run"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command run with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_run_post(root, &params);
	} else if (!strncmp(cmd, "shell/output", strlen("shell/output"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command output with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_run_get(root, &params, buf_reply);
	} else if (!strncmp(cmd, "session", strlen("session"))) {
		if (method != OG_METHOD_POST && method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command session with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		if (method == OG_METHOD_POST)
			err = og_cmd_session(root, &params);
		else
			err = og_cmd_get_session(root, &params, buf_reply);
	} else if (!strncmp(cmd, "scopes", strlen("scopes"))) {
		if (method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (root) {
			syslog(LOG_ERR, "command scopes with payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_scope_get(root, &params, buf_reply);
	} else if (!strncmp(cmd, "poweroff", strlen("poweroff"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command poweroff with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_poweroff(root, &params);
	} else if (!strncmp(cmd, "reboot", strlen("reboot"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command reboot with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_reboot(root, &params);
	} else if (!strncmp(cmd, "mode", strlen("mode"))) {
		if (method != OG_METHOD_GET && method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (method == OG_METHOD_POST && !root) {
			syslog(LOG_ERR, "command mode with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		if (method == OG_METHOD_GET)
			err = og_cmd_get_modes(root, &params, buf_reply);
		else if (method == OG_METHOD_POST)
			err = og_cmd_post_modes(root, &params);
	} else if (!strncmp(cmd, "stop", strlen("stop"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command stop with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_stop(root, &params);
	} else if (!strncmp(cmd, "refresh", strlen("refresh"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command refresh with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_refresh(root, &params);
	} else if (!strncmp(cmd, "hardware", strlen("hardware"))) {
		if (method != OG_METHOD_GET && method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command hardware with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		if (method == OG_METHOD_GET)
			err = og_cmd_get_hardware(root, &params, buf_reply);
		else if (method == OG_METHOD_POST)
			err = og_cmd_hardware(root, &params);
	} else if (!strncmp(cmd, "software", strlen("software"))) {
		if (method != OG_METHOD_POST && method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command software with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		if (method == OG_METHOD_POST)
			err = og_cmd_software(root, &params);
		else
			err = og_cmd_get_software(root, &params, buf_reply);
	} else if (!strncmp(cmd, "images", strlen("images"))) {
		if (method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (root) {
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_images(buf_reply);
	} else if (!strncmp(cmd, "image/create", strlen("image/create"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_create_image(root, &params);
	} else if (!strncmp(cmd, "image/restore", strlen("image/restore"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_restore_image(root, &params);
	} else if (!strncmp(cmd, "setup", strlen("setup"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_setup(root, &params);
	} else if (!strncmp(cmd, "run/schedule", strlen("run/schedule"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command create with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_run_schedule(root, &params);
	} else if (!strncmp(cmd, "task/run", strlen("task/run"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_task_post(root, &params);
	} else if (!strncmp(cmd, "schedule/create",
			    strlen("schedule/create"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_schedule_create(root, &params);
	} else if (!strncmp(cmd, "schedule/delete",
			    strlen("schedule/delete"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_schedule_delete(root, &params);
	} else if (!strncmp(cmd, "schedule/update",
			    strlen("schedule/update"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		if (!root) {
			syslog(LOG_ERR, "command task with no payload\n");
			err = og_client_bad_request(cli);
			goto err_process_rest_payload;
		}
		err = og_cmd_schedule_update(root, &params);
	} else if (!strncmp(cmd, "schedule/get",
			    strlen("schedule/get"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_schedule_get(root, &params, buf_reply);
	} else if (!strncmp(cmd, "oglive/list",
			    strlen("oglive/list"))) {
		if (method != OG_METHOD_GET) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_oglive_list(buf_reply);
	} else if (!strncmp(cmd, "center/add",
			    strlen("center/add"))) {
		if (method != OG_METHOD_POST) {
			err = og_client_method_not_found(cli);
			goto err_process_rest_payload;
		}

		err = og_cmd_post_center_add(root, &params, buf_reply);
	} else {
		syslog(LOG_ERR, "unknown command: %.32s ...\n", cmd);
		err = og_client_not_found(cli);
	}

	json_decref(root);

	if (err < 0)
		return og_client_bad_request(cli);

	return og_client_ok(cli, buf_reply);

err_process_rest_payload:
	json_decref(root);

	return err;
}
