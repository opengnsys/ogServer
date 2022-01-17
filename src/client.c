/*
 * Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ogAdmServer.h"
#include "cfg.h"
#include "dbi.h"
#include "utils.h"
#include "list.h"
#include "rest.h"
#include "json.h"
#include "schedule.h"
#include <syslog.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <jansson.h>
#include <time.h>

static int og_status_session_start(struct og_client *cli)
{
	switch (cli->status) {
	case OG_CLIENT_STATUS_LINUX:
		cli->status = OG_CLIENT_STATUS_LINUX_SESSION;
		break;
	case OG_CLIENT_STATUS_WIN:
		cli->status = OG_CLIENT_STATUS_WIN_SESSION;
		break;
	default:
		syslog(LOG_ERR, "%s:%d: invalid session start for status %d\n",
		       __FILE__, __LINE__, cli->status);
		return -1;
	}
	return 0;
}

static int og_status_session_stop(struct og_client *cli)
{
	switch (cli->status) {
	case OG_CLIENT_STATUS_WIN_SESSION:
		cli->status = OG_CLIENT_STATUS_WIN;
		break;
	case OG_CLIENT_STATUS_LINUX_SESSION:
		cli->status = OG_CLIENT_STATUS_LINUX;
		break;
	default:
		syslog(LOG_ERR, "%s:%d: invalid session stop for status %d\n",
		       __FILE__, __LINE__, cli->status);
		return -1;
	}
	return 0;
}

static int og_resp_early_hints(struct og_client *cli, json_t *data)
{
	const char *event, *action, *user;
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "event")) {
			err = og_json_parse_string(value, &event);
			if (err < 0)
				return err;
		} else if (!strcmp(key, "action")) {
			err = og_json_parse_string(value, &action);
			if (err < 0)
				return err;
		} else if (!strcmp(key, "user")) {
			err = og_json_parse_string(value, &user);
			if (err < 0)
				return err;
		}
	}

	syslog(LOG_INFO, "Received event %s %s %s\n", event, action, user);

	if (strncmp(event, "session", strlen("session")))
		return -1;

	if (!strncmp(action, "start", strlen("start")))
		return og_status_session_start(cli);
	if (!strncmp(action, "stop", strlen("stop")))
		return og_status_session_stop(cli);

	syslog(LOG_ERR, "Invalid action for event %s %s %s\n", event, action, user);
	return -1;
}

static int og_resp_probe(struct og_client *cli, json_t *data)
{
	const char *status = NULL;
	const char *key;
	uint32_t speed;
	json_t *value;
	int err = 0;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "status")) {
			err = og_json_parse_string(value, &status);
			if (err < 0)
				return err;
		} else if (!strcmp(key, "speed")) {
			err = og_json_parse_uint(value, &speed);
			if (err < 0)
				return err;
			cli->speed = speed;
		}
	}

	if (!strcmp(status, "BSY"))
		cli->status = OG_CLIENT_STATUS_BUSY;
	else if (!strcmp(status, "OPG"))
		cli->status = OG_CLIENT_STATUS_OGLIVE;
	else if (!strcmp(status, "VDI"))
		cli->status = OG_CLIENT_STATUS_VIRTUAL;

	return status ? 0 : -1;
}

static int og_resp_shell_run(struct og_client *cli, json_t *data)
{
	const char *output = NULL;
	const char *key;
	json_t *value;
	int err = -1;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "out")) {
			err = og_json_parse_string(value, &output);
			if (err < 0)
				return err;
		}
	}

	if (!output) {
		syslog(LOG_ERR, "%s:%d: malformed json response\n",
		       __FILE__, __LINE__);
		return -1;
	}

	free((void *)cli->shell_output);
	cli->shell_output = strdup(output);

	return 0;
}

struct og_computer_legacy  {
	char center[OG_DB_INT_MAXLEN + 1];
	char id[OG_DB_INT_MAXLEN + 1];
	char hardware[8192];
};

static int og_resp_hardware(json_t *data, struct og_client *cli)
{
	struct og_computer_legacy legacy = {};
	struct og_computer computer = {};
	const char *hardware = NULL;
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err = 0;
	bool res;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "hardware")) {
			err = og_json_parse_string(value, &hardware);
			if (err < 0)
				return -1;
		}
	}

	if (!hardware) {
		syslog(LOG_ERR, "malformed response json\n");
		return -1;
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	err = og_dbi_get_computer_info(dbi, &computer, cli->addr.sin_addr);
	if (err < 0) {
		og_dbi_close(dbi);
		return -1;
	}

	snprintf(legacy.center, sizeof(legacy.center), "%d", computer.center);
	snprintf(legacy.id, sizeof(legacy.id), "%d", computer.id);
	snprintf(legacy.hardware, sizeof(legacy.hardware), "%s", hardware);

	res = actualizaHardware(dbi, legacy.hardware, legacy.id, computer.name,
				legacy.center);
	og_dbi_close(dbi);

	if (!res) {
		syslog(LOG_ERR, "Problem updating client configuration\n");
		return -1;
	}

	return 0;
}

struct og_software_legacy {
	char software[8192];
	char center[OG_DB_INT_MAXLEN + 1];
	char part[OG_DB_SMALLINT_MAXLEN + 1];
	char id[OG_DB_INT_MAXLEN + 1];
};

static int og_resp_software(json_t *data, struct og_client *cli)
{
	struct og_software_legacy legacy = {};
	struct og_computer computer = {};
	const char *partition = NULL;
	const char *software = NULL;
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err = 0;
	bool res;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "software"))
			err = og_json_parse_string(value, &software);
		else if (!strcmp(key, "partition"))
			err = og_json_parse_string(value, &partition);

		if (err < 0)
			return -1;
	}

	if (!software || !partition) {
		syslog(LOG_ERR, "malformed response json\n");
		return -1;
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	err = og_dbi_get_computer_info(dbi, &computer, cli->addr.sin_addr);
	if (err < 0) {
		og_dbi_close(dbi);
		return -1;
	}

	snprintf(legacy.software, sizeof(legacy.software), "%s", software);
	snprintf(legacy.part, sizeof(legacy.part), "%s", partition);
	snprintf(legacy.id, sizeof(legacy.id), "%d", computer.id);
	snprintf(legacy.center, sizeof(legacy.center), "%d", computer.center);

	res = actualizaSoftware(dbi, legacy.software, legacy.part, legacy.id,
				computer.name, legacy.center);
	og_dbi_close(dbi);

	if (!res) {
		syslog(LOG_ERR, "Problem updating client configuration\n");
		return -1;
	}

	return 0;
}

#define OG_PARAMS_RESP_REFRESH	(OG_PARAM_PART_DISK |		\
				 OG_PARAM_PART_NUMBER |		\
				 OG_PARAM_PART_CODE |		\
				 OG_PARAM_PART_FILESYSTEM |	\
				 OG_PARAM_PART_OS |		\
				 OG_PARAM_PART_SIZE |		\
				 OG_PARAM_PART_USED_SIZE)

static int og_json_parse_partition_array(json_t *value,
					 struct og_partition *partitions)
{
	json_t *element;
	int i, err;

	if (json_typeof(value) != JSON_ARRAY)
		return -1;

	for (i = 0; i < json_array_size(value) && i < OG_PARTITION_MAX; i++) {
		element = json_array_get(value, i);

		err = og_json_parse_partition(element, &partitions[i],
					      OG_PARAMS_RESP_REFRESH);
		if (err < 0)
			return err;
	}

	return 0;
}

static int og_dbi_queue_autorun(uint32_t computer_id, uint32_t proc_id)
{
	struct og_task dummy_task = {
		.scope		= computer_id,
		.type_scope	= AMBITO_ORDENADORES,
		.procedure_id	= proc_id,
	};
	struct og_dbi *dbi;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database "
				"(%s:%d)\n", __func__, __LINE__);
		return -1;
	}
	if (og_dbi_queue_procedure(dbi, &dummy_task)) {
		og_dbi_close(dbi);
		return -1;
	}
	og_dbi_close(dbi);

	return 0;
}

static int og_resp_refresh(json_t *data, struct og_client *cli)
{
	struct og_partition partitions[OG_PARTITION_MAX] = {};
	struct og_partition disks[OG_DISK_MAX] = {};
	const char *serial_number = NULL;
	struct og_computer computer = {};
	const char *status = NULL;
	char cfg[4096] = {};
	struct og_dbi *dbi;
	const char *key;
	unsigned int i;
	json_t *value;
	int err = 0;
	bool res;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "disk_setup")) {
			err = og_json_parse_partition_array(value, disks);
		} else if (!strcmp(key, "partition_setup")) {
			err = og_json_parse_partition_array(value, partitions);
		} else if (!strcmp(key, "serial_number")) {
			err = og_json_parse_string(value, &serial_number);
		} else if (!strcmp(key, "status")) {
			err = og_json_parse_string(value, &status);
		}

		if (err < 0)
			return err;
	}

	if (status) {
		if (!strncmp(status, "LINUX", strlen("LINUX"))) {
			cli->status = OG_CLIENT_STATUS_LINUX;
		} else if (!strncmp(status, "WIN", strlen("WIN"))) {
			cli->status = OG_CLIENT_STATUS_WIN;
		}
		return 0;
	}

	if (strlen(serial_number) > 0)
		snprintf(cfg, sizeof(cfg), "ser=%s\n", serial_number);

	for (i = 0; i < OG_DISK_MAX; i++) {
		if (!disks[i].disk || !disks[i].number ||
		    !disks[i].code || !disks[i].filesystem ||
		    !disks[i].os || !disks[i].size ||
		    !disks[i].used_size)
			continue;

		snprintf(cfg + strlen(cfg), sizeof(cfg) - strlen(cfg),
			 "disk=%s\tpar=%s\tcpt=%s\tfsi=%s\tsoi=%s\ttam=%s\tuso=%s\tdtype=%s\n",
			 disks[i].disk, disks[i].number,
			 disks[i].code, disks[i].filesystem,
			 disks[i].os, disks[i].size,
			 disks[i].used_size, disks[i].disk_type);
	}

	for (i = 0; i < OG_PARTITION_MAX; i++) {
		if (!partitions[i].disk || !partitions[i].number ||
		    !partitions[i].code || !partitions[i].filesystem ||
		    !partitions[i].os || !partitions[i].size ||
		    !partitions[i].used_size)
			continue;

		snprintf(cfg + strlen(cfg), sizeof(cfg) - strlen(cfg),
			 "disk=%s\tpar=%s\tcpt=%s\tfsi=%s\tsoi=%s\ttam=%s\tuso=%s\n",
			 partitions[i].disk, partitions[i].number,
			 partitions[i].code, partitions[i].filesystem,
			 partitions[i].os, partitions[i].size,
			 partitions[i].used_size);
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
				  __func__, __LINE__);
		return -1;
	}

	err = og_dbi_get_computer_info(dbi, &computer, cli->addr.sin_addr);
	if (err < 0) {
		og_dbi_close(dbi);
		return -1;
	}

	res = actualizaConfiguracion(dbi, cfg, computer.id);
	og_dbi_close(dbi);

	if (!res) {
		syslog(LOG_ERR, "Problem updating client configuration\n");
		return -1;
	}

	if (!cli->autorun && computer.procedure_id) {
		cli->autorun = true;

		if (og_dbi_queue_autorun(computer.id, computer.procedure_id))
			return -1;
	}

	return 0;
}

static int update_image_info(struct og_dbi *dbi, const char *image_id,
			     const char *clonator, const char *compressor,
			     const char *filesystem, const uint64_t datasize)
{
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn,
		"UPDATE imagenes"
		"   SET clonator='%s', compressor='%s',"
		"       filesystem='%s', datasize=%lld"
		" WHERE idimagen=%s", clonator, compressor, filesystem,
		datasize, image_id);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	return 0;
}

static int og_resp_image_create(json_t *data, struct og_client *cli)
{
	struct og_software_legacy soft_legacy;
	struct og_image_legacy img_legacy;
	struct og_computer computer = {};
	const char *compressor = NULL;
	const char *filesystem = NULL;
	const char *partition = NULL;
	const char *software = NULL;
	const char *image_id = NULL;
	const char *clonator = NULL;
	const char *disk = NULL;
	const char *code = NULL;
	const char *name = NULL;
	const char *repo = NULL;
	uint64_t datasize = 0;
	struct og_dbi *dbi;
	const char *key;
	json_t *value;
	int err = 0;
	bool res;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "software"))
			err = og_json_parse_string(value, &software);
		else if (!strcmp(key, "partition"))
			err = og_json_parse_string(value, &partition);
		else if (!strcmp(key, "disk"))
			err = og_json_parse_string(value, &disk);
		else if (!strcmp(key, "code"))
			err = og_json_parse_string(value, &code);
		else if (!strcmp(key, "id"))
			err = og_json_parse_string(value, &image_id);
		else if (!strcmp(key, "name"))
			err = og_json_parse_string(value, &name);
		else if (!strcmp(key, "repository"))
			err = og_json_parse_string(value, &repo);
		else if (!strcmp(key, "clonator"))
			err = og_json_parse_string(value, &clonator);
		else if (!strcmp(key, "compressor"))
			err = og_json_parse_string(value, &compressor);
		else if (!strcmp(key, "filesystem"))
			err = og_json_parse_string(value, &filesystem);
		else if (!strcmp(key, "datasize"))
			err = og_json_parse_uint64(value, &datasize);

		if (err < 0)
			return err;
	}

	if (!software || !partition || !disk || !code || !image_id || !name ||
	    !repo || !clonator || !compressor || !filesystem || !datasize) {
		syslog(LOG_ERR, "malformed response json\n");
		return -1;
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	err = og_dbi_get_computer_info(dbi, &computer, cli->addr.sin_addr);
	if (err < 0) {
		og_dbi_close(dbi);
		return -1;
	}

	snprintf(soft_legacy.center, sizeof(soft_legacy.center), "%d",
		 computer.center);
	snprintf(soft_legacy.software, sizeof(soft_legacy.software), "%s",
		 software);
	snprintf(img_legacy.image_id, sizeof(img_legacy.image_id), "%s",
		 image_id);
	snprintf(soft_legacy.id, sizeof(soft_legacy.id), "%d", computer.id);
	snprintf(img_legacy.part, sizeof(img_legacy.part), "%s", partition);
	snprintf(img_legacy.disk, sizeof(img_legacy.disk), "%s", disk);
	snprintf(img_legacy.code, sizeof(img_legacy.code), "%s", code);
	snprintf(img_legacy.name, sizeof(img_legacy.name), "%s", name);
	snprintf(img_legacy.repo, sizeof(img_legacy.repo), "%s", repo);

	res = actualizaSoftware(dbi,
				soft_legacy.software,
				img_legacy.part,
				soft_legacy.id,
				computer.name,
				soft_legacy.center);
	if (!res) {
		og_dbi_close(dbi);
		syslog(LOG_ERR, "Problem updating client configuration\n");
		return -1;
	}

	res = actualizaCreacionImagen(dbi,
				      img_legacy.image_id,
				      img_legacy.disk,
				      img_legacy.part,
				      img_legacy.code,
				      img_legacy.repo,
				      soft_legacy.id);
	if (!res) {
		og_dbi_close(dbi);
		syslog(LOG_ERR, "Problem updating client configuration\n");
		return -1;
	}

	res = update_image_info(dbi, image_id, clonator, compressor,
				filesystem, datasize);
	og_dbi_close(dbi);

	if (res) {
		syslog(LOG_ERR, "Problem updating image info\n");
		return -1;
	}

	return 0;
}

static int og_resp_image_restore(json_t *data, struct og_client *cli)
{
	struct og_software_legacy soft_legacy;
	struct og_image_legacy img_legacy;
	struct og_computer computer = {};
	const char *partition = NULL;
	const char *image_id = NULL;
	const char *disk = NULL;
	const char *msglog;
	struct og_dbi *dbi;
	dbi_result result;
	const char *key;
	json_t *value;
	int err = 0;

	if (json_typeof(data) != JSON_OBJECT)
		return -1;

	json_object_foreach(data, key, value) {
		if (!strcmp(key, "partition"))
			err = og_json_parse_string(value, &partition);
		else if (!strcmp(key, "disk"))
			err = og_json_parse_string(value, &disk);
		else if (!strcmp(key, "image_id"))
			err = og_json_parse_string(value, &image_id);

		if (err < 0)
			return err;
	}

	if (!partition || !disk || !image_id) {
		syslog(LOG_ERR, "malformed response json\n");
		return -1;
	}

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		syslog(LOG_ERR, "cannot open connection database (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT idperfilsoft FROM imagenes "
				 " WHERE idimagen='%s'", image_id);
	if (!result) {
		og_dbi_close(dbi);
		syslog(LOG_ERR, "failed to query database\n");
		return -1;
	}
	if (!dbi_result_next_row(result)) {
		dbi_result_free(result);
		og_dbi_close(dbi);
		syslog(LOG_ERR, "software profile does not exist in database\n");
		return -1;
	}
	snprintf(img_legacy.software_id, sizeof(img_legacy.software_id),
		 "%d", dbi_result_get_uint(result, "idperfilsoft"));
	dbi_result_free(result);

	err = og_dbi_get_computer_info(dbi, &computer, cli->addr.sin_addr);
	if (err < 0) {
		og_dbi_close(dbi);
		return -1;
	}

	snprintf(img_legacy.image_id, sizeof(img_legacy.image_id), "%s",
		 image_id);
	snprintf(img_legacy.part, sizeof(img_legacy.part), "%s", partition);
	snprintf(img_legacy.disk, sizeof(img_legacy.disk), "%s", disk);
	snprintf(soft_legacy.id, sizeof(soft_legacy.id), "%d", computer.id);

	result = dbi_conn_queryf(dbi->conn,
				 "UPDATE ordenadores_particiones"
				 "   SET idimagen=%s, idperfilsoft=%s, fechadespliegue=NOW(),"
				 "       revision=(SELECT revision FROM imagenes WHERE idimagen=%s),"
				 "       idnombreso=IFNULL((SELECT idnombreso FROM perfilessoft WHERE idperfilsoft=%s),0)"
				 " WHERE idordenador=%s AND numdisk=%s AND numpar=%s",
				 img_legacy.image_id, img_legacy.software_id,
				 img_legacy.image_id, img_legacy.software_id,
				 soft_legacy.id, img_legacy.disk, img_legacy.part);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to update database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		og_dbi_close(dbi);
		return -1;
	}
	dbi_result_free(result);
	og_dbi_close(dbi);

	return 0;
}

static int og_agent_http_response_code(const char *buf)
{
	if (!strncmp(buf, "HTTP/1.0 200 OK", strlen("HTTP/1.0 200 OK"))) {
		return 200;
	} else if (!strncmp(buf, "HTTP/1.0 202 Accepted",
			    strlen("HTTP/1.0 202 Accepted"))) {
		return 202;
	} else if (!strncmp(buf, "HTTP/1.0 400 Bad Request",
			    strlen("HTTP/1.0 400 Bad Request"))) {
		return 400;
	} else if (!strncmp(buf, "HTTP/1.0 500 Internal Server Error",
			    strlen("HTTP/1.0 500 Internal Server Error"))) {
		return 500;
	} else if (!strncmp(buf, "HTTP/1.0 503 Service Unavailable",
			    strlen("HTTP/1.0 503 Service Unavailable"))) {
		return 503;
	} else if (!strncmp(buf, "HTTP/1.0 103 Early Hints",
			    strlen("HTTP/1.0 103 Early Hints"))) {
		return 103;
	}

	return -1;
}

int og_agent_state_process_response(struct og_client *cli)
{
	int ret, err = -1, code;
	json_error_t json_err;
	bool success;
	json_t *root;
	char *body;

	code = og_agent_http_response_code(cli->buf);
	switch (code) {
	case 103:
	case 200:
		ret = 0;
		success = true;
		break;
	case 202:
		ret = 1;
		success = true;
		break;
	case 400:
		ret = -1;
		success = false;
		syslog(LOG_ERR, "Client %s:%hu reports malformed HTTP request from server\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		break;
	case 500:
		ret = 0;
		success = false;
		cli->last_cmd = OG_CMD_UNSPEC;
		syslog(LOG_ERR, "Client %s:%hu reports failure to process command\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		/* ... cancel pending actions related to this task for this client here */
		break;
	case 503:
		ret = 1;
		success = false;
		syslog(LOG_ERR, "Client %s:%hu is busy to process command\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		break;
	default:
		ret = -1;
		success = false;
		syslog(LOG_ERR, "Client %s:%hu reports unknown HTTP response code\n",
		       inet_ntoa(cli->addr.sin_addr), ntohs(cli->addr.sin_port));
		break;
	}

	if (code != 200 && code != 103) {
		og_dbi_update_action(cli->last_cmd_id, success);
		cli->last_cmd_id = 0;
		return ret;
	}

	if (!cli->content_length) {
		og_dbi_update_action(cli->last_cmd_id, true);
		cli->last_cmd_id = 0;
		cli->last_cmd = OG_CMD_UNSPEC;
		return 0;
	}

	body = strstr(cli->buf, "\r\n\r\n") + 4;

	root = json_loads(body, 0, &json_err);
	if (!root) {
		syslog(LOG_ERR, "%s:%d: malformed json line %d: %s\n",
		       __FILE__, __LINE__, json_err.line, json_err.text);
		return -1;
	}

	if (code == 103) {
		err = og_resp_early_hints(cli, root);
		json_decref(root);
		return err;
	}

	switch (cli->last_cmd) {
	case OG_CMD_PROBE:
		err = og_resp_probe(cli, root);
		break;
	case OG_CMD_SHELL_RUN:
		err = og_resp_shell_run(cli, root);
		break;
	case OG_CMD_HARDWARE:
		err = og_resp_hardware(root, cli);
		break;
	case OG_CMD_SOFTWARE:
		err = og_resp_software(root, cli);
		break;
	case OG_CMD_REFRESH:
		err = og_resp_refresh(root, cli);
		break;
	case OG_CMD_SETUP:
		err = og_resp_refresh(root, cli);
		break;
	case OG_CMD_IMAGE_CREATE:
		err = og_resp_image_create(root, cli);
		break;
	case OG_CMD_IMAGE_RESTORE:
		err = og_resp_image_restore(root, cli);
		break;
	default:
		err = -1;
		break;
	}

	json_decref(root);

	if (err < 0) {
		err = 0;
		success = false;
		/* ... cancel pending actions related to this task for this client here */
	}

	og_dbi_update_action(cli->last_cmd_id, success);
	cli->last_cmd_id = 0;
	cli->last_cmd = OG_CMD_UNSPEC;

	return err;
}
