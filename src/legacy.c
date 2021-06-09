/*
 * Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include <jansson.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <syslog.h>

#include "json.h"
#include "rest.h"
#include "legacy.h"

#define LEGACY_CMD_MAX 4096

static const char *og_cmd_wol_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	const json_t *root = cmd->json;
	const char *wol_type;
	uint32_t type;
	int len;

	wol_type = json_string_value(json_object_get(root, "type"));
	if (!wol_type)
		return NULL;

	if (!strcmp(wol_type, "broadcast"))
		type = 1;
	else
		type = 2;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd), "nfn=Arrancar\rmar=%u", type);
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_poweroff_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	int len;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd), "nfn=Apagar");
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_reboot_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	int len;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd), "nfn=Reiniciar");
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_session_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	const json_t *root = cmd->json;
	const char *dsk, *par;
	int len;

	dsk = json_string_value(json_object_get(root, "disk"));
	if (!dsk)
		return NULL;
	par = json_string_value(json_object_get(root, "part"));
	if (!par)
		return NULL;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd),
		       "nfn=IniciarSesion\rdsk=%s\rpar=%s",
		       dsk, par);
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_software_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	const json_t *root = cmd->json;
	const char *dsk, *par;
	int len;

	dsk = json_string_value(json_object_get(root, "disk"));
	if (!dsk)
		return NULL;
	par = json_string_value(json_object_get(root, "partition"));
	if (!par)
		return NULL;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd),
		       "nfn=InventarioSoftware\rdsk=%s\rpar=%s",
		       dsk, par);
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_hardware_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	int len;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd),
		       "nfn=InventarioHardware");
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_shell_run_to_legacy(struct og_cmd_json *cmd)
{
	const json_t *root = cmd->json;
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	const char *scp;
	int len;

	scp = json_string_value(json_object_get(root, "run"));
	if (!scp)
		return NULL;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd),
		       "nfn=EjecutarScript\rscp=%s", scp);
	if (len >= (int)sizeof(legacy_cmd)) {
		syslog(LOG_ERR, "script payload too large (%s:%d)\n",
		       __func__, __LINE__);
		return NULL;
	}

	return strdup(legacy_cmd);
}

static char *og_cmd_image_create_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	struct og_msg_params params = {};
	json_t *root = cmd->json;
	int len;

	if (og_json_parse_create_image(root, &params) < 0)
		return NULL;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd),
		       "nfn=CrearImagen\rdsk=%s\rpar=%s\rcpt=%s\ridi=%s\rnci=%s\ripr=%s",
		       params.disk, params.partition, params.code, params.id,
		       params.name, params.repository);
	if (len >= (int)sizeof(legacy_cmd))
		return NULL;

	return strdup(legacy_cmd);
}

static const char *og_cmd_image_restore_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	struct og_msg_params params = {};
	json_t *root = cmd->json;
	int len;

	if (og_json_parse_restore_image(root, &params) < 0)
		return NULL;

	len = snprintf(legacy_cmd, sizeof(legacy_cmd),
		       "nfn=RestaurarImagen\rdsk=%s\rpar=%s\ridi=%s\rnci=%s\ripr=%s\rifs=%s\rptc=%s",
		       params.disk, params.partition, params.id, params.name,
		       params.repository, params.profile, params.type);
	if (len >= (int)sizeof(legacy_cmd)) {
		return NULL;
	}

	return strdup(legacy_cmd);
}

static const char *og_cmd_setup_to_legacy(struct og_cmd_json *cmd)
{
	char legacy_cmd[LEGACY_CMD_MAX + 1] = {};
	uint32_t bufsiz = sizeof(legacy_cmd);
	const char *dsk, *ttp, *che, *tch;
	struct og_msg_params params = {};
	json_t *partition_setup, *value;
	const json_t *root = cmd->json;
	uint32_t consumed = 0;
	size_t index;
	int len;

	dsk = json_string_value(json_object_get(root, "disk"));
	if (!dsk)
		return NULL;
	ttp = json_string_value(json_object_get(root, "type"));
	if (!ttp)
		return NULL;
	che = json_string_value(json_object_get(root, "cache"));
	if (!che)
		return NULL;
	tch = json_string_value(json_object_get(root, "cache_size"));
	if (!tch)
		return NULL;

	len = snprintf(legacy_cmd + consumed, bufsiz, "nfn=Configurar\rttp=%s\rdsk=%s\rcfg=dis=%s*che=%s*tch=%s!",
		   ttp, dsk, dsk, che, tch);
	if (len >= bufsiz)
		return NULL;
	consumed += len;
	if (consumed < bufsiz)
		bufsiz -= len;

	partition_setup = json_object_get(root, "partition_setup");
	if (!partition_setup)
		return NULL;
	if (og_json_parse_partition_setup(partition_setup, &params) < 0)
		return NULL;

	json_array_foreach(partition_setup, index, value) {
		len = snprintf(legacy_cmd + consumed, bufsiz, "par=%s*cpt=%s*sfi=%s*tam=%s*ope=%s%%",
			       params.partition_setup[index].number,
			       params.partition_setup[index].code,
			       params.partition_setup[index].filesystem,
			       params.partition_setup[index].size,
			       params.partition_setup[index].format);
		if (len >= bufsiz)
			return NULL;
		consumed += len;
		if (consumed < bufsiz)
			bufsiz -= len;
	}

	return strdup(legacy_cmd);
}

const char *og_msg_params_to_legacy(struct og_cmd_json *cmd)
{
	const char *legacy_cmd = NULL;

	if (!strncmp(cmd->type, "wol", strlen("wol")))
		legacy_cmd = og_cmd_wol_to_legacy(cmd);
	else if (!strncmp(cmd->type, "poweroff", strlen("poweroff")))
		legacy_cmd = og_cmd_poweroff_to_legacy(cmd);
	else if (!strncmp(cmd->type, "reboot", strlen("reboot")))
		legacy_cmd = og_cmd_reboot_to_legacy(cmd);
	else if (!strncmp(cmd->type, "session", strlen("session")))
		legacy_cmd = og_cmd_session_to_legacy(cmd);
	else if (!strncmp(cmd->type, "software", strlen("software")))
		legacy_cmd = og_cmd_software_to_legacy(cmd);
	else if (!strncmp(cmd->type, "hardware", strlen("hardware")))
		legacy_cmd = og_cmd_hardware_to_legacy(cmd);
	else if (!strncmp(cmd->type, "run", strlen("run")))
		legacy_cmd = og_cmd_shell_run_to_legacy(cmd);
	else if (!strncmp(cmd->type, "image_create", strlen("image_create")))
		legacy_cmd = og_cmd_image_create_to_legacy(cmd);
	else if (!strncmp(cmd->type, "image_restore", strlen("image_restore")))
		legacy_cmd = og_cmd_image_restore_to_legacy(cmd);
	else if (!strncmp(cmd->type, "setup", strlen("setup")))
		legacy_cmd = og_cmd_setup_to_legacy(cmd);

	if (!legacy_cmd) {
		syslog(LOG_ERR, "failed to translate command %s (%s:%d)\n",
		       cmd->type, __func__, __LINE__);
	}

	return legacy_cmd;
}
