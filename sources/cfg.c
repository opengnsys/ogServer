/*
 * Copyright (C) 2020 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, version 3.
 */

#include "json.h"
#include "cfg.h"
#include "ogAdmServer.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>

static int parse_json_rest(struct og_server_cfg *cfg, json_t *element)
{
	const char *key;
	json_t *value;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "ip")) {
			if (og_json_parse_string(value, &cfg->rest.ip) < 0)
				return -1;
		} else if (!strcmp(key, "port")) {
			if (og_json_parse_string(value, &cfg->rest.port) < 0)
				return -1;
		} else if (!strcmp(key, "api_token")) {
			if (og_json_parse_string(value, &cfg->rest.api_token) < 0)
				return -1;
		} else {
			syslog(LOG_ERR, "unknown key `%s' in rest\n", key);
			return -1;
		}
	}

	return 0;
}

static int parse_json_db(struct og_server_cfg *cfg, json_t *element)
{
	const char *key;
	json_t *value;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "ip")) {
			if (og_json_parse_string(value, &cfg->db.ip) < 0)
				return -1;
		} else if (!strcmp(key, "user")) {
			if (og_json_parse_string(value, &cfg->db.user) < 0)
				return -1;
		} else if (!strcmp(key, "pass")) {
			if (og_json_parse_string(value, &cfg->db.pass) < 0)
				return -1;
		} else if (!strcmp(key, "name")) {
			if (og_json_parse_string(value, &cfg->db.name) < 0)
				return -1;
		} else {
			syslog(LOG_ERR, "unknown key `%s' in db\n", key);
			return -1;
		}
	}

	return 0;
}

static int parse_json_wol(struct og_server_cfg *cfg, json_t *element)
{
	const char *key;
	json_t *value;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "interface")) {
			if (og_json_parse_string(value, &cfg->wol.interface) < 0)
				return -1;
		} else {
			syslog(LOG_ERR, "unknown key `%s' in wol\n", key);
			return -1;
		}
	}

	return 0;
}

#define OG_SERVER_CFG_REST	(1 << 0)
#define OG_SERVER_CFG_DB	(1 << 1)
#define OG_SERVER_CFG_WOL	(1 << 2)

int parse_json_config(const char *filename, struct og_server_cfg *cfg)
{
	json_t *root, *value;
	uint32_t flags = 0;
	json_error_t err;
	const char *key;
	char buf[4096];
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		syslog(LOG_ERR, "Cannot open %s", filename);
		return -1;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0 || ret == sizeof(buf)) {
		syslog(LOG_ERR, "Cannot read from %s", filename);
		return -1;
	}

	root = json_loads(buf, 0, &err);
	if (!root) {
		syslog(LOG_ERR, "Cannot parse malformed json file");
		return -1;
	}

	json_object_foreach(root, key, value) {
		if (!strcmp(key, "rest")) {
			if (parse_json_rest(cfg, value) < 0)
				return -1;

			flags |= OG_SERVER_CFG_REST;
		} else if (!strcmp(key, "wol")) {
			if (parse_json_wol(cfg, value) < 0)
				return -1;

			flags |= OG_SERVER_CFG_WOL;
		} else if (!strcmp(key, "database")) {
			if (parse_json_db(cfg, value) < 0)
				return -1;

			flags |= OG_SERVER_CFG_DB;
		} else {
			syslog(LOG_ERR, "unknown key `%s' in %s\n",
			       key, filename);
			ret = -1;
		}
	}

	if ((flags & OG_SERVER_CFG_REST) &&
	    (flags & OG_SERVER_CFG_DB) &&
	    (flags & OG_SERVER_CFG_WOL)) {
		ret = 0;
	} else {
		syslog(LOG_ERR, "Missing attributes in json file");
		ret = -1;
	}

	json_decref(root);

	return ret;
}

void from_json_to_legacy(struct og_server_cfg *cfg)
{
	snprintf(servidoradm, sizeof(servidoradm), cfg->rest.ip);
	snprintf(puerto, sizeof(puerto), cfg->rest.port);
	snprintf(usuario, sizeof(usuario), cfg->db.user);
	snprintf(pasguor, sizeof(pasguor), cfg->db.pass);
	snprintf(datasource, sizeof(datasource), cfg->db.ip);
	snprintf(catalog, sizeof(catalog), cfg->db.name);
	snprintf(interface, sizeof(interface), cfg->wol.interface);
	snprintf(auth_token, sizeof(auth_token), cfg->rest.api_token);
}
