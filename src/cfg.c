/*
 * Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
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
		} else if (!strcmp(key, "port")) {
			if (og_json_parse_string(value, &cfg->db.port) < 0)
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

static int parse_json_repo(struct og_server_cfg *cfg, json_t *element)
{
	const char *key;
	json_t *value;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "directory")) {
			if (og_json_parse_string(value, &cfg->repo.dir) < 0)
				return -1;
		} else {
			syslog(LOG_ERR, "unknown key `%s' in repo\n", key);
			return -1;
		}
	}

	return 0;
}

#define OG_SERVER_CFG_REST	(1 << 0)
#define OG_SERVER_CFG_DB	(1 << 1)
#define OG_SERVER_CFG_WOL	(1 << 2)
#define OG_SERVER_CFG_REPO	(1 << 3)

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
			if (parse_json_rest(cfg, value) < 0) {
				ret = -1;
				break;
			}
			flags |= OG_SERVER_CFG_REST;
		} else if (!strcmp(key, "wol")) {
			if (parse_json_wol(cfg, value) < 0) {
				ret = -1;
				break;
			}
			flags |= OG_SERVER_CFG_WOL;
		} else if (!strcmp(key, "database")) {
			if (parse_json_db(cfg, value) < 0) {
				ret = -1;
				break;
			}
			flags |= OG_SERVER_CFG_DB;
		} else if (!strcmp(key, "repository")) {
			if (parse_json_repo(cfg, value) < 0)
				return -1;

			flags |= OG_SERVER_CFG_REPO;
		} else {
			syslog(LOG_ERR, "unknown key `%s' in %s\n",
			       key, filename);
			ret = -1;
		}
	}

	if (ret < 0)
		json_decref(root);

	if ((flags & OG_SERVER_CFG_REST) &&
	    (flags & OG_SERVER_CFG_DB) &&
	    (flags & OG_SERVER_CFG_WOL)) {
		ret = 0;
	} else {
		syslog(LOG_ERR, "Missing attributes in json file");
		ret = -1;
	}

	if (ret < 0)
		json_decref(root);
	else
		cfg->json = root;

	return ret;
}
