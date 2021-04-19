/*
 * Copyright (C) 2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, version 3.
 */

#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "dbi.h"
#include "cfg.h"
#include <syslog.h>
#include <string.h>
#include <stdio.h>

struct og_server_cfg ogconfig;

static int og_dbi_create_version(struct og_dbi *dbi)
{
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn, "CREATE TABLE `version` "
					    "(`version` smallint unsigned NOT NULL) "
					    "ENGINE='MyISAM' COLLATE 'utf8_general_ci'");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_INFO, "Could not create schema version table (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	result = dbi_conn_queryf(dbi->conn, "INSERT INTO `version` (`version`) VALUES ('0')");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_INFO, "Could not insert into schema version table (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	return 0;
}
static int og_dbi_schema_version(struct og_dbi *dbi)
{
	const char *msglog;
	dbi_result result;
	uint32_t version;

	result = dbi_conn_queryf(dbi->conn, "SELECT * from version");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_INFO, "no version table found (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	if (!dbi_result_last_row(result)) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "cannot get last row from version table (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	version = dbi_result_get_uint(result, "version");

	dbi_result_free(result);

	return version;
}
static int og_dbi_schema_v1(struct og_dbi *dbi)
{
	const char *msglog, *command;
	dbi_result result, result_alter;

	result = dbi_conn_queryf(dbi->conn, "SELECT concat('alter table `',TABLE_SCHEMA,'`.`',TABLE_NAME,'` engine=innodb;')"
					    "AS cmd FROM information_schema.TABLES WHERE TABLE_SCHEMA='%s'",
					    ogconfig.db.name);

	while (dbi_result_next_row(result)) {
		command = dbi_result_get_string(result, "cmd");

		syslog(LOG_DEBUG, "Upgrading to innoDB: %s\n", command);
		result_alter = dbi_conn_query(dbi->conn, command);
		if (!result_alter) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_INFO, "Error when upgrading engine to innoDB (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return -1;
		}
		dbi_result_free(result_alter);
	}
	dbi_result_free(result);

	result = dbi_conn_query(dbi->conn, "UPDATE version SET version = 1");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_INFO, "Could not update version row (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	return 0;
}

static struct og_schema_version {
	int	version;
	int	(*update)(struct og_dbi *dbi);
} schema_version[] = {
	{	.version = 1,	.update = og_dbi_schema_v1	},
	{	0,		NULL				},
};

int og_dbi_schema_update(void)
{
	int version, i, err;
	struct og_dbi *dbi;
	const char *msglog;

	dbi = og_dbi_open(&ogconfig.db);
	if (!dbi) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	version = og_dbi_schema_version(dbi);

	if (version < 0) {
		syslog(LOG_INFO, "creating table version in schema\n");
		og_dbi_create_version(dbi);
	} else {
		syslog(LOG_INFO, "database schema version %d\n", version);
	}

	for (i = 0; schema_version[i].version; i++) {
		if (version >= schema_version[i].version)
			continue;

		syslog(LOG_INFO, "upgrading to schema version %d\n", schema_version[i].version);

		err = schema_version[i].update(dbi);
		if (err < 0) {
			syslog(LOG_ERR, "failed to update schema!\n");
			og_dbi_close(dbi);
			return -1;
		}
	}

	og_dbi_close(dbi);

	return 0;
}