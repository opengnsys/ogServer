/*
 * Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
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

#define OG_SCHEMA_STMTS_V2      7

static const char *stmts_v2[OG_SCHEMA_STMTS_V2] = {
	[0] 	=	"ALTER TABLE `aulas` "
			"ADD CONSTRAINT FK_centros "
			"FOREIGN KEY (`idcentro`) "
			"REFERENCES `centros` (`idcentro`) ON DELETE CASCADE",
	[1] 	= 	"ALTER TABLE `ordenadores` "
			"ADD CONSTRAINT FK_aulas "
			"FOREIGN KEY (`idaula`) "
			"REFERENCES `aulas` (`idaula`) ON DELETE CASCADE",
	[2] 	=	"ALTER TABLE `ordenadores_particiones` "
			"ADD CONSTRAINT FK_ordenadores "
			"FOREIGN KEY (`idordenador`) "
			"REFERENCES `ordenadores` (`idordenador`) ON DELETE CASCADE",
	[3] 	=	"DELETE PS FROM perfilessoft_softwares AS PS "
			"WHERE NOT EXISTS ("
			"SELECT null FROM softwares AS S "
			"WHERE S.idsoftware = PS.idsoftware)",
	[4] 	=	"ALTER TABLE `perfilessoft_softwares` "
			"ADD CONSTRAINT FK_softwares "
			"FOREIGN KEY (`idsoftware`) "
			"REFERENCES `softwares` (`idsoftware`) ON DELETE CASCADE",
	[5]	=	"ALTER TABLE `perfilessoft_softwares` "
			"ADD CONSTRAINT FK_perfilessoft "
			"FOREIGN KEY (`idperfilsoft`) "
			"REFERENCES `perfilessoft` (`idperfilsoft`) ON DELETE CASCADE",
	[6]	=	"UPDATE version SET version = 2",
};

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

static int og_dbi_schema_v2(struct og_dbi *dbi)
{
	const char *msglog;
	dbi_result result;
	int ret, i;

	ret = dbi_conn_transaction_begin(dbi->conn);
	if (ret) {
		syslog(LOG_DEBUG, "could not begin a transaction (%s:%d)\n",
		       __func__, __LINE__);
		goto err_no_trans;
	}

	for (i = 0; i < OG_SCHEMA_STMTS_V2; i++) {
		result = dbi_conn_query(dbi->conn, stmts_v2[i]);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "Statement number %d failed (%s:%d): %s\n",
					i, __func__, __LINE__, msglog);
			goto err_trans;
		}
		dbi_result_free(result);
	}

	ret = dbi_conn_transaction_commit(dbi->conn);
	if (ret) {
		syslog(LOG_DEBUG, "could not commit a transaction (%s:%d)\n",
		       __func__, __LINE__);
		goto err_trans;
	}
	return 0;

err_trans:
	dbi_conn_transaction_rollback(dbi->conn);
err_no_trans:
	return -1;
}

static int og_dbi_schema_v3(struct og_dbi *dbi)
{
	const char *msglog;
	dbi_result result;

	syslog(LOG_DEBUG, "Adding disk type to ordenadores_particiones\n");
	result = dbi_conn_query(dbi->conn,
				"ALTER TABLE ordenadores_particiones "
				"ADD disk_type VARCHAR(32) DEFAULT NULL "
				"AFTER numdisk;");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_INFO, "Error when adding disk type (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	dbi_result_free(result);

	result = dbi_conn_query(dbi->conn, "UPDATE version SET version = 3");
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
	{	.version = 2,	.update = og_dbi_schema_v2	},
	{	.version = 3,	.update = og_dbi_schema_v3	},
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
