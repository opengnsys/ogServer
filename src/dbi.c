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
#include <syslog.h>
#include <string.h>
#include <stdio.h>

struct og_dbi *og_dbi_open(struct og_dbi_config *config)
{
	struct og_dbi *dbi;

	dbi = (struct og_dbi *)malloc(sizeof(struct og_dbi));
	if (!dbi)
		return NULL;

	dbi_initialize_r(NULL, &dbi->inst);
	dbi->conn = dbi_conn_new_r("mysql", dbi->inst);
	if (!dbi->conn) {
		free(dbi);
		return NULL;
	}

	dbi_conn_set_option(dbi->conn, "host", config->ip);
	dbi_conn_set_option(dbi->conn, "port", config->port);
	dbi_conn_set_option(dbi->conn, "username", config->user);
	dbi_conn_set_option(dbi->conn, "password", config->pass);
	dbi_conn_set_option(dbi->conn, "dbname", config->name);
	dbi_conn_set_option(dbi->conn, "encoding", "UTF-8");

	if (dbi_conn_connect(dbi->conn) < 0) {
		dbi_shutdown_r(dbi->inst);
		free(dbi);
		return NULL;
	}

	return dbi;
}

void og_dbi_close(struct og_dbi *dbi)
{
	dbi_conn_close(dbi->conn);
	dbi_shutdown_r(dbi->inst);
	free(dbi);
}

int og_dbi_get_computer_info(struct og_dbi *dbi, struct og_computer *computer,
			     struct in_addr addr)
{
	const char *msglog;
	dbi_result result;

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT ordenadores.idordenador,"
				 "       ordenadores.nombreordenador,"
				 "       ordenadores.numserie,"
				 "       ordenadores.ip,"
				 "       ordenadores.mac,"
				 "       ordenadores.idaula,"
				 "       ordenadores.idperfilhard,"
				 "       ordenadores.idrepositorio,"
				 "       ordenadores.mascara,"
				 "       ordenadores.arranque,"
				 "       ordenadores.netiface,"
				 "       ordenadores.netdriver,"
				 "       ordenadores.idproautoexec,"
				 "       ordenadores.oglivedir,"
				 "       ordenadores.inremotepc,"
				 "       ordenadores.maintenance,"
				 "       centros.idcentro "
				 "FROM ordenadores "
				 "INNER JOIN aulas ON aulas.idaula=ordenadores.idaula "
				 "INNER JOIN centros ON centros.idcentro=aulas.idcentro "
				 "WHERE ordenadores.ip='%s'", inet_ntoa(addr));
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}
	if (!dbi_result_next_row(result)) {
		syslog(LOG_ERR, "client does not exist in database (%s:%d)\n",
		       __func__, __LINE__);
		dbi_result_free(result);
		return -1;
	}

	computer->id = dbi_result_get_uint(result, "idordenador");
	snprintf(computer->name, sizeof(computer->name), "%s",
		 dbi_result_get_string(result, "nombreordenador"));
	snprintf(computer->serial_number, sizeof(computer->serial_number), "%s",
		 dbi_result_get_string(result, "numserie"));
	snprintf(computer->ip, sizeof(computer->ip), "%s",
		 dbi_result_get_string(result, "ip"));
	snprintf(computer->mac, sizeof(computer->mac), "%s",
		 dbi_result_get_string(result, "mac"));
	computer->room = dbi_result_get_uint(result, "idaula");
	computer->center = dbi_result_get_uint(result, "idcentro");
	computer->hardware_id = dbi_result_get_uint(result, "idperfilhard");
	computer->repo_id = dbi_result_get_uint(result, "idrepositorio");
	snprintf(computer->netmask, sizeof(computer->netmask), "%s",
		 dbi_result_get_string(result, "mascara"));
	snprintf(computer->boot, sizeof(computer->boot), "%s",
		 dbi_result_get_string(result, "arranque"));
	snprintf(computer->netiface, sizeof(computer->netiface), "%s",
		 dbi_result_get_string(result, "netiface"));
	snprintf(computer->netdriver, sizeof(computer->netdriver), "%s",
		 dbi_result_get_string(result, "netdriver"));
	computer->procedure_id = dbi_result_get_uint(result, "idproautoexec");
	snprintf(computer->livedir, sizeof(computer->livedir), "%s",
		 dbi_result_get_string(result, "oglivedir"));
	computer->remote = dbi_result_get_uint(result, "inremotepc") != 0;
	computer->maintenance = dbi_result_get_uint(result, "maintenance") != 0;

	dbi_result_free(result);

	return 0;
}

const int og_dbi_get_repository(const struct og_dbi *dbi, const char *repo_ip)
{
	const char *msglog;
	dbi_result result;
	int repo_id;

	/* database can store duplicated repositories, limit query to return
	 * only one */
	result = dbi_conn_queryf(dbi->conn,
				 "SELECT idrepositorio FROM repositorios "
				 "WHERE ip = '%s' LIMIT 1",
				 repo_ip);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	if (!dbi_result_next_row(result)) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR,
		       "software profile does not exist in database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		dbi_result_free(result);
		return -1;
	}

	repo_id = dbi_result_get_int(result, "idrepositorio");
	dbi_result_free(result);

	return repo_id;
}

#define OG_UNASSIGNED_SW_ID 0
#define OG_IMAGE_DEFAULT_TYPE 1 /* monolithic */

int og_dbi_add_image(struct og_dbi *dbi, const struct og_image *image)
{
	const char *msglog;
	dbi_result result;
	int repo_id;

	repo_id = og_dbi_get_repository(dbi, image->repo_ip);
	if (repo_id < 0) {
		syslog(LOG_ERR, "failed to get repository (%s:%d)\n",
		       __func__, __LINE__);
		return -1;
	}

	result = dbi_conn_queryf(dbi->conn,
				 "SELECT nombreca FROM imagenes WHERE nombreca = '%s'",
				 image->name);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	if (dbi_result_next_row(result)) {
		syslog(LOG_ERR, "image creation attempt with already used image name (%s:%d)\n",
		       __func__, __LINE__);
		dbi_result_free(result);
		return -1;
	}
	dbi_result_free(result);

	result = dbi_conn_queryf(dbi->conn,
				 "INSERT INTO imagenes (nombreca, "
				 "descripcion, "
				 "idperfilsoft, "
				 "idcentro, "
				 "comentarios, "
				 "grupoid, "
				 "idrepositorio, "
				 "tipo, "
				 "ruta) "
				 "VALUES ('%s', '%s', %u, %lu, '', %u, %lu, %u, '')",
				 image->name, image->description,
				 OG_UNASSIGNED_SW_ID, image->center_id,
				 image->group_id, repo_id,
				 OG_IMAGE_DEFAULT_TYPE);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to add client to database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return -1;
	}

	dbi_result_free(result);
	return dbi_conn_sequence_last(dbi->conn, NULL);
}
