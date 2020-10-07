#ifndef _OG_SERVER_CFG_H
#define _OG_SERVER_CFG_H

#include <jansson.h>
#include "dbi.h"

struct og_server_cfg {
        struct og_dbi_config	db;
        struct {
                const char      *ip;
                const char      *port;
                const char      *api_token;
        } rest;
        struct {
                const char      *interface;
        } wol;
        struct {
                const char      *dir;
        } repo;
	json_t			*json;
};

int parse_json_config(const char *filename, struct og_server_cfg *cfg);

extern struct og_server_cfg ogconfig;

#endif
