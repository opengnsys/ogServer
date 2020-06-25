#ifndef _OG_SERVER_CFG_H
#define _OG_SERVER_CFG_H

struct og_server_cfg {
        struct {
                const char *user;
                const char *pass;
                const char *ip;
                const char *name;
        } db;
        struct {
                const char      *ip;
                const char      *port;
                const char      *api_token;
        } rest;
        struct {
                const char      *interface;
        } wol;
};

int parse_json_config(const char *filename, struct og_server_cfg *cfg);

extern char auth_token[4096];
extern char usuario[4096];
extern char pasguor[4096];
extern char catalog[4096];
extern char datasource[4096];
extern char interface[4096];
extern char api_token[4096];

void from_json_to_legacy(struct og_server_cfg *cfg);

#endif
