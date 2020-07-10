#ifndef _OG_SERVER_CFG_H
#define _OG_SERVER_CFG_H

struct og_server_cfg {
        struct {
                const char *user;
                const char *pass;
                const char *ip;
                unsigned int port;
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
void from_json_to_legacy(struct og_server_cfg *cfg);

#endif
