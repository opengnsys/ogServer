#ifndef __OG_DBI
#define __OG_DBI

#include <dbi/dbi.h>
#include <stdbool.h>

struct og_dbi_config {
	const char	*user;
	const char	*passwd;
	const char	*host;
	const char	*port;
	const char	*database;
};

struct og_dbi {
	dbi_conn	conn;
	dbi_inst	inst;
};

struct og_dbi *og_dbi_open(struct og_dbi_config *config);
void og_dbi_close(struct og_dbi *db);

#define OG_DB_COMPUTER_NAME_MAXLEN	100
#define OG_DB_CENTER_NAME_MAXLEN	100
#define OG_DB_ROOM_NAME_MAXLEN		100
#define OG_DB_IMAGE_NAME_MAXLEN 50
#define OG_DB_FILESYSTEM_MAXLEN 16
#define OG_DB_INT8_MAXLEN	8
#define OG_DB_INT_MAXLEN	11
#define OG_DB_IP_MAXLEN		15
#define OG_DB_SMALLINT_MAXLEN	6

struct og_image_legacy {
	char software_id[OG_DB_INT_MAXLEN + 1];
	char image_id[OG_DB_INT_MAXLEN + 1];
	char name[OG_DB_IMAGE_NAME_MAXLEN + 1];
	char repo[OG_DB_IP_MAXLEN + 1];
	char part[OG_DB_SMALLINT_MAXLEN + 1];
	char disk[OG_DB_SMALLINT_MAXLEN + 1];
	char code[OG_DB_INT8_MAXLEN + 1];
};

struct og_legacy_partition {
	char partition[OG_DB_SMALLINT_MAXLEN + 1];
	char code[OG_DB_INT8_MAXLEN + 1];
	char size[OG_DB_INT_MAXLEN + 1];
	char filesystem[OG_DB_FILESYSTEM_MAXLEN + 1];
	char format[2]; /* Format is a boolean 0 or 1 => length is 2 */
};

extern struct og_dbi_config dbi_config;

struct og_computer {
	unsigned int	procedure_id;
	unsigned int	hardware_id;
	unsigned int	repo_id;
	unsigned int	center;
	unsigned int	room;
	unsigned int	id;
	bool		maintenance;
	bool		remote;
	char		*serial_number;
	char		*netdriver;
	char		*netiface;
	char		*netmask;
	char		*livedir;
	char		*name;
	char		*boot;
	char		*mac;
	char		*ip;
};

struct in_addr;
int og_dbi_get_computer_info(struct og_dbi *dbi, struct og_computer *computer,
			     struct in_addr addr);
void og_dbi_free_computer_info(struct og_computer *computer);

#endif
