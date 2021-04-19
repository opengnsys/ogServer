#ifndef __OG_DBI
#define __OG_DBI

#include <dbi/dbi.h>
#include <stdbool.h>
#include <sys/stat.h>

struct og_dbi_config {
	const char	*user;
	const char	*pass;
	const char	*ip;
	const char	*port;
	const char	*name;
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
#define OG_DB_SERIAL_NUMBER_MAXLEN	25
#define OG_DB_IMAGE_DESCRIPTION_MAXLEN 	250
#define OG_DB_IMAGE_NAME_MAXLEN 50
#define OG_DB_FILESYSTEM_MAXLEN 16
#define OG_DB_NETDRIVER_MAXLEN	30
#define OG_DB_NETIFACE_MAXLEN	4
#define OG_DB_LIVEDIR_MAXLEN	50
#define OG_DB_INT8_MAXLEN	8
#define OG_DB_BOOT_MAXLEN	30
#define OG_DB_INT_MAXLEN	11
#define OG_DB_MAC_MAXLEN	15
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

struct og_image {
	char name[OG_DB_IMAGE_NAME_MAXLEN + 1];
	char description[OG_DB_IMAGE_DESCRIPTION_MAXLEN + 1];
	uint64_t software_id;
	uint64_t center_id;
	uint64_t datasize;
	uint64_t group_id;
	uint64_t type;
	uint64_t id;
	struct stat image_stats;
};

struct og_legacy_partition {
	char partition[OG_DB_SMALLINT_MAXLEN + 1];
	char code[OG_DB_INT8_MAXLEN + 1];
	char size[OG_DB_INT_MAXLEN + 1];
	char filesystem[OG_DB_FILESYSTEM_MAXLEN + 1];
	char format[2]; /* Format is a boolean 0 or 1 => length is 2 */
};

struct og_computer {
	unsigned int	procedure_id;
	unsigned int	hardware_id;
	unsigned int	repo_id;
	unsigned int	center;
	unsigned int	room;
	unsigned int	id;
	bool		maintenance;
	bool		remote;
	char		serial_number[OG_DB_SERIAL_NUMBER_MAXLEN + 1];
	char		netdriver[OG_DB_NETDRIVER_MAXLEN + 1];
	char		name[OG_DB_COMPUTER_NAME_MAXLEN + 1];
	char		netiface[OG_DB_NETIFACE_MAXLEN + 1];
	char		livedir[OG_DB_LIVEDIR_MAXLEN + 1];
	char		netmask[OG_DB_IP_MAXLEN + 1];
	char		boot[OG_DB_BOOT_MAXLEN + 1];
	char		mac[OG_DB_MAC_MAXLEN + 1];
	char		ip[OG_DB_IP_MAXLEN + 1];
};

struct in_addr;
int og_dbi_get_computer_info(struct og_dbi *dbi, struct og_computer *computer,
			     struct in_addr addr);
int og_dbi_add_image(struct og_dbi *dbi, const struct og_image *image);

int og_dbi_schema_update(void);

#endif
