#ifndef _OG_JSON_H
#define _OG_JSON_H

#include <jansson.h>
#include "schedule.h"

int og_json_parse_string(json_t *element, const char **str);
int og_json_parse_string_copy(json_t *element, char *str, size_t size);
int og_json_parse_uint64(json_t *element, uint64_t *integer);
int og_json_parse_uint(json_t *element, uint32_t *integer);
int og_json_parse_bool(json_t *element, bool *value);

#define OG_PARAM_PART_NUMBER			(1UL << 0)
#define OG_PARAM_PART_CODE			(1UL << 1)
#define OG_PARAM_PART_FILESYSTEM		(1UL << 2)
#define OG_PARAM_PART_SIZE			(1UL << 3)
#define OG_PARAM_PART_FORMAT			(1UL << 4)
#define OG_PARAM_PART_DISK			(1UL << 5)
#define OG_PARAM_PART_OS			(1UL << 6)
#define OG_PARAM_PART_USED_SIZE			(1UL << 7)
#define OG_PARAM_PART_DISK_TYPE			(1UL << 8)

struct og_partition {
	const char	*disk;
	const char	*disk_type;
	const char	*number;
	const char	*code;
	const char	*size;
	const char	*filesystem;
	const char	*format;
	const char	*os;
	const char	*used_size;
};

#define OG_DISK_MAX		4
#define OG_PARTITION_MAX	(4 * OG_DISK_MAX)

int og_json_parse_partition(json_t *element, struct og_partition *part,
			    uint64_t required_flags);

#define OG_CLIENTS_MAX	4096

struct og_sync_params {
	const char	*sync;
	const char	*diff;
	const char	*remove;
	const char	*compress;
	const char	*cleanup;
	const char	*cache;
	const char	*cleanup_cache;
	const char	*remove_dst;
	const char	*diff_id;
	const char	*diff_name;
	const char	*path;
	const char	*method;
};

#define OG_PARAM_SCOPE_ID	(1UL << 0)
#define OG_PARAM_SCOPE_TYPE	(1UL << 1)

struct og_scope {
	uint32_t	id;
	const char	*type;
};

int og_json_parse_scope(json_t *element, struct og_scope *scope,
			const uint64_t required_flags);

struct og_msg_params {
	const char	*ips_array[OG_CLIENTS_MAX];
	const char	*mac_array[OG_CLIENTS_MAX];
	const char	*netmask_array[OG_CLIENTS_MAX];
	unsigned int	ips_array_len;
	const char	*wol_type;
	char		run_cmd[4096];
	const char	*disk;
	const char	*partition;
	const char	*repository;
	const char	*name;
	const char	*id;
	const char	*code;
	const char	*type;
	const char	*profile;
	const char	*cache;
	const char	*cache_size;
	const char	*comment;
	bool		echo;
	struct og_partition	partition_setup[OG_PARTITION_MAX];
	struct og_sync_params sync_setup;
	struct og_schedule_time time;
	const char	*task_id;
	uint64_t	flags;
};

struct og_cmd_json {
	const char	*type;
	json_t		*json;
	uint32_t	flags;
};

enum og_procedure_step_type {
	OG_STEP_COMMAND		= 0,
	OG_STEP_PROCEDURE,
};

#define OG_PROCEDURE_STEPS_MAX	256

struct og_procedure_step {
	enum og_procedure_step_type	type;
	uint32_t			position;

	union {
		struct og_cmd_json	cmd;
		struct {
			uint64_t	id;
		} procedure;
	};
};

struct og_procedure {
	uint64_t			id;
	struct og_procedure_step	steps[OG_PROCEDURE_STEPS_MAX];
	uint32_t			num_steps;
};

int og_json_parse_procedure(json_t *element, struct og_procedure *proc);

#endif
