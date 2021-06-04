/*
 * Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include "json.h"
#include <stdint.h>

int og_json_parse_string(json_t *element, const char **str)
{
	if (json_typeof(element) != JSON_STRING)
		return -1;

	*str = json_string_value(element);
	return 0;
}

int og_json_parse_string_copy(json_t *element, char *str, size_t size)
{
	const char *reference_str;
	int err = 0;

	err = og_json_parse_string(element, &reference_str);
	if (err != 0)
		return err;

	err = snprintf(str, size, "%s", reference_str);
	if (err >= size)
		return -1;
	return 0;
}

int og_json_parse_uint64(json_t *element, uint64_t *integer)
{
	if (json_typeof(element) != JSON_INTEGER)
		return -1;

	*integer = json_integer_value(element);
	return 0;
}

int og_json_parse_uint(json_t *element, uint32_t *integer)
{
	if (json_typeof(element) != JSON_INTEGER)
		return -1;

	*integer = json_integer_value(element);
	return 0;
}

int og_json_parse_bool(json_t *element, bool *value)
{
	if (json_typeof(element) == JSON_TRUE)
		*value = true;
	else if (json_typeof(element) == JSON_FALSE)
		*value = false;
	else
		return -1;

	return 0;
}

int og_json_parse_scope(json_t *element, struct og_scope *scope,
			const uint64_t required_flags)
{
	uint64_t flags = 0UL;
	const char *key;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "id")) {
			err = og_json_parse_uint(value, &scope->id);
			flags |= OG_PARAM_SCOPE_ID;
		} else if (!strcmp(key, "type")) {
			err = og_json_parse_string(value, &scope->type);
			flags |= OG_PARAM_SCOPE_TYPE;
		} else {
			err = -1;
		}

		if (err < 0)
			return err;
	}

	if (flags != required_flags)
		return -1;

	return err;
}

int og_json_parse_partition(json_t *element, struct og_partition *part,
			    uint64_t required_flags)
{
	uint64_t flags = 0UL;
	const char *key;
	json_t *value;
	int err = 0;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "partition")) {
			err = og_json_parse_string(value, &part->number);
			flags |= OG_PARAM_PART_NUMBER;
		} else if (!strcmp(key, "code")) {
			err = og_json_parse_string(value, &part->code);
			flags |= OG_PARAM_PART_CODE;
		} else if (!strcmp(key, "filesystem")) {
			err = og_json_parse_string(value, &part->filesystem);
			flags |= OG_PARAM_PART_FILESYSTEM;
		} else if (!strcmp(key, "size")) {
			err = og_json_parse_string(value, &part->size);
			flags |= OG_PARAM_PART_SIZE;
		} else if (!strcmp(key, "format")) {
			err = og_json_parse_string(value, &part->format);
			flags |= OG_PARAM_PART_FORMAT;
		} else if (!strcmp(key, "disk")) {
			err = og_json_parse_string(value, &part->disk);
			flags |= OG_PARAM_PART_DISK;
		} else if (!strcmp(key, "disk_type")) {
			err = og_json_parse_string(value, &part->disk_type);
			flags |= OG_PARAM_PART_DISK_TYPE;
		} else if (!strcmp(key, "os")) {
			err = og_json_parse_string(value, &part->os);
			flags |= OG_PARAM_PART_OS;
		} else if (!strcmp(key, "used_size")) {
			err = og_json_parse_string(value, &part->used_size);
			flags |= OG_PARAM_PART_USED_SIZE;
		}

		if (err < 0)
			return err;
	}

	if ((flags & required_flags) != required_flags)
		return -1;

	return err;
}

static int og_json_parse_procedure_cmd(json_t *element, int position,
				       struct og_procedure *proc)
{
	struct og_procedure_step *step;
	uint32_t err = 0;
	const char *key;
	json_t *value;

	step = &proc->steps[proc->num_steps++];
	step->type = OG_STEP_COMMAND;
	step->position = position;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "command"))
			err = og_json_parse_string(value, &step->cmd.type);
		else if (!strcmp(key, "params"))
			step->cmd.json = value;
		else
			return -1;
	}

	return err;
}

static int og_json_parse_procedure_call(json_t *element, int position,
					struct og_procedure *proc)
{
	struct og_procedure_step *step;
	uint32_t err = 0;
	const char *key;
	json_t *value;

	step = &proc->steps[proc->num_steps++];
	step->type = OG_STEP_PROCEDURE;
	step->position = position;

	json_object_foreach(element, key, value) {
		if (!strcmp(key, "procedure"))
			err = og_json_parse_uint64(value, &step->procedure.id);
		else
			return -1;
	}

	return err;
}

int og_json_parse_procedure(json_t *element, struct og_procedure *proc)
{
	unsigned int i;
	json_t *item;
	int err = 0;

	if (json_typeof(element) != JSON_ARRAY)
		return -1;

	for (i = 0; i < json_array_size(element) && i < OG_PROCEDURE_STEPS_MAX; ++i) {
		item = json_array_get(element, i);

		if (json_object_get(item, "command"))
			err = og_json_parse_procedure_cmd(item, i, proc);
		else if (json_object_get(item, "procedure"))
			err = og_json_parse_procedure_call(item, i, proc);
		else
			err = -1;

		if (err)
			break;
	}

	return err;
}
