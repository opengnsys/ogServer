/*
 * Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include <ctype.h>
#include "utils.h"

const char *str_toupper(char *str)
{
       char *c = str;

       while (*c) {
               *c = toupper(*c);
               c++;
       }

       return str;
}
