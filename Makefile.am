sbin_PROGRAMS = ogserver

AM_CFLAGS  =  ${LIBDBI_CFLAGS} ${LIBJANSSON_CFLAGS} ${LIBEVENT_CFLAGS} -g -Wall

ogserver_SOURCES= src/ogAdmServer.c	\
		  src/cfg.c		\
		  src/core.c		\
		  src/dbi.c		\
		  src/main.c		\
		  src/schedule.c	\
		  src/schema.c		\
		  src/utils.c		\
		  src/rest.c		\
		  src/client.c		\
		  src/json.c		\
		  src/ogAdmLib.c	\
		  src/wol.c
