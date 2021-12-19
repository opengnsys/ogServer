// ********************************************************************************************************
// Servicio: ogAdmServer
// Autor: José Manuel Alonso (E.T.S.I.I.) Universidad de Sevilla
// Fecha Creación: Marzo-2010
// Fecha Última modificación: Marzo-2010
// Nombre del fichero: ogAdmServer.h
// Descripción: Este fichero implementa el servicio de administración general del sistema
// ********************************************************************************************************
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "ogAdmLib.h"

struct og_dbi;

bool actualizaConfiguracion(struct og_dbi *,char* ,int);
bool WakeUp(int, const char *, const char *, const char *, const char *);
bool actualizaCreacionImagen(struct og_dbi *,char*,char*,char*,char*,char*,char*);
bool actualizaRestauracionImagen(struct og_dbi *,char*,char*,char*,char*,char*);
bool actualizaHardware(struct og_dbi *dbi, char* ,char*,char*,char*);
bool cuestionPerfilHardware(struct og_dbi *dbi,char*,char*,int,char*,char*,int *,int);
bool actualizaSoftware(struct og_dbi *, char* , char* , char*,char*,char*);
bool cuestionPerfilSoftware(struct og_dbi *, char*, char*,int,int,char*,char*,char*,int *,int);

int checkDato(struct og_dbi *,char*,const char*,const char*,const char*);
