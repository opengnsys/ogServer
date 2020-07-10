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

extern char auth_token[4096];
extern char usuario[4096];
extern char pasguor[4096];
extern char catalog[4096];
extern char datasource[4096];
extern char interface[4096];
extern char api_token[4096];
extern char servidoradm[4096];
extern char puerto[4096];
extern char db_port[4096];

struct og_client;

typedef struct{ // Estructura usada para guardar información de los clientes
	char ip[LONIP]; // IP del cliente
	char estado[4]; // Tipo de Sistema Operativo en que se encuentra el cliente
	struct og_client *cli;
}SOCKETCL;

extern SOCKETCL tbsockets[MAXIMOS_CLIENTES];

struct og_dbi;

bool clienteExistente(char *,int *);
bool clienteDisponible(char *,int *);
bool actualizaConfiguracion(struct og_dbi *,char* ,int);
bool Levanta(char**, char**, char**, int, char*);
bool WakeUp(int,char*,char*,char*,char*);
bool actualizaCreacionImagen(struct og_dbi *,char*,char*,char*,char*,char*,char*);
bool actualizaRestauracionImagen(struct og_dbi *,char*,char*,char*,char*,char*);
bool actualizaHardware(struct og_dbi *dbi, char* ,char*,char*,char*);
bool cuestionPerfilHardware(struct og_dbi *dbi,char*,char*,int,char*,char*,int *,int);
bool actualizaSoftware(struct og_dbi *, char* , char* , char*,char*,char*);
bool cuestionPerfilSoftware(struct og_dbi *, char*, char*,int,int,char*,char*,char*,int *,int);

int checkDato(struct og_dbi *,char*,const char*,const char*,const char*);
