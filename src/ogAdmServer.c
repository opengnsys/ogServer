// *******************************************************************************************************
// Servicio: ogAdmServer
// Autor: José Manuel Alonso (E.T.S.I.I.) Universidad de Sevilla
// Fecha Creación: Marzo-2010
// Fecha Última modificación: Marzo-2010
// Nombre del fichero: ogAdmServer.cpp
// Descripción :Este fichero implementa el servicio de administración general del sistema
// *******************************************************************************************************
#include "ogAdmServer.h"
#include "dbi.h"
#include "utils.h"
#include "list.h"
#include "rest.h"
#include "client.h"
#include "json.h"
#include "schedule.h"
#include <syslog.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <jansson.h>
#include <time.h>

char usuario[4096]; // Usuario de acceso a la base de datos
char pasguor[4096]; // Password del usuario
char datasource[4096]; // Dirección IP del gestor de base de datos
char catalog[4096]; // Nombre de la base de datos
char interface[4096]; // Interface name
char auth_token[4096]; // API token
char servidoradm[4096]; // Dirección IP del servidor de administración
char puerto[4096];    // Puerto de comunicación

SOCKETCL tbsockets[MAXIMOS_CLIENTES];

struct og_dbi_config dbi_config = {
	.user		= usuario,
	.passwd		= pasguor,
	.host		= datasource,
	.database	= catalog,
};

//________________________________________________________________________________________________________
//	Función: tomaConfiguracion
//
//	Descripción:
//		Lee el fichero de configuración del servicio
//	Parámetros:
//		filecfg : Ruta completa al fichero de configuración
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error 
//________________________________________________________________________________________________________
bool tomaConfiguracion(const char *filecfg)
{
	char buf[1024], *line;
	char *key, *value;
	FILE *fcfg;

	if (filecfg == NULL || strlen(filecfg) == 0) {
		syslog(LOG_ERR, "No configuration file has been specified\n");
		return false;
	}

	fcfg = fopen(filecfg, "rt");
	if (fcfg == NULL) {
		syslog(LOG_ERR, "Cannot open configuration file `%s'\n",
		       filecfg);
		return false;
	}

	servidoradm[0] = '\0'; //inicializar variables globales

	line = fgets(buf, sizeof(buf), fcfg);
	while (line != NULL) {
		const char *delim = "=";

		line[strlen(line) - 1] = '\0';

		key = strtok(line, delim);
		value = strtok(NULL, delim);

		if (!strcmp(str_toupper(key), "SERVIDORADM"))
			snprintf(servidoradm, sizeof(servidoradm), "%s", value);
		else if (!strcmp(str_toupper(key), "PUERTO"))
			snprintf(puerto, sizeof(puerto), "%s", value);
		else if (!strcmp(str_toupper(key), "USUARIO"))
			snprintf(usuario, sizeof(usuario), "%s", value);
		else if (!strcmp(str_toupper(key), "PASSWORD"))
			snprintf(pasguor, sizeof(pasguor), "%s", value);
		else if (!strcmp(str_toupper(key), "DATASOURCE"))
			snprintf(datasource, sizeof(datasource), "%s", value);
		else if (!strcmp(str_toupper(key), "CATALOG"))
			snprintf(catalog, sizeof(catalog), "%s", value);
		else if (!strcmp(str_toupper(key), "INTERFACE"))
			snprintf(interface, sizeof(interface), "%s", value);
		else if (!strcmp(str_toupper(key), "APITOKEN"))
			snprintf(auth_token, sizeof(auth_token), "%s", value);

		line = fgets(buf, sizeof(buf), fcfg);
	}

	fclose(fcfg);

	if (!servidoradm[0]) {
		syslog(LOG_ERR, "Missing SERVIDORADM in configuration file\n");
		return false;
	}
	if (!puerto[0]) {
		syslog(LOG_ERR, "Missing PUERTO in configuration file\n");
		return false;
	}
	if (!usuario[0]) {
		syslog(LOG_ERR, "Missing USUARIO in configuration file\n");
		return false;
	}
	if (!pasguor[0]) {
		syslog(LOG_ERR, "Missing PASSWORD in configuration file\n");
		return false;
	}
	if (!datasource[0]) {
		syslog(LOG_ERR, "Missing DATASOURCE in configuration file\n");
		return false;
	}
	if (!catalog[0]) {
		syslog(LOG_ERR, "Missing CATALOG in configuration file\n");
		return false;
	}
	if (!interface[0])
		syslog(LOG_ERR, "Missing INTERFACE in configuration file\n");

	return true;
}

#define OG_CMD_MAXLEN		64

// ________________________________________________________________________________________________________
// Función: clienteDisponible
//
//	Descripción:
//		Comprueba la disponibilidad del cliente para recibir comandos interactivos
//	Parametros:
//		- ip : La ip del cliente a buscar
//		- idx: (Salida)  Indice que ocupa el cliente, de estar ya registrado
//	Devuelve:
//		true: Si el cliente está disponible
//		false: En caso contrario
// ________________________________________________________________________________________________________
bool clienteDisponible(char *ip, int* idx)
{
	int estado;

	if (clienteExistente(ip, idx)) {
		estado = strcmp(tbsockets[*idx].estado, CLIENTE_OCUPADO); // Cliente ocupado
		if (estado == 0)
			return false;

		estado = strcmp(tbsockets[*idx].estado, CLIENTE_APAGADO); // Cliente apagado
		if (estado == 0)
			return false;

		estado = strcmp(tbsockets[*idx].estado, CLIENTE_INICIANDO); // Cliente en proceso de inclusión
		if (estado == 0)
			return false;

		return true; // En caso contrario el cliente está disponible
	}
	return false; // Cliente no está registrado en el sistema
}
// ________________________________________________________________________________________________________
// Función: clienteExistente
//
//	Descripción:
//		Comprueba si el cliente está registrado en la tabla de socket del sistema
//	Parametros:
//		- ip : La ip del cliente a buscar
//		- idx:(Salida)  Indice que ocupa el cliente, de estar ya registrado
//	Devuelve:
//		true: Si el cliente está registrado
//		false: En caso contrario
// ________________________________________________________________________________________________________
bool clienteExistente(char *ip, int* idx)
{
	int i;
	for (i = 0; i < MAXIMOS_CLIENTES; i++) {
		if (contieneIP(ip, tbsockets[i].ip)) { // Si existe la IP en la cadena
			*idx = i;
			return true;
		}
	}
	return false;
}
// ________________________________________________________________________________________________________
// Función: actualizaConfiguracion
//
//	Descripción:
//		Esta función actualiza la base de datos con la configuracion de particiones de un cliente
//	Parámetros:
//		- db: Objeto base de datos (ya operativo)
//		- tbl: Objeto tabla
//		- cfg: cadena con una Configuración
//		- ido: Identificador del ordenador cliente
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
//	Especificaciones:
//		Los parametros de la configuración son:
//			par= Número de partición
//			cpt= Codigo o tipo de partición
//			sfi= Sistema de ficheros que está implementado en la partición
//			soi= Nombre del sistema de ficheros instalado en la partición
//			tam= Tamaño de la partición
// ________________________________________________________________________________________________________
bool actualizaConfiguracion(struct og_dbi *dbi, char *cfg, int ido)
{
	int lon, p, c,i, dato, swu, idsoi, idsfi,k;
	char *ptrPar[MAXPAR], *ptrCfg[7], *ptrDual[2], tbPar[LONSTD];
	char *ser, *disk, *par, *cpt, *sfi, *soi, *tam, *uso; // Parametros de configuración.
	dbi_result result, result_update;
	const char *msglog;

	lon = 0;
	p = splitCadena(ptrPar, cfg, '\n');
	for (i = 0; i < p; i++) {
		c = splitCadena(ptrCfg, ptrPar[i], '\t');

		// Si la 1ª línea solo incluye el número de serie del equipo; actualizar BD.
		if (i == 0 && c == 1) {
			splitCadena(ptrDual, ptrCfg[0], '=');
			ser = ptrDual[1];
			if (strlen(ser) > 0) {
				// Solo actualizar si número de serie no existía.
				result = dbi_conn_queryf(dbi->conn,
						"UPDATE ordenadores SET numserie='%s'"
						" WHERE idordenador=%d AND numserie IS NULL",
						ser, ido);
				if (!result) {
					dbi_conn_error(dbi->conn, &msglog);
					syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
					       __func__, __LINE__, msglog);
					return false;
				}
				dbi_result_free(result);
			}
			continue;
		}

		// Distribución de particionado.
		disk = par = cpt = sfi = soi = tam = uso = NULL;

		splitCadena(ptrDual, ptrCfg[0], '=');
		disk = ptrDual[1]; // Número de disco

		splitCadena(ptrDual, ptrCfg[1], '=');
		par = ptrDual[1]; // Número de partición

		k=splitCadena(ptrDual, ptrCfg[2], '=');
		if(k==2){
			cpt = ptrDual[1]; // Código de partición
		}else{
			cpt = (char*)"0";
		}

		k=splitCadena(ptrDual, ptrCfg[3], '=');
		if(k==2){
			sfi = ptrDual[1]; // Sistema de ficheros
			/* Comprueba existencia del s0xistema de ficheros instalado */
			idsfi = checkDato(dbi, sfi, "sistemasficheros", "descripcion","idsistemafichero");
		}
		else
			idsfi=0;

		k=splitCadena(ptrDual, ptrCfg[4], '=');
		if(k==2){ // Sistema operativo detecdtado
			soi = ptrDual[1]; // Nombre del S.O. instalado
			/* Comprueba existencia del sistema operativo instalado */
			idsoi = checkDato(dbi, soi, "nombresos", "nombreso", "idnombreso");
		}
		else
			idsoi=0;

		splitCadena(ptrDual, ptrCfg[5], '=');
		tam = ptrDual[1]; // Tamaño de la partición

		splitCadena(ptrDual, ptrCfg[6], '=');
		uso = ptrDual[1]; // Porcentaje de uso del S.F.

		lon += sprintf(tbPar + lon, "(%s, %s),", disk, par);

		result = dbi_conn_queryf(dbi->conn,
				"SELECT numdisk, numpar, tamano, uso, idsistemafichero, idnombreso"
				"  FROM ordenadores_particiones"
				" WHERE idordenador=%d AND numdisk=%s AND numpar=%s",
				ido, disk, par);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}
		if (!dbi_result_next_row(result)) {
			result_update = dbi_conn_queryf(dbi->conn,
					"INSERT INTO ordenadores_particiones(idordenador,numdisk,numpar,codpar,tamano,uso,idsistemafichero,idnombreso,idimagen)"
					" VALUES(%d,%s,%s,0x%s,%s,%s,%d,%d,0)",
					ido, disk, par, cpt, tam, uso, idsfi, idsoi);
			if (!result_update) {
				dbi_conn_error(dbi->conn, &msglog);
				syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
				       __func__, __LINE__, msglog);
				return false;
			}
			dbi_result_free(result_update);

		} else { // Existe el registro
			swu = true; // Se supone que algún dato ha cambiado

			dato = dbi_result_get_uint(result, "tamano");
			if (atoi(tam) == dato) {// Parámetro tamaño igual al almacenado
				dato = dbi_result_get_uint(result, "idsistemafichero");
				if (idsfi == dato) {// Parámetro sistema de fichero igual al almacenado
					dato = dbi_result_get_uint(result, "idnombreso");
					if (idsoi == dato) {// Parámetro sistema de fichero distinto al almacenado
						swu = false; // Todos los parámetros de la partición son iguales, no se actualiza
					}
				}
			}
			if (swu) { // Hay que actualizar los parámetros de la partición
				result_update = dbi_conn_queryf(dbi->conn,
					"UPDATE ordenadores_particiones SET "
					" codpar=0x%s,"
					" tamano=%s,"
					" uso=%s,"
					" idsistemafichero=%d,"
					" idnombreso=%d,"
					" idimagen=0,"
					" idperfilsoft=0,"
					" fechadespliegue=NULL"
					" WHERE idordenador=%d AND numdisk=%s AND numpar=%s",
					cpt, tam, uso, idsfi, idsoi, ido, disk, par);
			} else {  // Actualizar porcentaje de uso.
				result_update = dbi_conn_queryf(dbi->conn,
					"UPDATE ordenadores_particiones SET "
					" codpar=0x%s,"
					" uso=%s"
					" WHERE idordenador=%d AND numdisk=%s AND numpar=%s",
					cpt, uso, ido, disk, par);
			}
			if (!result_update) {
				dbi_conn_error(dbi->conn, &msglog);
				syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
				       __func__, __LINE__, msglog);
				return false;
			}

			dbi_result_free(result_update);
		}
		dbi_result_free(result);
	}
	lon += sprintf(tbPar + lon, "(0,0)");
	// Eliminar particiones almacenadas que ya no existen
	result_update = dbi_conn_queryf(dbi->conn,
		"DELETE FROM ordenadores_particiones WHERE idordenador=%d AND (numdisk, numpar) NOT IN (%s)",
			ido, tbPar);
	if (!result_update) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result_update);

	return true;
}
// ________________________________________________________________________________________________________
// Función: checkDato
//
//	Descripción:
//		 Esta función comprueba si existe un dato en una tabla y si no es así lo incluye. devuelve en
//		cualquier caso el identificador del registro existenet o del insertado
//	Parámetros:
//		- db: Objeto base de datos (ya operativo)
//		- tbl: Objeto tabla
//		- dato: Dato
//		- tabla: Nombre de la tabla
//		- nomdato: Nombre del dato en la tabla
//		- nomidentificador: Nombre del identificador en la tabla
//	Devuelve:
//		El identificador del registro existente o el del insertado
//
//	Especificaciones:
//		En caso de producirse algún error se devuelve el valor 0
// ________________________________________________________________________________________________________

int checkDato(struct og_dbi *dbi, char *dato, const char *tabla,
		     const char *nomdato, const char *nomidentificador)
{
	const char *msglog;
	int identificador;
	dbi_result result;

	if (strlen(dato) == 0)
		return (0); // EL dato no tiene valor
	result = dbi_conn_queryf(dbi->conn,
			"SELECT %s FROM %s WHERE %s ='%s'", nomidentificador,
			tabla, nomdato, dato);

	// Ejecuta consulta
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return (0);
	}
	if (!dbi_result_next_row(result)) { //  Software NO existente
		dbi_result_free(result);

		result = dbi_conn_queryf(dbi->conn,
				"INSERT INTO %s (%s) VALUES('%s')", tabla, nomdato, dato);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return (0);
		}
		// Recupera el identificador del software
		identificador = dbi_conn_sequence_last(dbi->conn, NULL);
	} else {
		identificador = dbi_result_get_uint(result, nomidentificador);
	}
	dbi_result_free(result);

	return (identificador);
}

// ________________________________________________________________________________________________________
// Función: Levanta
//
//	Descripción:
//		Enciende ordenadores a través de la red cuyas macs se pasan como parámetro
//	Parámetros:
//		- iph: Cadena de direcciones ip separadas por ";"
//		- mac: Cadena de direcciones mac separadas por ";"
//		- mar: Método de arranque (1=Broadcast, 2=Unicast)
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
// ________________________________________________________________________________________________________

bool Levanta(char *ptrIP[], char *ptrMacs[], char *ptrNetmasks[], int lon,
	     char *mar)
{
	unsigned int on = 1;
	struct sockaddr_in local;
	int i, res;
	int s;

	/* Creación de socket para envío de magig packet */
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		syslog(LOG_ERR, "cannot create socket for magic packet\n");
		return false;
	}
	res = setsockopt(s, SOL_SOCKET, SO_BROADCAST, (unsigned int *) &on,
			 sizeof(on));
	if (res < 0) {
		syslog(LOG_ERR, "cannot set broadcast socket\n");
		return false;
	}
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(PUERTO_WAKEUP);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	for (i = 0; i < lon; i++) {
		if (!WakeUp(s, ptrIP[i], ptrMacs[i], ptrNetmasks[i], mar)) {
			syslog(LOG_ERR, "problem sending magic packet\n");
			close(s);
			return false;
		}
	}
	close(s);
	return true;
}

#define OG_WOL_SEQUENCE		6
#define OG_WOL_MACADDR_LEN	6
#define OG_WOL_REPEAT		16

struct wol_msg {
	char secuencia_FF[OG_WOL_SEQUENCE];
	char macbin[OG_WOL_REPEAT][OG_WOL_MACADDR_LEN];
};

static bool wake_up_broadcast(int sd, struct sockaddr_in *client,
			      const struct wol_msg *msg)
{
	struct sockaddr_in *broadcast_addr;
	struct ifaddrs *ifaddr, *ifa;
	int ret;

	if (getifaddrs(&ifaddr) < 0) {
		syslog(LOG_ERR, "cannot get list of addresses\n");
		return false;
	}

	client->sin_addr.s_addr = htonl(INADDR_BROADCAST);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_INET ||
		    strcmp(ifa->ifa_name, interface) != 0)
			continue;

		broadcast_addr =
			(struct sockaddr_in *)ifa->ifa_ifu.ifu_broadaddr;
		client->sin_addr.s_addr = broadcast_addr->sin_addr.s_addr;
		break;
	}
	freeifaddrs(ifaddr);

	ret = sendto(sd, msg, sizeof(*msg), 0,
		     (struct sockaddr *)client, sizeof(*client));
	if (ret < 0) {
		syslog(LOG_ERR, "failed to send broadcast wol\n");
		return false;
	}

	return true;
}

static bool wake_up_unicast(int sd, struct sockaddr_in *client,
			    const struct wol_msg *msg,
			    const struct in_addr *addr)
{
	int ret;

	client->sin_addr.s_addr = addr->s_addr;

	ret = sendto(sd, msg, sizeof(*msg), 0,
		     (struct sockaddr *)client, sizeof(*client));
	if (ret < 0) {
		syslog(LOG_ERR, "failed to send unicast wol\n");
		return false;
	}

	return true;
}

enum wol_delivery_type {
	OG_WOL_BROADCAST = 1,
	OG_WOL_UNICAST = 2
};

//_____________________________________________________________________________________________________________
// Función: WakeUp
//
//	 Descripción:
//		Enciende el ordenador cuya MAC se pasa como parámetro
//	Parámetros:
//		- s : Socket para enviar trama magic packet
//		- iph : Cadena con la dirección ip
//		- mac : Cadena con la dirección mac en formato XXXXXXXXXXXX
//		- mar: Método de arranque (1=Broadcast, 2=Unicast)
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
//_____________________________________________________________________________________________________________
//
bool WakeUp(int s, char* iph, char *mac, char *netmask, char *mar)
{
	struct in_addr addr, netmask_addr, broadcast_addr ={};
	unsigned int macaddr[OG_WOL_MACADDR_LEN];
	char HDaddress_bin[OG_WOL_MACADDR_LEN];
	struct sockaddr_in WakeUpCliente;
	struct wol_msg Trama_WakeUp;
	bool ret;
	int i;

	if (inet_aton(iph, &addr) < 0) {
		syslog(LOG_ERR, "bad IP address\n");
		return false;
	}

	if (inet_aton(netmask, &netmask_addr) < 0) {
		syslog(LOG_ERR, "bad netmask address: %s\n", netmask);
		return false;
	}

	broadcast_addr.s_addr = addr.s_addr | ~netmask_addr.s_addr;

	for (i = 0; i < 6; i++) // Primera secuencia de la trama Wake Up (0xFFFFFFFFFFFF)
		Trama_WakeUp.secuencia_FF[i] = 0xFF;

	sscanf(mac, "%02x%02x%02x%02x%02x%02x",
	       &macaddr[0], &macaddr[1], &macaddr[2],
	       &macaddr[3], &macaddr[4], &macaddr[5]);

	for (i = 0; i < 6; i++)
		HDaddress_bin[i] = (uint8_t)macaddr[i];

	for (i = 0; i < 16; i++) // Segunda secuencia de la trama Wake Up , repetir 16 veces su la MAC
		memcpy(&Trama_WakeUp.macbin[i][0], &HDaddress_bin, 6);

	/* Creación de socket del cliente que recibe la trama magic packet */
	WakeUpCliente.sin_family = AF_INET;
	WakeUpCliente.sin_port = htons((short) PUERTO_WAKEUP);

	switch (atoi(mar)) {
	case OG_WOL_BROADCAST:
		ret = wake_up_broadcast(s, &WakeUpCliente, &Trama_WakeUp);
		ret &= wake_up_unicast(s, &WakeUpCliente, &Trama_WakeUp,
				      &broadcast_addr);
		break;
	case OG_WOL_UNICAST:
		ret = wake_up_unicast(s, &WakeUpCliente, &Trama_WakeUp, &addr);
		break;
	default:
		syslog(LOG_ERR, "unknown wol type\n");
		ret = false;
		break;
	}
	return ret;
}

// ________________________________________________________________________________________________________
// Función: actualizaCreacionImagen
//
//	Descripción:
//		Esta función actualiza la base de datos con el resultado de la creación de una imagen
//	Parámetros:
//		- db: Objeto base de datos (ya operativo)
//		- tbl: Objeto tabla
//		- idi: Identificador de la imagen
//		- dsk: Disco de donde se creó
//		- par: Partición de donde se creó
//		- cpt: Código de partición
//		- ipr: Ip del repositorio
//		- ido: Identificador del ordenador modelo
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
// ________________________________________________________________________________________________________
bool actualizaCreacionImagen(struct og_dbi *dbi, char *idi, char *dsk,
			     char *par, char *cpt, char *ipr, char *ido)
{
	const char *msglog;
	dbi_result result;
	int idr,ifs;

	/* Toma identificador del repositorio correspondiente al ordenador modelo */
	result = dbi_conn_queryf(dbi->conn,
			"SELECT repositorios.idrepositorio"
			"  FROM repositorios"
			"  LEFT JOIN ordenadores USING (idrepositorio)"
			" WHERE repositorios.ip='%s' AND ordenadores.idordenador=%s", ipr, ido);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	if (!dbi_result_next_row(result)) {
		syslog(LOG_ERR,
		       "repository does not exist in database (%s:%d)\n",
		       __func__, __LINE__);
		dbi_result_free(result);
		return false;
	}
	idr = dbi_result_get_uint(result, "idrepositorio");
	dbi_result_free(result);

	/* Toma identificador del perfilsoftware */
	result = dbi_conn_queryf(dbi->conn,
			"SELECT idperfilsoft"
			"  FROM ordenadores_particiones"
			" WHERE idordenador=%s AND numdisk=%s AND numpar=%s", ido, dsk, par);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	if (!dbi_result_next_row(result)) {
		syslog(LOG_ERR,
		       "software profile does not exist in database (%s:%d)\n",
		       __func__, __LINE__);
		dbi_result_free(result);
		return false;
	}
	ifs = dbi_result_get_uint(result, "idperfilsoft");
	dbi_result_free(result);

	/* Actualizar los datos de la imagen */
	result = dbi_conn_queryf(dbi->conn,
		"UPDATE imagenes"
		"   SET idordenador=%s, numdisk=%s, numpar=%s, codpar=%s,"
		"       idperfilsoft=%d, idrepositorio=%d,"
		"       fechacreacion=NOW(), revision=revision+1"
		" WHERE idimagen=%s", ido, dsk, par, cpt, ifs, idr, idi);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	/* Actualizar los datos en el cliente */
	result = dbi_conn_queryf(dbi->conn,
		"UPDATE ordenadores_particiones"
		"   SET idimagen=%s, revision=(SELECT revision FROM imagenes WHERE idimagen=%s),"
		"       fechadespliegue=NOW()"
		" WHERE idordenador=%s AND numdisk=%s AND numpar=%s",
		idi, idi, ido, dsk, par);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	return true;
}

// ________________________________________________________________________________________________________
// Función: actualizaRestauracionImagen
//
//	Descripción:
//		Esta función actualiza la base de datos con el resultado de la restauración de una imagen
//	Parámetros:
//		- db: Objeto base de datos (ya operativo)
//		- tbl: Objeto tabla
//		- idi: Identificador de la imagen
//		- dsk: Disco de donde se restauró
//		- par: Partición de donde se restauró
//		- ido: Identificador del cliente donde se restauró
//		- ifs: Identificador del perfil software contenido	en la imagen
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
// ________________________________________________________________________________________________________
bool actualizaRestauracionImagen(struct og_dbi *dbi, char *idi,
				 char *dsk, char *par, char *ido, char *ifs)
{
	const char *msglog;
	dbi_result result;

	/* Actualizar los datos de la imagen */
	result = dbi_conn_queryf(dbi->conn,
			"UPDATE ordenadores_particiones"
			"   SET idimagen=%s, idperfilsoft=%s, fechadespliegue=NOW(),"
			"       revision=(SELECT revision FROM imagenes WHERE idimagen=%s),"
			"       idnombreso=IFNULL((SELECT idnombreso FROM perfilessoft WHERE idperfilsoft=%s),0)"
			" WHERE idordenador=%s AND numdisk=%s AND numpar=%s", idi, ifs, idi, ifs, ido, dsk, par);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	return true;
}
// ________________________________________________________________________________________________________
// Función: actualizaHardware
//
//		Descripción:
//			Actualiza la base de datos con la configuracion hardware del cliente
//		Parámetros:
//			- db: Objeto base de datos (ya operativo)
//			- tbl: Objeto tabla
//			- hrd: cadena con el inventario hardware
//			- ido: Identificador del ordenador
//			- npc: Nombre del ordenador
//			- idc: Identificador del centro o Unidad organizativa
// ________________________________________________________________________________________________________
//
bool actualizaHardware(struct og_dbi *dbi, char *hrd, char *ido, char *npc,
		       char *idc)
{
	const char *msglog;
	int idtipohardware, idperfilhard;
	int lon, i, j, aux;
	bool retval;
	char *whard;
	int tbidhardware[MAXHARDWARE];
	char *tbHardware[MAXHARDWARE],*dualHardware[2], strInt[LONINT], *idhardwares;
	dbi_result result;

	/* Toma Centro (Unidad Organizativa) */
	result = dbi_conn_queryf(dbi->conn,
				 "SELECT idperfilhard FROM ordenadores WHERE idordenador=%s",
				 ido);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	if (!dbi_result_next_row(result)) {
		syslog(LOG_ERR, "client does not exist in database (%s:%d)\n",
		       __func__, __LINE__);
		dbi_result_free(result);
		return false;
	}
	idperfilhard = dbi_result_get_uint(result, "idperfilhard");
	dbi_result_free(result);

	whard=escaparCadena(hrd); // Codificar comillas simples
	if(!whard)
		return false;
	/* Recorre componentes hardware*/
	lon = splitCadena(tbHardware, whard, '\n');
	if (lon > MAXHARDWARE)
		lon = MAXHARDWARE; // Limita el número de componentes hardware
	/*
	 for (i=0;i<lon;i++){
	 sprintf(msglog,"Linea de inventario: %s",tbHardware[i]);
	 RegistraLog(msglog,false);
	 }
	 */
	for (i = 0; i < lon; i++) {
		splitCadena(dualHardware, rTrim(tbHardware[i]), '=');
		//sprintf(msglog,"nemonico: %s",dualHardware[0]);
		//RegistraLog(msglog,false);
		//sprintf(msglog,"valor: %s",dualHardware[1]);
		//RegistraLog(msglog,false);
		result = dbi_conn_queryf(dbi->conn,
					 "SELECT idtipohardware,descripcion FROM tipohardwares WHERE nemonico='%s'",
					 dualHardware[0]);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}
		if (!dbi_result_next_row(result)) { //	Tipo de Hardware NO existente
			dbi_result_free(result);
			return false;
		} else { //  Tipo de Hardware Existe
			idtipohardware = dbi_result_get_uint(result, "idtipohardware");
			dbi_result_free(result);

			result = dbi_conn_queryf(dbi->conn,
						 "SELECT idhardware FROM hardwares WHERE idtipohardware=%d AND descripcion='%s'",
						 idtipohardware, dualHardware[1]);

			if (!result) {
				dbi_conn_error(dbi->conn, &msglog);
				syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
				       __func__, __LINE__, msglog);
				return false;
			}

			if (!dbi_result_next_row(result)) { //	Hardware NO existente
				dbi_result_free(result);
				result = dbi_conn_queryf(dbi->conn,
							"INSERT hardwares (idtipohardware,descripcion,idcentro,grupoid) "
							" VALUES(%d,'%s',%s,0)", idtipohardware,
						dualHardware[1], idc);
				if (!result) {
					dbi_conn_error(dbi->conn, &msglog);
					syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
					       __func__, __LINE__, msglog);
					return false;
				}

				// Recupera el identificador del hardware
				tbidhardware[i] = dbi_conn_sequence_last(dbi->conn, NULL);
			} else {
				tbidhardware[i] = dbi_result_get_uint(result, "idhardware");
			}
			dbi_result_free(result);
		}
	}
	// Ordena tabla de identificadores para cosultar si existe un pefil con esas especificaciones

	for (i = 0; i < lon - 1; i++) {
		for (j = i + 1; j < lon; j++) {
			if (tbidhardware[i] > tbidhardware[j]) {
				aux = tbidhardware[i];
				tbidhardware[i] = tbidhardware[j];
				tbidhardware[j] = aux;
			}
		}
	}
	/* Crea cadena de identificadores de componentes hardware separados por coma */
	sprintf(strInt, "%d", tbidhardware[lon - 1]); // Pasa a cadena el último identificador que es de mayor longitud
	aux = strlen(strInt); // Calcula longitud de cadena para reservar espacio a todos los perfiles
	idhardwares = calloc(1, sizeof(aux) * lon + lon);
	if (idhardwares == NULL) {
		syslog(LOG_ERR, "%s:%d OOM\n", __FILE__, __LINE__);
		return false;
	}
	aux = sprintf(idhardwares, "%d", tbidhardware[0]);
	for (i = 1; i < lon; i++)
		aux += sprintf(idhardwares + aux, ",%d", tbidhardware[i]);

	if (!cuestionPerfilHardware(dbi, idc, ido, idperfilhard, idhardwares,
			npc, tbidhardware, lon)) {
		syslog(LOG_ERR, "Problem updating client hardware\n");
		retval=false;
	} else {
		retval=true;
	}
	free(whard);
	free(idhardwares);

	return (retval);
}
// ________________________________________________________________________________________________________
// Función: cuestionPerfilHardware
//
//		Descripción:
//			Comprueba existencia de perfil hardware y actualización de éste para el ordenador
//		Parámetros:
//			- db: Objeto base de datos (ya operativo)
//			- tbl: Objeto tabla
//			- idc: Identificador de la Unidad organizativa donde se encuentra el cliente
//			- ido: Identificador del ordenador
//			- tbidhardware: Identificador del tipo de hardware
//			- con: Número de componentes detectados para configurar un el perfil hardware
//			- npc: Nombre del cliente
// ________________________________________________________________________________________________________
bool cuestionPerfilHardware(struct og_dbi *dbi, char *idc, char *ido,
		int idperfilhardware, char *idhardwares, char *npc, int *tbidhardware,
		int lon)
{
	const char *msglog;
	dbi_result result;
	int i;
	int nwidperfilhard;

	// Busca perfil hard del ordenador que contenga todos los componentes hardware encontrados
	result = dbi_conn_queryf(dbi->conn,
		"SELECT idperfilhard FROM"
		" (SELECT perfileshard_hardwares.idperfilhard as idperfilhard,"
		"	group_concat(cast(perfileshard_hardwares.idhardware AS char( 11) )"
		"	ORDER BY perfileshard_hardwares.idhardware SEPARATOR ',' ) AS idhardwares"
		" FROM	perfileshard_hardwares"
		" GROUP BY perfileshard_hardwares.idperfilhard) AS temp"
		" WHERE idhardwares LIKE '%s'", idhardwares);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	if (!dbi_result_next_row(result)) {
		// No existe un perfil hardware con esos componentes de componentes hardware, lo crea
		dbi_result_free(result);
		result = dbi_conn_queryf(dbi->conn,
				"INSERT perfileshard  (descripcion,idcentro,grupoid)"
				" VALUES('Perfil hardware (%s) ',%s,0)", npc, idc);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}
		dbi_result_free(result);

		// Recupera el identificador del nuevo perfil hardware
		nwidperfilhard = dbi_conn_sequence_last(dbi->conn, NULL);

		// Crea la relación entre perfiles y componenetes hardware
		for (i = 0; i < lon; i++) {
			result = dbi_conn_queryf(dbi->conn,
					"INSERT perfileshard_hardwares  (idperfilhard,idhardware)"
						" VALUES(%d,%d)", nwidperfilhard, tbidhardware[i]);
			if (!result) {
				dbi_conn_error(dbi->conn, &msglog);
				syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
				       __func__, __LINE__, msglog);
				return false;
			}
			dbi_result_free(result);
		}
	} else { // Existe un perfil con todos esos componentes
		nwidperfilhard = dbi_result_get_uint(result, "idperfilhard");
		dbi_result_free(result);
	}
	if (idperfilhardware != nwidperfilhard) { // No coinciden los perfiles
		// Actualiza el identificador del perfil hardware del ordenador
		result = dbi_conn_queryf(dbi->conn,
			"UPDATE ordenadores SET idperfilhard=%d"
			" WHERE idordenador=%s", nwidperfilhard, ido);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}
		dbi_result_free(result);
	}
	/* Eliminar Relación de hardwares con Perfiles hardware que quedan húerfanos */
	result = dbi_conn_queryf(dbi->conn,
		"DELETE FROM perfileshard_hardwares WHERE idperfilhard IN "
		" (SELECT idperfilhard FROM perfileshard WHERE idperfilhard NOT IN"
		" (SELECT DISTINCT idperfilhard from ordenadores))");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	/* Eliminar Perfiles hardware que quedan húerfanos */
	result = dbi_conn_queryf(dbi->conn,
			"DELETE FROM perfileshard WHERE idperfilhard NOT IN"
			" (SELECT DISTINCT idperfilhard FROM ordenadores)");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	/* Eliminar Relación de hardwares con Perfiles hardware que quedan húerfanos */
	result = dbi_conn_queryf(dbi->conn,
			"DELETE FROM perfileshard_hardwares WHERE idperfilhard NOT IN"
			" (SELECT idperfilhard FROM perfileshard)");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	return true;
}
// ________________________________________________________________________________________________________
// Función: actualizaSoftware
//
//	Descripción:
//		Actualiza la base de datos con la configuración software del cliente
//	Parámetros:
//		- db: Objeto base de datos (ya operativo)
//		- tbl: Objeto tabla
//		- sft: cadena con el inventario software
//		- par: Número de la partición
//		- ido: Identificador del ordenador del cliente en la tabla
//		- npc: Nombre del ordenador
//		- idc: Identificador del centro o Unidad organizativa
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
//
//	Versión 1.1.0: Se incluye el sistema operativo. Autora: Irina Gómez - ETSII Universidad Sevilla
// ________________________________________________________________________________________________________
bool actualizaSoftware(struct og_dbi *dbi, char *sft, char *par,char *ido,
		       char *npc, char *idc)
{
	int i, j, lon, aux, idperfilsoft, idnombreso;
	bool retval;
	char *wsft;
	int tbidsoftware[MAXSOFTWARE];
	char *tbSoftware[MAXSOFTWARE], strInt[LONINT], *idsoftwares;
	const char *msglog;
	dbi_result result;

	/* Toma Centro (Unidad Organizativa) y perfil software */
	result = dbi_conn_queryf(dbi->conn,
		"SELECT idperfilsoft,numpar"
		" FROM ordenadores_particiones"
		" WHERE idordenador=%s", ido);
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	idperfilsoft = 0; // Por defecto se supone que el ordenador no tiene aún detectado el perfil software
	while (dbi_result_next_row(result)) {
		aux = dbi_result_get_uint(result, "numpar");
		if (aux == atoi(par)) { // Se encuentra la partición
			idperfilsoft = dbi_result_get_uint(result, "idperfilsoft");
			break;
		}
	}
	dbi_result_free(result);
	wsft=escaparCadena(sft); // Codificar comillas simples
	if(!wsft)
		return false;

	/* Recorre componentes software*/
	lon = splitCadena(tbSoftware, wsft, '\n');

	if (lon == 0)
		return true; // No hay lineas que procesar
	if (lon > MAXSOFTWARE)
		lon = MAXSOFTWARE; // Limita el número de componentes software

	idnombreso = 0;
	for (i = 0; i < lon; i++) {
		// Primera línea es el sistema operativo: se obtiene identificador
		if (i == 0) {
			idnombreso = checkDato(dbi, rTrim(tbSoftware[i]), "nombresos", "nombreso", "idnombreso");
			continue;
		}

		result = dbi_conn_queryf(dbi->conn,
				"SELECT idsoftware FROM softwares WHERE descripcion ='%s'",
				rTrim(tbSoftware[i]));
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}

		if (!dbi_result_next_row(result)) {
			dbi_result_free(result);
			result = dbi_conn_queryf(dbi->conn,
						"INSERT INTO softwares (idtiposoftware,descripcion,idcentro,grupoid)"
						" VALUES(2,'%s',%s,0)", tbSoftware[i], idc);
			if (!result) { // Error al insertar
				dbi_conn_error(dbi->conn, &msglog);
				syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
				       __func__, __LINE__, msglog);
				return false;
			}

			// Recupera el identificador del software
			tbidsoftware[i] = dbi_conn_sequence_last(dbi->conn, NULL);
		} else {
			tbidsoftware[i] = dbi_result_get_uint(result, "idsoftware");
		}
		dbi_result_free(result);
	}

	// Ordena tabla de identificadores para cosultar si existe un pefil con esas especificaciones

	for (i = 0; i < lon - 1; i++) {
		for (j = i + 1; j < lon; j++) {
			if (tbidsoftware[i] > tbidsoftware[j]) {
				aux = tbidsoftware[i];
				tbidsoftware[i] = tbidsoftware[j];
				tbidsoftware[j] = aux;
			}
		}
	}
	/* Crea cadena de identificadores de componentes software separados por coma */
	sprintf(strInt, "%d", tbidsoftware[lon - 1]); // Pasa a cadena el último identificador que es de mayor longitud
	aux = strlen(strInt); // Calcula longitud de cadena para reservar espacio a todos los perfiles
	idsoftwares = calloc(1, (sizeof(aux)+1) * lon + lon);
	if (idsoftwares == NULL) {
		syslog(LOG_ERR, "%s:%d OOM\n", __FILE__, __LINE__);
		return false;
	}
	aux = sprintf(idsoftwares, "%d", tbidsoftware[0]);
	for (i = 1; i < lon; i++)
		aux += sprintf(idsoftwares + aux, ",%d", tbidsoftware[i]);

	// Comprueba existencia de perfil software y actualización de éste para el ordenador
	if (!cuestionPerfilSoftware(dbi, idc, ido, idperfilsoft, idnombreso, idsoftwares,
			npc, par, tbidsoftware, lon)) {
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		retval=false;
	} else {
		retval=true;
	}
	free(wsft);
	free(idsoftwares);

	return retval;
}
// ________________________________________________________________________________________________________
// Función: CuestionPerfilSoftware
//
//	Parámetros:
//		- db: Objeto base de datos (ya operativo)
//		- tbl: Objeto tabla
//		- idcentro: Identificador del centro en la tabla
//		- ido: Identificador del ordenador del cliente en la tabla
//		- idnombreso: Identificador del sistema operativo
//		- idsoftwares: Cadena con los identificadores de componentes software separados por comas
//		- npc: Nombre del ordenador del cliente
//		- particion: Número de la partición
//		- tbidsoftware: Array con los identificadores de componentes software
//		- lon: Número de componentes
//	Devuelve:
//		true: Si el proceso es correcto
//		false: En caso de ocurrir algún error
//
//	Versión 1.1.0: Se incluye el sistema operativo. Autora: Irina Gómez - ETSII Universidad Sevilla
//_________________________________________________________________________________________________________
bool cuestionPerfilSoftware(struct og_dbi *dbi, char *idc, char *ido,
			    int idperfilsoftware, int idnombreso,
			    char *idsoftwares, char *npc, char *par,
			    int *tbidsoftware, int lon)
{
	int i, nwidperfilsoft;
	const char *msglog;
	dbi_result result;

	// Busca perfil soft del ordenador que contenga todos los componentes software encontrados
	result = dbi_conn_queryf(dbi->conn,
		"SELECT idperfilsoft FROM"
		" (SELECT perfilessoft_softwares.idperfilsoft as idperfilsoft,"
		"	group_concat(cast(perfilessoft_softwares.idsoftware AS char( 11) )"
		"	ORDER BY perfilessoft_softwares.idsoftware SEPARATOR ',' ) AS idsoftwares"
		" FROM	perfilessoft_softwares"
		" GROUP BY perfilessoft_softwares.idperfilsoft) AS temp"
		" WHERE idsoftwares LIKE '%s'", idsoftwares);

	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	if (!dbi_result_next_row(result)) { // No existe un perfil software con esos componentes de componentes software, lo crea
		dbi_result_free(result);
		result = dbi_conn_queryf(dbi->conn,
				"INSERT perfilessoft  (descripcion, idcentro, grupoid, idnombreso)"
				" VALUES('Perfil Software (%s, Part:%s) ',%s,0,%i)", npc, par, idc,idnombreso);
		if (!result) {
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}

		dbi_result_free(result);
		// Recupera el identificador del nuevo perfil software
		nwidperfilsoft = dbi_conn_sequence_last(dbi->conn, NULL);

		// Crea la relación entre perfiles y componenetes software
		for (i = 0; i < lon; i++) {
			result = dbi_conn_queryf(dbi->conn,
						"INSERT perfilessoft_softwares (idperfilsoft,idsoftware)"
						" VALUES(%d,%d)", nwidperfilsoft, tbidsoftware[i]);
			if (!result) {
				dbi_conn_error(dbi->conn, &msglog);
				syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
				       __func__, __LINE__, msglog);
				return false;
			}
			dbi_result_free(result);
		}
	} else { // Existe un perfil con todos esos componentes
		nwidperfilsoft = dbi_result_get_uint(result, "idperfilsoft");
		dbi_result_free(result);
	}

	if (idperfilsoftware != nwidperfilsoft) { // No coinciden los perfiles
		// Actualiza el identificador del perfil software del ordenador
		result = dbi_conn_queryf(dbi->conn,
				"UPDATE ordenadores_particiones SET idperfilsoft=%d,idimagen=0"
				" WHERE idordenador=%s AND numpar=%s", nwidperfilsoft, ido, par);
		if (!result) { // Error al insertar
			dbi_conn_error(dbi->conn, &msglog);
			syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
			       __func__, __LINE__, msglog);
			return false;
		}
		dbi_result_free(result);
	}

	/* DEPURACIÓN DE PERFILES SOFTWARE */

	 /* Eliminar Relación de softwares con Perfiles software que quedan húerfanos */
	result = dbi_conn_queryf(dbi->conn,
		"DELETE FROM perfilessoft_softwares WHERE idperfilsoft IN "\
		" (SELECT idperfilsoft FROM perfilessoft WHERE idperfilsoft NOT IN"\
		" (SELECT DISTINCT idperfilsoft from ordenadores_particiones) AND idperfilsoft NOT IN"\
		" (SELECT DISTINCT idperfilsoft from imagenes))");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result),
	/* Eliminar Perfiles software que quedan húerfanos */
	result = dbi_conn_queryf(dbi->conn,
		"DELETE FROM perfilessoft WHERE idperfilsoft NOT IN"
		" (SELECT DISTINCT idperfilsoft from ordenadores_particiones)"\
		" AND  idperfilsoft NOT IN"\
		" (SELECT DISTINCT idperfilsoft from imagenes)");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result),

	/* Eliminar Relación de softwares con Perfiles software que quedan húerfanos */
	result = dbi_conn_queryf(dbi->conn,
			"DELETE FROM perfilessoft_softwares WHERE idperfilsoft NOT IN"
			" (SELECT idperfilsoft from perfilessoft)");
	if (!result) {
		dbi_conn_error(dbi->conn, &msglog);
		syslog(LOG_ERR, "failed to query database (%s:%d) %s\n",
		       __func__, __LINE__, msglog);
		return false;
	}
	dbi_result_free(result);

	return true;
}
