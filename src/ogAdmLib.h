// **************************************************************************************************************************************************
// Libreria: ogAdmLib
// Autor: José Manuel Alonso (E.T.S.I.I.) Universidad de Sevilla
// Fecha Creación: Marzo-2010
// Fecha Última modificación: Marzo-2010
// Nombre del fichero: ogAdmLib.h
// Descripción: Este fichero implementa el archivo de cabecera de la libreria  ogAdmLib
// **************************************************************************************************************************************************
// ________________________________________________________________________________________________________
// Valores definidos
// ________________________________________________________________________________________________________
#define LONSTD 1024	// Longitud de memoria estandar
#define LONINT 16	// Longitud de memoria estandar para un número entero
#define MAXPAR 128	// Maximo numero de particiones manejadas por el sistema, ahora con GPT es 128

#define ACCION_SINRESULTADO 0 // Sin resultado
#define ACCION_EXITOSA	1 // Finalizada con éxito
#define ACCION_FALLIDA	2 // Finalizada con errores

#define ACCION_INICIADA	1 // Acción activa
#define ACCION_DETENIDA	2 // Acción momentanemente parada
#define ACCION_FINALIZADA 3 // Accion finalizada

#define EJECUCION_COMANDO 1
#define EJECUCION_PROCEDIMIENTO 2
#define EJECUCION_TAREA 3
#define EJECUCION_RESERVA 4

#define AMBITO_CENTROS 0x01
#define AMBITO_GRUPOSAULAS 0x02
#define AMBITO_AULAS 0x04
#define AMBITO_GRUPOSORDENADORES 0x08
#define AMBITO_ORDENADORES 0x10

#define ANNOREF 2009 // Año de referencia base

#define MAXHARDWARE 128 //	 Máximos elementos hardware a detectar
#define MAXSOFTWARE 8096 //	 Máximos elementos software a detectar

// ________________________________________________________________________________________________________
// Prototipo de funciones
// ________________________________________________________________________________________________________
int splitCadena(char **,char *, char);
char* rTrim(char *);
char* escaparCadena(char *cadena);

#include <stddef.h> /* for offsetof. */

#define container_of(ptr, type, member) ({			\
	typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - offsetof(type,member) );})
