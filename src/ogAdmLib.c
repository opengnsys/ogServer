// **************************************************************************************************************************************************
// Libreria: ogAdmLib
// Autor: José Manuel Alonso (E.T.S.I.I.) Universidad de Sevilla
// Fecha Creación: Marzo-2010
// Fecha Última modificación: Marzo-2010
// Nombre del fichero: ogAdmLib.c
// Descripción: Este fichero implementa una libreria de funciones para uso común de los servicios
// **************************************************************************************************************************************************

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ogAdmLib.h"

// ________________________________________________________________________________________________________
// Función: splitCadena
//
//	Descripción:
//			Trocea una cadena según un carácter delimitador
//	Parámetros:
//			- trozos: Array de punteros a cadenas
//			- cadena: Cadena a trocear
//			- chd: Carácter delimitador
//	Devuelve:
//		Número de trozos en que se divide la cadena
// ________________________________________________________________________________________________________
int splitCadena(char **trozos,char *cadena, char chd)
{
	int w=0;
	if(cadena==NULL) return(w);

	trozos[w++]=cadena;
	while(*cadena!='\0'){
		if(*cadena==chd){
			*cadena='\0';
			if(*(cadena+1)!='\0')
				trozos[w++]=cadena+1;
		}
		cadena++;
	}
	return(w); // Devuelve el número de trozos
}
// ________________________________________________________________________________________________________
// Función: escaparCadena
//
//	Descripción:
//			Sustituye las apariciones de un caracter comila simple ' por \'
//	Parámetros:
//			- cadena: Cadena a escapar
// Devuelve:
//		La cadena con las comillas simples sustituidas por \'
// ________________________________________________________________________________________________________
char* escaparCadena(char *cadena)
{
	int b,c;
	char *buffer;

	buffer = (char*) calloc(1, strlen(cadena)*2); // Toma memoria para el buffer de conversión
	if (buffer == NULL) { // No hay memoria suficiente para el buffer
		return NULL;
	}

	c=b=0;
	while(cadena[c]!=0) {
		if (cadena[c]=='\''){
			buffer[b++]='\\';
			buffer[b++]='\'';
		}
		else{
			buffer[b++]=cadena[c];
		}
		c++;
	}
	return(buffer);
}

// ________________________________________________________________________________________________________
// Función: rTrim
//
//		 Descripción:
//			Elimina caracteres de espacios y de asci menor al espacio al final de la cadena
//		Parámetros:
//			- cadena: Cadena a procesar
// ________________________________________________________________________________________________________
char* rTrim(char *cadena)
{
	int i,lon;

	lon=strlen(cadena);
	for (i=lon-1;i>=0;i--){
		if(cadena[i]<32)
			cadena[i]='\0';
		else
			return(cadena);
	}
	return(cadena);
}
