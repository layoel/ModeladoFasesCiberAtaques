#########################################################
# 							#
# Programa que:						#
# 							#
# - Lee del directorio de SNORT los logs creados	#
#   convertidos a ficheros json	(de forma continua)	#
#	directorio de logs: /home/tfg/Escritorio/fich/	#
#	directorio final: /home/tfg/Escritorio/prueba/	#
# - Inserta los json en la bd MongoDB			#
# 							#
#	TFG "Deteccion de las fases de un ciberataque"	#
#	autora: Elvira Castillo 			#
#  https://github.com/layoel/ModeladoFasesCiberAtaques  #
#	contacto twitter: @layoel			#
#							#
#	licencia CC-BY-SA				#
#	Granada marzo2020				#
#########################################################
#doc watchdog:  https://pythonhosted.org/watchdog/
#programa que comprueba los cambios en el directorio de snort y ejecuta el script para leer un nuevo fichero creado

# Uso: python insertJsong.py /home/tfg/Escritorio/fich/

from pymongo import * 							#libreria mongo
import json 								# import the built-in JSON library
import sys 								#para acceder a los argumentos
import shutil 								#para copiar, mover ficheros
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

#--------------------------METODOS---------------------------#

#funcion que lista los ficheros de un directorio que se pasa como argumento
def ls1(path):
	return [obj for obj in listdir(path) if isfile(path + obj)]


#funcion que calcula la ultima ocurrencia del separador que se le pasa en la cadena datoleido
def ultimaOcurrencia(datoLeido, separador):
	pos_inicial = -1
	lista = []
	try:
		while True:
			pos_inicial = datoLeido.index(separador, pos_inicial+1)
			lista.append(pos_inicial)
	except ValueError:
		print(" ")
	ultimaOc= lista[len(lista)-1]
	return ultimaOc

#se pasa un path y devuelve el nombre del archivo
def nombreArchivo(path):
	archivo = path[ultimaOcurrencia(path, "/"):len(path)]
	return archivo
#se pasa un archivo y devuelve la extension
def extension (archivo):
	ext = archivo[ultimaOcurrencia(archivo, "."):len(archivo)]
	return ext

def on_created(event):
	path = event.src_path
	cadena = "Se ha CREADO un archivo "+ path 
	print(cadena)
	
	
	conexion = MongoClient('localhost', 27017) 						#La conexion sera local
	db = conexion['tranalyzer'] 								#Conexion a la db
	coleccion = db['flow']									#Variable de referencia a la coleccion

	f = open(str(path), 'r')

	for lin in f:
		diccionario = json.loads(lin) 					#crea los diccionarios a partir del string lin
		#print (diccionario)
		db.flow.insert(diccionario) 					#inserto en la db los registros			
	f.close()

	#with open(path, 'r') as json_source:	
	#	diccionario = json.dumps(json_source)
	#	print (diccionario)
	#	db.flow.insert(diccionario)

def on_modified(event):
	path = event.src_path
	cadena = "Se ha MODIFICADO un archivo "+ path 
	print(cadena)
	
	conexion = MongoClient('localhost', 27017) 						#La conexion sera local
	db = conexion['tranalyzer'] 								#Conexion a la db
	coleccion = db['flow']									#Variable de referencia a la coleccion

	f = open(str(path), 'r')

	for lin in f:
		diccionario = json.loads(lin) 					#crea los diccionarios a partir del string lin
		#print (diccionario)
		db.flow.insert(diccionario) 					#inserto en la db los registros			
	f.close()


#---------------------------PROGRAMA PRINCIPAL-----------------#
if __name__ == '__main__':
	if len(sys.argv) == 2:
		#creo el controlador de eventos
		patterns = "*.json" # archivos que queremos manejar (json para insertar en bd y log snort para convertir a json)
		ignore_patterns = ""
		ignore_directories = True
		case_sensitive = True
		manejador = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
		
		#se invocan estas funciones cuando se genera el evento correspondiente
		manejador.on_created = on_created
		manejador.on_modified = on_modified

		#creamos el observador
		path = sys.argv[1]
		recursivo = True
		monitor = Observer()
		monitor.schedule(manejador, path, recursive=recursivo)

		#iniciamos el monitoreo
		monitor.start()
		try:
			while True:
				time.sleep(1)
		except KeyboardInterrupt:
			monitor.stop()
			monitor.join()
	else:
		print ("Uso: [insertJson.py] [path logs snort]")

