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

from os import listdir 							#listar archivos en directorio
from os.path import isfile, isdir 					#acceder a path
from pymongo import * 							#libreria mongo
import json 								# import the built-in JSON library
import sys 								#para acceder a los argumentos
import shutil 								#para copiar, mover ficheros
import idstools 							#para leer los logs de snort

		



#--------------------------FUNCIONES---------------------------#

#funcion que lista los ficheros de un directorio que se pasa como argumento
def ls1(path):    
    return [obj for obj in listdir(path) if isfile(path + obj)]

	

#---------------------PROGRAMA---------------------------------#

# - Lee del directorio de SNORT los logs creados en JSON	
path = []
fich = []
path = sys.argv[1] 									#ARGV[1] es la ruta donde tengo los logs

ficheros = []
ficheros = ls1(path) 									#array con el nombre de los ficheros

print (ls1(path))
	
# - Inserta los json en la bd MongoDB

#print "\nSe conectara al Servidor de Base de Datos Local."
conexion = MongoClient('localhost', 27018) 						#La conexion sera local
db = conexion['tranalyzer'] 								#Conexion a la db
coleccion = db['flow']									#Variable de referencia a la coleccion

listaficheros = []
listaficheros = ls1(path) 								#los ficheros en ese directorio

porLeer = ["null"] 									#archivos que me quedan por leer del log
leidos = [] 										#archivos que ya he leido

while (len(porLeer) >= 0):
	
	porLeer = listaficheros
	print(porLeer)

	if len(porLeer) is 0:
		porLeer = ["null"]
	else:
		archivo = path + porLeer[0] 						#sin nombre de fichero solo el path

		print "\nLos datos de conexion son:"
		print "Base de datos: " + str(db)
		print "Coleccion: " + str(coleccion)
		print "Ruta del archivo .json: " + str(archivo)				#ruta completa del archivo .json

		f = open(str(archivo), 'r')

		for lin in f:
			diccionario = json.loads(lin) 					#crea los diccionarios a partir del string lin
			print (diccionario)
			db.flow.insert(diccionario) 					#inserto en la db los registros
			
		f.close()

		shutil.move( str(archivo) , "/home/eca/Escritorio/prueba") 		#muevo el leido a la carpeta prueba
		leidos.append(porLeer.pop(0))
		#print("ME QUEDA POR LEER ESTO:")
		#print(porLeer)
		

