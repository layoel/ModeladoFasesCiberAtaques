from pymongo import * 																													#libreria mongo
import json 																																		# import the built-in JSON library
import sys 																																			#para acceder a los argumentos
import shutil 																																	#para copiar, mover ficheros
import time

#mongo map reduce
from bson.son import SON

import pprint #para imprimir json formateado pretty()

import calendar

from iso8601 import parse_date

#it make the conection to mongodb
def conectToDB(db, colection):

	conexion = MongoClient('localhost', 27017) 																		#the connection is local 
	db = conexion[db] 																														#the name of the db
	coleccion = db[colection]																											#the name of the collection where is the register of file 
	return coleccion																															# from snort insert in mongo and where is reading the file 

#TO CREATE HIPERALERT WE NEED ALERTS, CLASSIFICATIONS AND FLOW

'''agrupar por:
	 ip origen, 
	 ip destino, 
	 puerto orig, 
	 puerto dest, 
	 lista [ ids]
'''
def groupby1():
	alerts = conectToDB('tranalyzer','alertas')

	pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("count",-1),("_id",-1)])}]
	agrupIP = alerts.aggregate(pipeline) 
	
	#busco ip comunes y agrupo:
	#for aq in agrupIP:
		#pprint.pprint(aq) #pruebas de agrupar despues comentar este for
		#if aq[''] 
	
#	return agrupIP
	
#busco cada linea de agrupIP si coinciden las tuplas en la colección para añadir las lista de ids de los eventos y el id de los paquetes.

#def coincidencia(agrupIP):
	alerts = conectToDB('tranalyzer','alertas')
	flow = conectToDB('tranalyzer','flow')	
	hiperA = conectToDB('tranalyzer','HiperAlert')																#hiperAlert collection in mongodb 
	tupla = []
	count =[]
	idAlertas = []
	for a in agrupIP:
		#print(a["_id"])
		tupla= a["_id"]
		count= a["count"]
		#print(count)
		destIP = str(tupla['destIP']) #accedo al campo destIP de agrupIP
		srcIP = str(tupla['srcIP']) 
		srcPort = int(tupla['srcPort'])
		destPort = int(tupla['destPort'])
		findal = alerts.find({"event.source-ip":srcIP, "event.destination-ip":destIP,  "event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1})
		for b in findal:
			cadena = {"alerta":b}
			idAlertas.append(cadena)
			#pprint.pprint(b)
		#--------------------------------------#
		#print("--flow--")
		findfl = flow.find({"srcIP": srcIP, "srcPort": srcPort,  "dstIP": destIP, "dstPort":destPort},{"_id":1,"nDPIclass" :1}) #flow
		for c in findfl:
			flowid = c["_id"]
			prot = c["nDPIclass"]
			#pprint.pprint(c["_id"])
			#pprint.pprint(c["nDPIclass"])
		#print("-----------------------------------------")
		
		#insert into hiperalertas tupla, count, b["_id"] faltan los flujos y el tipo de protocolo
		myJson= {"tupla": a["_id"],
				"nAlertas": a["count"],
				"idAlertas": idAlertas,
				"flow" : flowid,
				"classificationProt":prot}
		#pprint.pprint(myJson)
		idAlertas = []																				
		hiperA.insert_one(myJson).inserted_id																					#Insert new file in mongo
	h = hiperA.find({"idAlertas":[{"alerta.event.event-id": 6}]})
	for n in h:
		pprint.pprint(n)
	#hiperA.drop()	
		
		
		
#end groupby1()



		
		
	#for f in find:
			
		
		
		
		
		
		#idf = q['_id']
		#tin = q['timeFirst']
	#	tfin = q['timeLast']
		#ipSrc = q['srcIP'] 
	#	pSrc = q['srcPort'] 
		#ipDes = q['dstIP'] 
	#	pDes = q['dstPort'] 
	
	
	
	
	
	#flows = conectToDB('tranalyzer','alertas')
	
#--------------------isoToUnix parser---------------#
def isoToUnixtime(time):

	parser= parse_date(str(time))	
	tupla = parser.timetuple()
	segundos = calendar.timegm(tupla) 
	
	return segundos
	
#-----------------update all isotime to unix it replace the fields timeFirst, timeLast, duration, tcpBtm--------------------------------#

def parsertime():
	flow = conectToDB('tranalyzer','flow')
	fl = flow.find()
	for f in fl:
		timeFirst = isoToUnixtime(f['timeFirst'])
		timeLast = isoToUnixtime(f['timeLast'])
		duration = isoToUnixtime(f['duration'])
		tcpBtm = isoToUnixtime(f['tcpBtm'])
		query = {"_id":f['_id']}
		updates = {"$set":{"timeFirst":timeFirst, "timeLast":timeLast, "duration":duration, "tcpBtm":tcpBtm}}
		flow.update_one(query, updates)
		
	
	#---------------------------MAIN PROGRAM-----------------#
if __name__ == '__main__':
	parsertime()
	#groupby1()
	
	
