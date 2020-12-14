from pymongo import * 																													# mongo library
import json 																																		# import the built-in JSON library
import sys 																																			# get arg
import shutil 																																	# copy and move files
import time
from bson.son import SON																												#mongo map reduce
import pprint 																																	# to print json format like pretty() in mongo
import calendar																																	# to get datetime now
from iso8601 import parse_date																									# to parse isotime to unixtime


#************************************
#   it make the conection to mongodb
#************************************
def conectToDB(db, colection):

	conexion = MongoClient('localhost', 27017) 																		#the connection is local 
	db = conexion[db] 																														#the name of the db
	coleccion = db[colection]																											#the name of the collection where is the register of file 
	return coleccion																															# from snort insert in mongo and where is reading the file


	
	
#*********************************************************		
	#flows = conectToDB('tranalyzer','alertas')
# Agrupa alertas y flujos comunes ipO ipD pO pD segun el tiempo que se le pasa por parametro en sg	

#busco alertas ordenadas por event.second de menos a mas,  .sort([(campo1, pymongo.ASCENDING o 1),(campo2, pymongo.DESCENDING o -1)])
#agrupo alertas entre event.second de la primera y timesg, agrupo por ips, añado los flujos
#*********************************************************

def groupby2(timeSg):
	alerts = conectToDB('tranalyzer','alertas')
	pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("count",-1),("_id",-1)])}]
	agrupIP = alerts.aggregate(pipeline) 
	
	#selecciona una alerta, agrupa ipO ipD pO pD y tiempo >= "event-second" : 1492358992
	
	#agrupa los flujos "timeFirst" >= "event-second",
	# y "timeLast" <= : "event-second" + timeSg,
	 
	 
	 
#*************************************
#      isoToUnix parser
#*************************************
def isoToUnixtime(time):

	parser= parse_date(str(time))	
	tupla = parser.timetuple()
	segundos = calendar.timegm(tupla) 
	
	return segundos
	
#*******************************************************************
#  update all isotime to unix time. it replace the fields timeFirst,
#  timeLast, duration, tcpBtm in flow collection
#*******************************************************************

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
		
def menu():

	selectMenu = int(input())
	
	#************************************************************
	#TO CREATE HIPERALERT WE NEED ALERTS, CLASSIFICATIONS AND FLOW
	#
	#'''agrupar por:
	#	 ip origen, 
	#	 ip destino, 
	#	 puerto orig, 
	#	 puerto dest, 
	#	 lista [ ids]
	#'''
	#	
	#	idf = q['_id']
	#	tin = q['timeFirst']
	#	tfin = q['timeLast']
	#	ipSrc = q['srcIP'] 
	#	pSrc = q['srcPort'] 
	#	ipDes = q['dstIP'] 
	#	pDes = q['dstPort'] 
	#**************************************************************
	
	def groupby1():
		
		alerts = conectToDB('tranalyzer','alertas')
		flow = conectToDB('tranalyzer','flow')	
		hiperA = conectToDB('tranalyzer','HiperAlert')																#hiperAlert collection in mongodb 
		tupla = []
		count =[]
		idAlertas = []
		
		#find the same ip and aggregate:
		pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("count",-1),("_id",-1)])}]
		agrupIP = alerts.aggregate(pipeline) 

		for a in agrupIP:
			tupla= a["_id"]
			count= a["count"]
			destIP = str(tupla['destIP']) #get the field destIP from agrupIP
			srcIP = str(tupla['srcIP']) 
			srcPort = int(tupla['srcPort'])
			destPort = int(tupla['destPort'])
			#find in agrupIP the same tuplas to add in a list of events and the packet-id (is the same id than event.event-id)
			findal = alerts.find({"event.source-ip":srcIP, "event.destination-ip":destIP,  "event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1, "event.classification" :1}) #alerts	
			
			for b in findal:
				cadena = {"alerta":b}
				idAlertas.append(cadena)
				#pprint.pprint(b)
			#--------------------------------------#

			findfl = flow.find({"srcIP": srcIP, "srcPort": srcPort,  "dstIP": destIP, "dstPort":destPort},{"_id":1,"nDPIclass" :1}) #flow
			for c in findfl:
				flowid = c["_id"]
				prot = c["nDPIclass"]
				#pprint.pprint(c["_id"])
				#pprint.pprint(c["nDPIclass"])
			#print("-----------------------------------------")
			
			#insert into hiperalertas tupla, count, b["_id"], flows and the protocol type
			myJson= {"tupla": a["_id"],
					"nAlertas": a["count"],
					"idAlertas": idAlertas,
					"flow" : flowid,
					"classificationProt":prot}
			#pprint.pprint(myJson)
			idAlertas = []																				
			hiperA.insert_one(myJson).inserted_id																					#Insert new file in mongo
		
		h = hiperA.find()
		print("\n")
		for n in h:
			pprint.pprint(n)
			print("\n----------------------------------------------\n")
			
		####prueba de filtro id.alert.event.event....
		#h = hiperA.find({"idAlertas.alerta.event.event-id": 9})
		#for n in h:
		#	pprint.pprint(n)
		#hiperA.drop()	
	#end groupby1()
	
	#**************************************
	#   if you select an wrong option in menu	
	#**************************************
	def default():
		print("Wrong option")

	#**************************************
	#   exit the program	
	#**************************************
	
	def exitp():
		return 0
		
#menu mapping
	dict = {
		0 : exitp,
		1 : groupby1,
		#2: groupby2,
		#3: groupby3
		9 : default
	}
	event = dict.get(selectMenu, default)()

	return event
	
	
#*********************************************
#                  MAIN PROGRAM
#*********************************************

if __name__ == '__main__':
	#parsertime()
	event = None
	while(event == None):
		print("\n************************************************************")
		print("**                  Correlator                            **")
		print("************************************************************\n")
		print("This program performs alert, flows and events correlation \nto minimize the number of false positives in the detection of \nalerts and events related to a cyber attack")
		print("\n")
		print("Select the numbre of one method of correlation:\n")
		print("1 Group by Source IP, Source Port, Destination IP, Destination \n  Port and flow clasification.\n")
		print("2 Group by\n") 
		print("3 Group by\n") 
		print("4 Group by\n") 
		print("0 exit program\n")
		event = menu()

		
	
