from tkinter import *
from Hyperalert import *

def conexionNodes():
	conexionHA = conectToDBNodes("tranalyzer", "nodes")  
	return conexionHA
	
	
def table():
	rows = []

	for i in range(5):
		cols = []
		for j in range(4):
			e = Entry(relief=GROOVE)
			e.grid(row=i, column=j, sticky=NSEW)
			e.insert(END, '%d.%d' % (i,j))
			cols.append(e)
		rows.append(cols)


mainloop()
		


























def groupby2():
		
		hiperA = conectToDB('tranalyzer','HiperAlert')																#hiperAlert collection in mongodb
		al = conectToDB('tranalyzer','alertas')
		hiperA.drop()
		timeAlerts = []
		timeFlow = []
		dataAlerts = []
		alerts = []
		
		timeAlerts = getListOfSecondsA() #obtengo las alertas ordenadas por seconds
		timeFlow = getListOfSecondsF()	#obtengo init y fin de flujos con tupla
			
		for a in timeAlerts: #recorro alertas
			destIP = a["destIP"]
			eventsecond = a["event-second"]
			srcIP = a["srcIP"]
			srcPort = a["srcPort"]
			destPort = a["destPort"]
			dataAlerts = al.find({"event.destination-ip":destIP, "event.event-second":eventsecond,"event.source-ip":srcIP,"event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1, "event.classification" :1, "event.priority":1, "event.event-second":1, "event.event-microsecond":1, "event.destination-ip":1, "event.event-second":1,"event.source-ip":1,"event.sport-itype":1, "event.dport-icode":1})	#buso el resto de datos de esas alertas
		
		for d in dataAlerts: #recorro alertas con todos los datos
			classification = d["event"]["classification"]
			destIP = d["event"]["destination-ip"] 
			eventsecond = d["event"]["event-second"]
			srcIP = d["event"]["source-ip"]
			srcPort =d["event"]["sport-itype"]
			destPort = d["event"]["dport-icode"]
			ide = d["_id"]
			eventid = d["event"]["event-id"]
			priority = d["event"]["priority"]
			second = d["event"]["event-second"]
			microsecond = d["event"]["event-microsecond"]
			event = d["event"]
			aJson={"alert":{"_id":ide, "event":{"classification": classification,"event-id":eventid,"event-microsecond":microsecond,"event-second":second, "priority":priority}}}
			alerts.append(aJson) #las guardo en json
			#pprint.pprint(alerts)										
		
		for f in timeFlow: #recorro los flujos
			for a in alerts: #recorro el json
				#pprint.pprint(a)
				if isBetween(f['secondsInit'], f['secondsFin'], a['alert']['event']['event-second']): 				#alert in a flow
					if "srcIP" in f:
						if (str(f['srcIP']) == str(a['srcIP'])):
							if (str(f['srcPort']) == str(a['srcPort'])):
								if (str(f['dstIP']) == str(a['destIP'])):
									if (str(f['dstPort']) == str(a['destPort'])): 
										alertJson={"alert":{"_id":a["_id"],"event":{"event-id": a["event-id"], "event-microsecond" : a["event-microsecond"], "event-second" : a["event-second"], "priority" : a["priority"]}}}
										alerts.append(alertJson)
										#print(alerts[0])
			if len(alerts) > 0:
				#alertJson = {"alert": {"_id":alerts["_id"], "event":{"Classification" : alerts["Classification"], "event-id" : alerts["event-id"], "event-microsecond" : alerts["event-microsecond"], "event-second" : alerts["event-second"], "priority" : alerts["priority"]}}}
				myJson = {"flow": f["_id"], "classificationProt":f["nDPIclass"],"tupla":{"srcIP":f['srcIP'],"srcPort": f['srcPort'],"destIP":f['dstIP'],"destPort":f['dstPort'] }, "alerts": alerts}
				hiperA.insert_one(myJson).inserted_id
				alerts = []
		
		h = hiperA.find()
		print("\n")
		for z in h:
			pprint.pprint(z)
			print("\n----------------------------------------------\n")
		
		
		#--------------------pruebas between--------
		#if fOa == "f": #flow
		#for f in lista:
		#	if f['secondsInit'] >= sgInit:
		#		if f['secondsFin'] <= sgFin:
		#			newList.append(f)
		#			
		#if fOa == "a": #alert
		#	for a in lista:
		#		if a['seconds'] >= sgInit:
		#			if a['seconds'] <= sgFin:
		#				newList.append(f)
		#-------------------------------------------------

		#-----------------------------------para acceder a t init o t fin de flow
		#z=0
		#for i in timeFlow:
			#print("--init--")
			#pprint.pprint(seconds[z]['secondsInit'])
			#print("---end--")
			#pprint.pprint(seconds[z]['secondsFin'])
			#z=z+1
		#-----------------------------------

	#end groupby2()
