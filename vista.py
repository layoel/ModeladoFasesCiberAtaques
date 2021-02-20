from tkinter import *
from tkinter import ttk
from tkinter import messagebox						#create message
from PIL import ImageTk
from Controlador import Hyperalert, getHAlert, getIPListAlerts


def conexionNodes():
	conexionHA = conectToDBNodes("tranalyzer", "nodes")  
	return conexionHA
	

def showIP(): #muestra la lista de ips

	ipText = Text(frTopCenter, padx = 8, pady= 4) #lista de ips
	listIPs = []
	listIPs = getIPListAlerts()
	for i in listIPs:
		ipText.insert(END, i + '\n')
	ipText.grid(column=1 , row=0)

def getHyperA():

	Hyperalert()
	hyperA = getHAlert()
	row=0
	row1=0
	for doc in hyperA:
		#********************************************************************
		#                		 top right full frame
		#********************************************************************
		frTopRightFull =  LabelFrame(frTopRight,text= ("HyperAlert ID:",doc["_id"]), font= ("verdana",8, "bold"), padx = 5, pady=10)			#creo el frame
		frTopRightFull.grid(column = 2, row = row)
			#********************************************************************
			#                		 top right left frame: Information
			#********************************************************************
		frTopRightLeft =  LabelFrame(frTopRightFull,text= ("Information"), font= ("verdana",8, "bold"), padx = 5, pady=10)			#creo el frame
		frTopRightLeft.grid(column = 2, row = row)

		Label(frTopRightLeft, text = "Flow ID", font= ("verdana",8, "bold"), justify = "left" ).grid(column=2, row=row)
		Label(frTopRightLeft, text = doc["flow"] , font= ("verdana",8)).grid(column=3, row=row)
		row=row+1
		
		Label(frTopRightLeft, text = "Protocol",font= ("verdana",8, "bold")).grid(column=2, row=row)
		Label(frTopRightLeft, text = doc["classificationProt"], font= ("verdana",8)).grid(column=3, row=row)
		row=row+1

		tupla = doc["tupla"]
		
		Label(frTopRightLeft, text = "Source IP" ,font= ("verdana",8, "bold")).grid(column=2, row=row)
		Label(frTopRightLeft, text = tupla["srcIP"] , font= ("verdana",8)).grid(column=3, row=row)
		row=row+1
		
		Label(frTopRightLeft, text = "Source Port", font= ("verdana",8, "bold")  ).grid(column=2, row=row)
		Label(frTopRightLeft, text = tupla["srcPort"] , font= ("verdana",8) ).grid(column=3, row=row)
		row=row+1
		
		Label(frTopRightLeft, text = "Dest IP", font= ("verdana",8, "bold") ).grid(column=2, row=row)
		Label(frTopRightLeft, text = tupla["destIP"] , font= ("verdana",8) ).grid(column=3, row=row)
		row=row+1

		Label(frTopRightLeft, text= "Dest Port", font= ("verdana",8, "bold") ).grid(column=2, row=row)
		Label(frTopRightLeft, text= tupla["destPort"] , font= ("verdana",8) ).grid(column=3, row=row)
		row=row+1
			#********************************************************************
			#                		 top right right frame: Alerts
			#********************************************************************
		frTopRightRight =  LabelFrame(frTopRightFull,text= ("Alerts"), font= ("verdana",8, "bold"), padx = 5, pady=10)			#creo el frame
		frTopRightRight.grid(column=4, row = row1)

		alertas= doc["alerts"]

		Label(frTopRightRight, text = "Priority", font= ("verdana",8, "bold") ).grid(column=4, row=row1)
		Label(frTopRightRight, text = "Alert ID", font= ("verdana",8, "bold") ).grid(column=5, row=row1)
		Label(frTopRightRight, text = "Classification", font= ("verdana",8, "bold") ).grid(column=6, row=row1)
		Label(frTopRightRight, text = "Event ID", font= ("verdana",8, "bold") ).grid(column=7, row=row1)
		Label(frTopRightRight, text = "Event Seconds", font= ("verdana",8, "bold") ).grid(column=8, row=row1)
		Label(frTopRightRight, text = "Event MicroSeconds", font= ("verdana",8, "bold") ).grid(column=9, row=row1)
		
		row1=row1+1
		for a in alertas:
			al = a['alert']
			event= al['event']
			if event["priority"] == 1:
				color="red"
			if event["priority"] == 2:
				color="orange"
			if event["priority"] == 3:
				color="yellow"
			if event["priority"] == 4:
				color="green"

			Label(frTopRightRight, text = event["priority"], font= ("verdana",8), bg=color ).grid(column=4, row=row1)
			Label(frTopRightRight, text = al["_id"], font= ("verdana",8) , bg=color).grid(column=5, row=row1)
			Label(frTopRightRight, text = event["classification"], font= ("verdana",8) , bg=color).grid(column=6, row=row1)
			Label(frTopRightRight, text = event["event-id"], font= ("verdana",8) , bg=color).grid(column=7, row=row1)
			Label(frTopRightRight, text = event["event-second"], font= ("verdana",8) , bg=color).grid(column=8, row=row1)
			Label(frTopRightRight, text = event["event-microsecond"], font= ("verdana",8) , bg=color).grid(column=9, row=row1)
			row1=row1+1
	


def getGraphL1():
	return 0
def getGraphL2():
	return 0
def getGraphL3():
	return 0


#*********************************************
#                  MAIN PROGRAM
#*********************************************

if __name__ == '__main__':	


	window = Tk()

	window.title("Phases of a Cyber-Attack tool")
	window.geometry("1024x768")
	window.attributes("-fullscreen", False)



	#********************************************************************
	#               crear una etiqueta y mostrarla
	#********************************************************************
	#mylable = Label(window, text="Hello world")
	#mylable.pack()

	#********************************************************************
	#             crear el lienzo y ponen el wallpaper
	#********************************************************************
	background = Canvas(window, width= 1024, height =768, bg= "#6600cc")
	background.pack(expand= True, fill = BOTH)
	image= ImageTk.PhotoImage(file = "./images/wallpaper.png")
	background.create_image(0,0, image = image, anchor= NW)

	#********************************************************************
	#                 		top left frame
	#********************************************************************

	frTopLeft = LabelFrame(background, padx =5, pady=5)
	#frTopLeft.pack()
	frTopLeft.grid(column=0, row=0) #distancia a los bordes de la window
	#********************************************************************
	#                		 top center frame
	#********************************************************************

	frTopCenter =  LabelFrame(background,text= "IPs List", padx = 5, pady=5)
	#frTopCenter.pack()
	frTopCenter.grid(column=1, row=0)

	#********************************************************************
	#                		 top right frame
	#********************************************************************

	frTopRight =  LabelFrame(background,text= "Hyper Alerts List", padx = 5, pady=5)
	frTopRight.grid(column=2, row=0)




	#********************************************************************
	#                		 bottom left frame
	#********************************************************************

	frBottomLeft =  LabelFrame(background,text= "Interaction Graph", padx = 5, pady=5)
	frBottomLeft.grid(column=0, row=6)

	#********************************************************************
	#                		 bottom right frame
	#********************************************************************

	frBottomRight =  LabelFrame(background,text= "Graphs Nodes Info", padx = 5, pady=5)
	frBottomRight.grid(column=1, row=6)




	#********************************************************************
	#                 top left frame: buttons
	#********************************************************************
	#create a button: Button(window, text="HyperAlert")
	hyperaButton = Button(frTopLeft, text="Show HyperAlert", padx = 16, pady= 2, command= getHyperA, bg= "#6600cc", fg= "#111111")
	hyperaButton.grid(row=0, column = 0)

	ipListButton = Button(frTopLeft, text="Show IPs" ,padx = 16, pady= 2, command= showIP,  bg= "#6600cc",fg= "#111111")
	ipListButton.grid(row=1, column = 0)

	graphL1Button = Button(frTopLeft, text="Interaction Graph L1", padx = 16, pady= 2, command= getGraphL1,bg= "#6600cc",  fg= "#111111")
	graphL1Button.grid(row=2, column = 0)

	graphL2Button = Button(frTopLeft, text="Interaction Graph L2", padx = 16, pady= 2, command= getGraphL2, bg= "#6600cc",fg= "#111111")
	graphL2Button.grid(row=3, column = 0)

	graphL3Button = Button(frTopLeft, text="Interaction Graph L3", padx = 16, pady= 2, command= getGraphL3, bg= "#6600cc",fg= "#111111")
	graphL3Button.grid(row=4, column = 0)


	#********************************************************************
	#                 top center frame: ips list
	#********************************************************************

	#***********
	# input box
	#***********
	#ipL1 = Button(frTopCenter, text="Interaction Graph L2")
	#ipL1.grid(row=0, column = 1)




	#canvasTopLeft = Canvas(frTopLeft)
	#scrollbarfrTopLeft = ttk.Scrollbar(frTopLeft, orient = "vertical", command = canvasTopLeft.yview)
	#scrollableTopLeft= ttk.Frame(frTopLeft)
	#scrollableTopLeft.bind("<Configure>", lambda e: canvasTopLeft.configure(scrollregion= canvasTopLeft.bbox("all")))

	#frTopCenter = Frame (window)
	#frTopRight = Frame(window)
	#frBottomLeft = Frame(window)
	#frBottomRight = Frame(window)







	#create line: mycanvas.create_line(x1, x2, y1, y2, fill = "color")
	#canvas.create_line(20, 20, 90, 20, fill = "white")


	#padding = 3
	#ancho = 8
	#alto = 2


	#hyperaButton = Button(frTopLeft, text="HyperAlert",width = ancho, height = alto, fg= "#6600cc", command = lambda: showIP(window)).place(x = 8, y = 10 )

	#ipListButton = Button(window, text="Show IPs",width = ancho, height = alto, fg= "#6600cc").place(x = 8, y = 10+padding*10*alto )

	#graphL1Button = Button(window, text="Interaction Graph L1",width = ancho+8, height = alto, fg= "#6600cc").place(x = 8, y = 10+padding*20*alto )
	#graphL1Button.grid()

	#graphL2Button = Button(window, text="Interaction Graph L2",width = ancho+8, height = alto, fg= "#6600cc").place(x = 8, y = 10+padding*30*alto )
	#graphL2Button.grid()

	#graphL3Button = Button(window, text="Interaction Graph L3",width = ancho+8, height = alto, fg= "#6600cc").place(x = 8, y = 10+padding*40*alto )
	#graphL3Button.grid()



	#table = ttk.Treeview(window, columns = 1)
	#table.grid(row=1,column =0, columnspan = 1)
	#table.heading("#0", text="IPs")




	window.mainloop()
		


























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
