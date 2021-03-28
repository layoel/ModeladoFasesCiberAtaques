import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox						#create message
from PIL import Image, ImageTk
from Controlador import Hyperalert, getHAlert, getIPListAlerts, parsertime
import tkinter.font as tkFont


def conexionNodes():
	conexionHA = conectToDBNodes("tranalyzer", "nodes")  
	return conexionHA


def showIP(): #muestra la lista de ips
	
	#ipText = Text(frTopCenter, padx = 8, pady= 4) #lista de ips
	
	listIPs = []
	listIPs = getIPListAlerts()
	row=0
	frTopCenterFull =  LabelFrame(scrollableFrameIP, padx = 10, pady=10)			#creo el frame
	frTopCenterFull.grid(column = 1, row = 0, rowspan=(len(listIPs)), sticky=W+E+N+S)
	for i in listIPs:
		Label(frTopCenterFull, text = i, font= ("verdana",8), justify = "left" ).grid(column=1, row=row)
		row=row+1
		#ipText.insert(END, i + '\n')
	#ipText.grid(column=1 , row=0)

def showDataAlert(tabla1, query):
	count = 0

	for a in query:
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


		tabla1.insert("",'end',text=event["priority"], values = (al["_id"], event["classification"], event["event-id"], event["event-second"], event["event-microsecond"]),tags= color)
		tabla1.tag_configure("red", background="#FF0000")
		tabla1.tag_configure("orange", background="#FFC100")
		tabla1.tag_configure("yellow", background="#FFFF1B")
		tabla1.tag_configure("green", background="#ACFF1B")
		count=count+1
	return count



def getHyperA():

	hyperA = getHAlert()
	row=0
	row1=0

	for doc in hyperA:
		alertas= doc["alerts"]
		nAlerts= int(doc["nAlerts"])
		
		#********************************************************************
		#                		 top right full frame
		#********************************************************************
		frTopRightFull =  LabelFrame(scrollableFrame,text= ("HyperAlert ID:",doc["_id"]), font= ("verdana",8, "bold"), padx = 10, pady=10)			#creo el frame
		frTopRightFull.grid(column = 2, row = row, rowspan=(nAlerts),columnspan=7, sticky=W+E+N+S)
			#********************************************************************
			#                		 top right left frame: Information
			#********************************************************************
		frTopRightLeft =  LabelFrame(frTopRightFull,text= ("Information"), font= ("verdana",8, "bold"), padx = 5, pady=5)			#creo el frame
		frTopRightLeft.grid(column = 2, row = row, rowspan=(nAlerts), columnspan=2,sticky=W+E+N+S)

		tk.Label(frTopRightLeft, text = "Flow ID",  anchor="w" ,font= ("verdana",8, "bold"), justify = "left" ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = doc["flow"] , anchor="w" ,font= ("verdana",8)).grid(column=3, row=row,sticky=W+E)
		row=row+1
		
		tk.Label(frTopRightLeft, text = "Protocol", anchor="w" ,font= ("verdana",8, "bold")).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = doc["classificationProt"], anchor="w", font= ("verdana",8)).grid(column=3, row=row,sticky=W+E)
		row=row+1

		tupla = doc["tupla"]
		
		tk.Label(frTopRightLeft, text = "Source IP" , anchor="w" ,font= ("verdana",8, "bold")).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = tupla["srcIP"] ,  anchor="w" ,font= ("verdana",8)).grid(column=3, row=row,sticky=W+E)
		row=row+1
		
		tk.Label(frTopRightLeft, text = "Source Port", anchor="w" , font= ("verdana",8, "bold")  ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = tupla["srcPort"] , anchor="w" , font= ("verdana",8) ).grid(column=3, row=row,sticky=W+E)
		row=row+1
		
		tk.Label(frTopRightLeft, text = "Dest IP", anchor="w" , font= ("verdana",8, "bold") ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = tupla["destIP"] ,  anchor="w" ,font= ("verdana",8) ).grid(column=3, row=row,sticky=W+E)
		row=row+1

		tk.Label(frTopRightLeft, text= "Dest Port",  anchor="w" ,font= ("verdana",8, "bold") ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text= tupla["destPort"] ,  anchor="w" ,font= ("verdana",8) ).grid(column=3, row=row,sticky=W+E)
		
			#********************************************************************
			#                		 top right right frame: Alerts
			#********************************************************************
		frTopRightRight = LabelFrame(frTopRightFull,text= ("Alerts List"), font= ("verdana",8, "bold"), padx = 5, pady=5)
		frTopRightRight.grid(column=4, row=row1, columnspan=5, rowspan=(nAlerts))

		tabla1 = ttk.Treeview(frTopRightRight, columns= ("#0","#1","#2","#3","#4","#5"), selectmode = "browse")
		tabla1.grid(column=4, row = row1, rowspan= 6, columnspan = 5, sticky=W+E+N+S)

		scrollYTable = ttk.Scrollbar(frTopRightRight, orient="vertical",command = tabla1.yview)
		scrollYTable.grid(column=9, row = row1, rowspan=6, sticky=W+E+N+S)
		tabla1.configure(yscrollcommand = scrollYTable.set)

		tabla1.heading("#0", text= "priority")
		tabla1.heading("#1", text= "id")
		tabla1.heading("#2", text= "classification")
		tabla1.heading("#3", text= "event-id")
		tabla1.heading("#4", text= "event-second")
		tabla1.heading("#5", text= "event-microsecond")

		row1 = row1+showDataAlert(tabla1, alertas)+1
		row = row1


def getGraphL1():
	imGraph = Image.open("GraphL1.png")
	imGraph.resize((300,155), Image.ANTIALIAS)
	show = ImageTk.PhotoImage(imGraph)

	grafo = Canvas(frBottomLeft, width= 300, height =155, bg= "#6600cc")
	grafo.create_image(15,0, image = imGraph, rowspan = 10, columnspan=5, anchor= NW)
	grafo.grid(row=20, column=0, rowspan = 10, columnspan=5, sticky=N+E)
	
	

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
	
	#window.grid_columnconfigure(0, weight=1)


	#********************************************************************
	#               crear una etiqueta y mostrarla
	#********************************************************************
	#mylable = Label(window, text="Hello world")
	#mylable.pack()

	#********************************************************************
	#             crear el lienzo y ponen el wallpaper
	#********************************************************************
	container= Frame(window)
	## Buttons FONDO
	#background = Canvas(container, width= 100, height =200, bg= "#6600cc")
	background = Canvas(container, width= 1024, height =768, bg= "#6600cc")
	#background.grid(row=0, column=0, columnspan=1,rowspan=6, sticky=N+S+W+E)
	background.grid(row=0, column=0, columnspan=10, sticky=N+S+W+E)
	image= ImageTk.PhotoImage(file = "./images/wallpaper.png")
	background.create_image(0,0, image = image, anchor= NW)
	
	

	

	#********************************************************************
	#                 		top left frame
	#********************************************************************

	frTopLeft = Frame(container, width= 50, height =200, padx =5, pady=5)
	#frTopLeft.pack()
	frTopLeft.grid(column=0, row=0, rowspan=6, sticky=N+W) #distancia a los bordes de la window
	#********************************************************************
	#                		 top center frame
	#********************************************************************
	
	frTopCenter =  LabelFrame(container,text= "IPs List", width= 120, height =200,padx = 5, pady=5)
	backgroundC = Canvas(frTopCenter, width=120 , height =200, bg= "#6600cc")
	
	scrollbarIP = ttk.Scrollbar(frTopCenter, orient="vertical",command = backgroundC.yview)
	scrollableFrameIP= ttk.Frame(backgroundC)

	scrollableFrameIP.bind(
		"<Configure>",
		lambda e: backgroundC.configure(
			scrollregion = backgroundC.bbox("all")
			)
		)

	backgroundC.create_window((0,0), window=scrollableFrameIP, anchor="nw")

	backgroundC.configure(yscrollcommand=scrollbarIP.set)

	frTopCenter.grid(row=0, column=1, rowspan=15, sticky=N+W)
	scrollbarIP.grid(row = 0, column=1, rowspan=15, sticky=E+N+S)
	backgroundC.grid(row=0, column=1, rowspan=15, sticky=N+S+W+E)

	
	## IPS FONDO
	#backgroundT = Canvas(frTopCenter, width= 100, height =200, bg= "#6600cc")
	#backgroundT.grid(row=0, column=1, rowspan=6, sticky=N+S+W+E)
	#transpImg = ImageTk.PhotoImage(file = "./images/wallpaper.png")
	#backgroundT.create_image(0,0, image = transpImg, anchor= NW)
	
	

	#********************************************************************
	#                		 top right frame
	#********************************************************************
	#backgroundR = Canvas(container, width= 100, height =200, bg= "#6600cc")
	#backgroundR.grid(row=0, column=2, columnspan=8,rowspan=6, sticky=N+S+W+E)
	#backgroundR.create_image(0,0, image = image, anchor= NW)
	frTopRight =  LabelFrame(container,text= "Hyper Alerts List", padx = 5, pady=5, width= 600, height=155)
	frTopRight.grid(column=2, row=0, rowspan=6,columnspan=8, sticky=N+W+E)

	## HYPERALERT FONDO
	backgroundR = Canvas(frTopRight, width= 600, height =155, bg= "#6600cc")
	backgroundR.grid(row=0, column=2, columnspan=8,rowspan=6, sticky=N+S+W+E)
	#transpImg = ImageTk.PhotoImage(file = "./images/wallpaper.png")
	#backgroundT.create_image(0,0, image = transpImg, anchor= NW)

	scrollbarTRVFrame=Scrollbar(frTopRight, orient=VERTICAL, command=backgroundR.yview) #scroll vertical
	scrollbarTRHFrame=Scrollbar(frTopRight, orient=HORIZONTAL, command=backgroundR.xview) #scroll Horizontal
	scrollableFrame= Frame(backgroundR)
	scrollableFrame.bind(
		"<Configure>",
		lambda e: backgroundR.configure(
			scrollregion = backgroundR.bbox("all")
			)
		)
	backgroundR.create_window((0,0), window=scrollableFrame, anchor="nw")
	backgroundR.configure(yscrollcommand=scrollbarTRVFrame.set, xscrollcommand=scrollbarTRHFrame.set)
	scrollbarTRVFrame.grid(row=0, column=10, rowspan=6, sticky=N+S+W+E)
	scrollbarTRHFrame.grid(row=6, column=0, columnspan=10, sticky=W+E)

	#********************************************************************
	#                		 bottom left frame
	#********************************************************************
	## GRAPH FONDO

	frBottomLeft =  LabelFrame(container,text= "Interaction Graph", padx = 5, pady=5)
	frBottomLeft.grid(column=0, row=6, sticky=W+E)


	#********************************************************************
	#                		 bottom right frame
	#********************************************************************
	## NODE FONDO
	frBottomRight =  LabelFrame(container,text= "Graphs Nodes Info", padx = 5, pady=5)
	frBottomRight.grid(column=1, row=6, sticky=W+E)




	#********************************************************************
	#                 top left frame: buttons
	#********************************************************************
	#create a button: Button(window, text="HyperAlert")
	hyperaButton = Button(frTopLeft, text="Show HyperAlert", padx = 16, pady= 2, command= getHyperA, bg= "#e699ff", fg= "#000000")
	hyperaButton.grid(row=0, column = 0, sticky=W+E)

	ipListButton = Button(frTopLeft, text="Show IPs" ,padx = 16, pady= 2, command= showIP,  bg= "#e699ff",fg= "#000000")
	ipListButton.grid(row=1, column = 0, sticky=W+E)

	graphL1Button = Button(frTopLeft, text="Interaction Graph L1", padx = 16, pady= 2, command= getGraphL1,bg= "#e699ff",  fg= "#000000")
	graphL1Button.grid(row=2, column = 0, sticky=W+E)

	graphL2Button = Button(frTopLeft, text="Interaction Graph L2", padx = 16, pady= 2, command= getGraphL2, bg= "#e699ff",fg= "#000000")
	graphL2Button.grid(row=3, column = 0, sticky=W+E)

	graphL3Button = Button(frTopLeft, text="Interaction Graph L3", padx = 16, pady= 2, command= getGraphL3, bg= "#e699ff",fg= "#000000")
	graphL3Button.grid(row=4, column = 0, sticky=W+E)

	closeApp=  Button(frTopLeft, text="Close App", padx = 16, pady= 2, command= window.destroy, bg= "#ff8080", fg= "#000000")
	closeApp.grid(row=5, column = 0, sticky=W+E)


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

	container.grid(row=0, column=0, columnspan=10,rowspan=2000, sticky=N+S+W+E)

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
