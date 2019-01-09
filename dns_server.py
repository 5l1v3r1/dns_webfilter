import socket
import sys

class DNSQuery:
	def __init__(self, data):
		self.data=data
		self.dominio=''

		tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
		if tipo == 0:                     # Standard query
			ini=12
			lon=ord(data[ini])
			while lon != 0:
				self.dominio+=data[ini+1:ini+lon+1]+'.'
				ini+=lon+1
				lon=ord(data[ini])


	def answer(self, ip):
		packet=''
		if self.dominio:
			packet+=self.data[:2] + "\x81\x80"
			packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'	# Questions and Answers Counts
			packet+=self.data[12:]											# Original Domain Name Question
			packet+='\xc0\x0c'												# Pointer to domain name
			packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'				# Response type, ttl and resource data length -> 4 bytes
			packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))	# 4bytes of IP
		return packet


def resolve (p, addr):
	dom = p.dominio[:-1]							# Dominio RAW
	dom_req = dom.split(".")						# Dominio richiesto
	dom_comp = dom_req[-2] + "." + dom_req[-1]		# Dominio per comparazione

	if "TUTTI" in PERMESSI:
		ip = str(socket.gethostbyname_ex(dom)[2][0])
		udps.sendto(p.answer(ip), addr)
	else:

		if dom_comp in PERMESSI:
			ip = str(socket.gethostbyname_ex(dom)[2][0])
			udps.sendto(p.answer(ip), addr)
		else:
			udps.sendto(p.answer('127.0.0.1'), addr)
	


PERMESSI = [] #["example.com"]
f_data = ""

try:
	f = open("permessi.txt", 'r')
	f_data = f.read()
	f.close()
except:
	try:
		f = open("permessi.txt", 'w')
		f.write("example1.com\n")
		f.write("example2.com\n")


		f.close()
	except Exception, e:
		print "[!] Impossibile leggere e scrivere sul file permessi.txt"
		print e
		raw_input ("\n[*] Premere INVIO per uscire...")
		sys.exit (-1)


PERMESSI = [s.strip() for s in f_data.splitlines()]

if len(PERMESSI) < 1:
	print "[!] Nessun sito nel file permessi.txt"
	print "[I] Inserire almeno un sito e riavviare il programma."
	raw_input ("[*] Premere INVIO per uscire...")
	sys.exit (-1)

try:
	udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	udps.bind(('',53))
except Exception, e:
	print "[!] Impossibile avviare il server"
	print e
	raw_input ("\n[*] Premere INVIO per uscire...")
	sys.exit (-1)

if "TUTTI" in PERMESSI:
	print "[*] Server avviato, nel file permessi.txt e' presente"
	print "    la parola \"TUTTI\" quindi tutti i siti possono essere visitati"

else:
	print "[*] Server avviato, gli utenti posso navigare nei seguenti siti: "
	for l in PERMESSI:
		print "-) " + l

	print "\n\n[N] Nota, inseire la parola \"TUTTI\" (senza virgolette)"
	print "    nel file permessi.txt per permettere l'accesso a tutti i siti."
	print "\n\n[I] Premere ctrl+c per interrompere..."

while 1:
	try:
		data, addr = udps.recvfrom(1024)
		p=DNSQuery(data)

		resolve(p, addr)

	except KeyboardInterrupt:
		print "[*] Fine"
		udps.close()
		raw_input ("\n[*] Premere INVIO per uscire...")
		sys.exit(1)

	except:
		pass