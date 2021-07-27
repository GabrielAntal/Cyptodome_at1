#! /usr/bin/env python
from Crypto.Cipher import AES, PKCS1_OAEP #PKCS1_OAEP é um pacote que de cifra assimétrica utilizada junto com o RSA para fazer o preenchimento e criação da cifra para criptografia
from Crypto.PublicKey import RSA #Pacote para criar par de chaves assimétricas baseado no algoritmo de RSA
from Crypto.Util.Padding import pad, unpad #biblioteca para fazer preenchimento
from base64 import b64encode, b64decode # biblioteca que transforma os dados dem ASCII ou em binário
import socket
import sys
import time
import threading
import select
import traceback
import os, os.path
from Crypto.Hash import SHA3_224 #usando o sha para fazer o hash
from Crypto.Signature import pkcs1_15 #pacote para fazer a assinatura baseado em RSA


key= b']\x9c\xdbC\x17\x1f\xfa\x89\xda\x12kf\x15\xee\r\xb2' #chave simétrica

iv = b'f\xf0b\xc2E\xa2\xb8\xc5W^\xf1\x8c\xe1`\xbe2' #vetor de iniciação para ser usado no CBC


class Server(threading.Thread):
    

    def initialise(self, receive):
        self.receive = receive
        
    def getUser(self, name):
        self.name =name
                

    def run(self):
        lis = []
        lis.append(self.receive)
        user= self.name

        



        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    
                    s = item.recv(1024)
                    if s != '':
                        
                        
                       
                        ci_txt = b64decode(s)
                        
                      
                        cipher = AES.new(key, AES.MODE_CBC,  iv)
                        dec=cipher.decrypt(ci_txt)
                        chunk = unpad(dec, AES.block_size)
                        
                        hash1 = SHA3_224.new(chunk)
                        cli = Client()
                        
                        comp =cli.hashcompare(hash1, user, chunk)
                        if comp:
                            print(chunk.decode() + '\n>>')
                        else:
                            print('Hashs não batem')    
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):

   

    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):

        sent = self.sock.send(msg)

        # print "Sent\n"

    def check(self, direc): #checa o diretório para ver se tem mais de um arquivo criado
        while 1:
            count = os.listdir(direc)
            if len(count)==1:
                
                continue
            if len(count)>=2:
                
                return(0)   
        return (1) 

    def handshake(self,name, dir):
        
        for file in os.listdir(dir):
            if (name+'.pem')!= file : #verifica o arquivo que não é do usuário que gerou, mas sim do destinatário
             completeName = os.path.join(dir, file)   
             f = open(completeName,'r')
             keyPub = RSA.import_key(f.read())
             encryptor= PKCS1_OAEP.new(keyPub)
             encrypted = encryptor.encrypt(key) # faz criptografia da chave simétrica com a chave pública do destinatário
             

             direc='C://Users//gabri//OneDrive//Documentos//Estudos//UTFPR//Trabalhos para fazer//SAS//Ativ_2//Cyptodome_at1//priv//'
             completeName = os.path.join(direc, file)     
             f = open(completeName,'r')
             keyPriv = RSA.import_key(f.read())
             
             decryptor= PKCS1_OAEP.new(keyPriv)
             decr = decryptor.decrypt(encrypted) #decriptografa a chave simétrica com a chave privada do usuário remetente
             hash1 = SHA3_224.new(decr)
             
             comp =self.hashcompare(hash1, name,key)  #manda o hash da chave simétrica, o nome do usuário e a chave simétrica em si como parâmetros para ser feita função de comparação  
             if comp:
                print('Handshake concluido')
                return True
             else: 
                 print('Handshake não concluído')
                 return False



             
    def hashcompare(self, has,name, vl): #faz a comparação dos hashs do valor passado feita com a assinatura
        
        direc='C://Users//gabri//OneDrive//Documentos//Estudos//UTFPR//Trabalhos para fazer//SAS//Ativ_2//Cyptodome_at1//priv//'
        completeName = os.path.join(direc, name+'.pem')     
        f = open(completeName,'r')
        Privkey= RSA.import_key(f.read())
        h = SHA3_224.new(vl)
        signature = pkcs1_15.new(Privkey).sign(h)#assina com a chave privada do remetente

        direc='C://Users//gabri//OneDrive//Documentos//Estudos//UTFPR//Trabalhos para fazer//SAS//Ativ_2//Cyptodome_at1//pub//'
        completeName = os.path.join(direc, name+'.pem')     
        f = open(completeName,'r')
        Pubkey = RSA.import_key(f.read())
        h = SHA3_224.new(vl)#faz o hash da chave simétrica
        try:
            pkcs1_15.new(Pubkey).verify(h, signature)#verifica a autencicidade comparando as assinaturas da chave pública com a chave privada do remetente e verifica
                                                    # se o hash bate com o hash da chave

            if h.digest() == has.digest(): #compara os hashs em formato digest para verificar o seu valor
                
                 return True
            else:
                return False
                
                

            
        except (ValueError, TypeError):
            print ("The signature is not valid.")
 
        
            
    def run(self):
    
        cipher = AES.new(key,AES.MODE_CBC);  #criar a cifra com chave e o modo em CBC
       

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP \n>>")
            port = int(input("Enter the server Destination Port\n>>"))
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
       
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.getUser(user_name)
        srv.start()

        # criação do par de chaves com RSA e guardando a chave privada e publica em locais diferentes
        keyP = RSA.generate(2048)
        direc1='C://Users//gabri//OneDrive//Documentos//Estudos//UTFPR//Trabalhos para fazer//SAS//Ativ_2//Cyptodome_at1//priv//'#diretorio das chaves privadas
        completeName = os.path.join(direc1, str(user_name)+'.pem')#utilizando o path para estruturar o diretórico com o nome do arquivo, que no caso é o nome do usuário
        f = open(completeName,'wb')
        f.write(keyP.export_key('PEM'))#escrevendo a chave privada no arquivo
        f.close()
       
        
        
        pubKey = keyP.public_key()
     
        direc='C://Users//gabri//OneDrive//Documentos//Estudos//UTFPR//Trabalhos para fazer//SAS//Ativ_2//Cyptodome_at1//pub//'#diretorio das chaves publicas
        completeName = os.path.join(direc, str(user_name)+'.pem')
        f = open(completeName ,'wb')
        f.write(pubKey.export_key('PEM'))#gravando a cha pública no arquivo 
        f.close()
        self.check(direc)# verifica se tem duas chaves armazenadas, indicando dois usuários conectados

        cond = self.handshake(user_name, direc) # chamada para o handshake
        
        if cond:
        

            while 1:
                # print "Waiting for message\n"
            
                msg = input('>>')
                if msg == 'exit':
                    break
                if msg == '':
                    continue

            
                msg = user_name + ': ' + msg 
                cipher = AES.new(key,AES.MODE_CBC, iv);  #criar a cifra com chave e o modo em CBC
                ct_bytes = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size)) #criptografa usando padding para deixar o tamanho do bloco do tamanho esperado
                ct = b64encode(ct_bytes).decode('utf-8') 
                data = ct.encode()
                #print("antes ->"+ str(ct_bytes) +"\n")
            
                self.client(host, port, data)
            return (1)
        else: 
            print ('Tente novamente')

if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
