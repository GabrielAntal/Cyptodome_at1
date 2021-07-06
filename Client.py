#! /usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad 
from base64 import b64encode, b64decode # biblioteca que transforma os dados dem ASCII ou em binário
import socket
import sys
import time
import threading
import select
import traceback
import os


key= b']\x9c\xdbC\x17\x1f\xfa\x89\xda\x12kf\x15\xee\r\xb2'

iv = b'f\xf0b\xc2E\xa2\xb8\xc5W^\xf1\x8c\xe1`\xbe2'


class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
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
                        print(chunk.decode() + '\n>>')
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):

   

    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):

        sent = self.sock.send(msg)

        # print "Sent\n"

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
        srv.start()
        while 1:
            # print "Waiting for message\n"
           
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue

        
            msg = user_name + ': ' + msg + '\n'
            cipher = AES.new(key,AES.MODE_CBC, iv);  #criar a cifra com chave e o modo em CBC
            ct_bytes = cipher.encrypt(pad(msg.encode('utf-8'), AES.block_size))
            ct = b64encode(ct_bytes).decode('utf-8')
            data = ct.encode()
            #print("antes ->"+ str(ct_bytes) +"\n")
           
            self.client(host, port, data)
        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()