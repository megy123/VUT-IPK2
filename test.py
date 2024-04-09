import sys
from socket import socket, AF_INET, SOCK_STREAM
import socket

HOST = "localhost"
PORT = 4567

def sendTCP():
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((HOST, PORT))
        s.send(b'TCP-test')
        s.close()
    except:
        print("")
        
def sendUDP():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes("UDP-test", "utf-8"), (HOST, PORT))
    
    
if(sys.argv[1] == "--tcp"):
    sendTCP()
    print("Sent TCP packet.")
elif(sys.argv[1] == "--udp"):
    sendUDP()
    print("Sent UDP packet.")
else:
    print("Invalid argument.")