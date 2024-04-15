import sys
from socket import socket, AF_INET, SOCK_STREAM
import socket
from icmplib import ping

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
    
def sendPing(ip):
    ping(ip)
    
if(len(sys.argv) < 2):
    exit(1);    

if(sys.argv[1] == "--tcp"):
    sendTCP()
    print("Sent TCP packet.")
elif(sys.argv[1] == "--udp"):
    sendUDP()
    print("Sent UDP packet.")
elif(sys.argv[1] == "--ping4"):
    sendPing('127.0.0.1')
    print("Sent ping4 packets.")
elif(sys.argv[1] == "--ping6"):
    sendPing('::1')
    print("Sent ping6 packets.")
else:
    print("Invalid argument.")