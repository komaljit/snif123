import socket
import struct
import textwrap
import binascii

def Addr(hexa,st):
    a=binascii.hexlify(hexa)
    print st+' mac_address- {}'.format(a) 
def protocol(arg):
    print "protocol is ",binascii.hexlify(arg)

def IP(x,st):
    address=binascii.hexlify(x)
    a=['a']
    for i in range(0,4):
  
        b=address[2*i:(2*i+2)]
        g=int(b,16)
        a.append(str(g))
    del a[0]   
    a='.'.join(a)    
    print st+'IP_adsdress- {}'.format(a)

def sniffer():
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    try:
        data=s.recv(4096)
        dest_mac,source_mac,proto=struct.unpack('!6s6s2s',data[0:14])
        ip_header=data[14:34]
        source_ip,dest_ip=struct.unpack('!4s 4s',ip_header[12:20])
        return Addr(dest_mac,'destination'),Addr(source_mac,'source'),protocol(proto),IP(source_ip,'source'),IP(dest_ip,'Destination')
    except:
        pass

       
start=0
while True:
    try:   
        start=start+1
        print('Packet {}-'.format(start)) 
        sniffer()
    except KeyboardInterrupt:
        exit()

