import socket
import struct
import binascii

#  class for the sniffer in which incoming data is handled according type of protocol ie. Ether type, Ip version 4 or 6,
#  ARP,DNS,TCP or UDP protocol.   


class Sniffer:
    
    def __init__(self,mtu):                       
        self.mtu=mtu
        self.dest_mac,self.src_mac,self.Type=struct.unpack('!6s6s2s',self.mtu[0:14])
        a=binascii.hexlify(self.dest_mac)
        self.dest_mac=binascii.hexlify(self.dest_mac)
        self.src_mac=binascii.hexlify(self.src_mac)
        self.protocol=binascii.hexlify(self.Type)
        print(' Destination MAC address- {}'.format(self.dest_mac))
        print(' Source MAC address- {}'.format(self.src_mac))
        print(' Protocol- {}'.format(self.protocol))

#  Function to format Ipv4 address   

    def IP4(self,x):
        self.add=struct.unpack('!4B',x)  
        return ('.'.join(map(str,self.add)))

#  Function to format Ipv6 address
     
    def IP6(self,x):        
        self.add=struct.unpack('!8H',x)
        return ('.'.join(map(str,self.add)))
 
#  Function to handle TCP header

    def TCP(self):
        self.src_port,self.dest_port,self.seq_num,self.ack_num=struct.unpack('!HHHH',self.mtu[34:42])
        print('   TCP-')
        print('   Source port is {}'.format(self.src_port))
        print('   Destination address is {}'.format(self.dest_port))
        print('   Sequence number is {}'.format(self.seq_num))
        print('   Acknowledgement number is {}'.format(self.ack_num))           

#  Function to handle UDP header
                
    def UDP(self):
        print('   UDP- ')
        self.src_port,self.dest_port,self.length,self.checksum=struct.unpack('!HHH2s',self.mtu[34:42])
        print('   Sourcce port is {}'.format(self.src_port))    
        print('   Destination port is {}'.format(self.dest_port))
        print('   Length is {}'.format(self.length))
        print('   Checksum is {}'.format(binascii.hexlify(self.checksum)))
        
#  defining function to check networl layer protocol(IPv4 or 6) using Type field of Ethernet header and 
#  then using protocol field of network layer header to chrck transmission layer protocol ie. TCP or UDP

               
    def check(self,protocol):
         
        if protocol=='0800':
            self.ver_HL,self.Tos,self.Total_len=struct.unpack('!ssH',self.mtu[14:18])
            self.ver_HL=binascii.hexlify(self.ver_HL)
            self.TTL,self.prtcl,self.checksum=struct.unpack('!BB2s',self.mtu[22:26])
            print('  Protocol is IPv{}'.format(self.ver_HL[0]))
            print('  Header length is {}'.format(self.ver_HL[1]))          
            print('  Type of Service is {}'.format(binascii.hexlify(self.Tos)))
            print(' Total length is {}'.format(self.Total_len)) 
            print('  Time to live is {}'.format(self.TTL))
            print('  Tranport layer protocol is {}'.format(self.prtcl))
            print('  Checksum is {}'.format(binascii.hexlify(self.checksum)))
            print('  Source Ipv4 address- {}'.format(self.IP4(self.mtu[26:30])))
            print('  Destination Ipv4 address- {}'.format(self.IP4(self.mtu[30:34])))

            if self.prtcl==6:
                self.TCP
            if self.prtcl==17:
                self.UDP
        elif protocol=='0806':
            self.hard_type,self.prtcl_type,self.hard_add_size,self.prtcl_aad_size,self.opcode=struct.unpack('!2s2sBBH',self.mtu[14:22])
            print('   ARP header-')
            print('   Hardware Tpye is {}'.format(binascii.hexlify(self.hard_type)))
            print('   Protocol Type is {}'.format(binascii.hexlify(self.prtcl_type)))
            print('   Hardware address size {}'.format(self.hard_add_size))
            print('   Protocol size is {}'.format(self.prtcl_aad_size))
            print('   Opcode is {}'.format(self.opcode))

        elif protocol=="086d":
            self.src_add,self.dest_add=IP6(self.mtu[22:38]),IP6(self.mtu[38:54])
            print('   IPV6 packet-')
            print('   Source IPV6 address is {}'.format(self.src_add))
            print('   Destination IPV6 address is {}'.format(self.dest_add))

            if self.prtcl==6:
                TCP(self)
            if self.prtcl==17:
                UDP(self)             

        else:
            pass
       
            
if __name__==('__main__'):


#Creating a raw socket to receive incoming bytes

    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    start=0
    while True:
        start=start+1
        print('Packet {}'.format(start))
        frame=Sniffer(s.recv(4096))
        frame.check(frame.protocol)       

