# snif123
Packet sniffer
Using a raw socket, all the incoming traffic is captured and then unpacking all the packets headers to get information about protocol, mac addresses and IP addresses etc.
Steps involved-
1. Creating a raw socket.
2. capturing incoming frame and using the protocol value (such as ETHERNET II), ectracting information such upper layer protocol. 
3. Depending upon the protocol (ARP, DNS, IPV4 OR IPV6), next layer header fileds are unpacked and displayed in eihter he or decimal.
4. In addition upper transport layers are checked and depending upon whether it is TCP or UDP, dditional fields such as port numbers or acknowldgement and SYN fields are displayed.

 
