from scapy.all import *

def sniffer(pkt):
	'''printing only SRC IP and DST IP ,DST port ,Payload  '''
	if pkt[IP].dport == 80:
		print("\n{} -----HTTP----- {}:{}:\n{}".format(pkt[IP].src,pkt[IP].dst,pkt[IP].dport,str(bytes(pkt[TCP].payload))))
	#print ("source MAC :%s<-------> dest MAC: %s"%(pkt[Ether].src,pkt[Ether].dst))
	#print(pkt[TCP].show())

sniff(filter='tcp port 80' , count=10,prn=sniffer)


Something is changed..





