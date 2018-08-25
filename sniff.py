from scapy.all import *
def Sniff(pkt):
    print "-"*80
    print "\n\t\t\tIP\t"
    print "ID\t\t\t: ",pkt.id,"\nVersion\t\t\t: ",pkt.version,"\nLength of Packet\t: ",pkt.len,"\nTime to Leave\t\t: "\
,pkt.ttl,"\nProtocol\t\t: ",pkt.proto,"\nSource IP\t\t: ",pkt[IP].src,"\nDestination IP\t\t: ",pkt[IP].dst
    print "\n\t\t\tETHER\t"
    print "Source MAC\t\t: ",pkt[Ether].src,"\nDestination MAC\t\t: ",pkt[Ether].dst
    print "\n\t\t\tRAW\t"
    print str(pkt).encode("HEX")
    print "\n\t\t\tTCP\t"
    print "Source Port\t\t: ",pkt[TCP].sport,"\nDestination\t\t: ",pkt[TCP].dport
    
sniff(filter='tcp',count=10,prn=Sniff)