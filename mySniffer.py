
from scapy.all import *
def pack_callback(packet):
    try:
        if packet.payload.dst =="39.97.232.156":
            print(packet.show())
        # print(packet.payload.dst)
    except:
        pass

sniff(prn=pack_callback)
