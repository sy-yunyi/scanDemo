from scapy.all import *
import pdb
class PortScanClass(object):
    def __init__(self,host,port):
        self.host = host
        self.port = port
    

    def TCPConnect(self):
        """
        TCP Connect扫描又称全连接扫描，此过程客户端会和服务端进行完整的3次握手。
        假设客户端想与服务端的80端口进行通信，首先客户端会发送一个带有SYN标识和端口号的TCP数据包给服务器，
        如果服务器这个端口是开放的，则会接受这个连接并返回一个带有SYN和ACK标识的数据包给客户端，
        随后客户端会发送带有ACK和RST标识的数据包给服务端，此时客户端与服务器建立了连接。
        如果端口不开放则会返回一个RST标识的数据包给客户端。
        """
        src_port = RandShort() 
        print("start scan host %s" % self.host)
        for dport in self.port:
            resp = sr1(IP(dst=self.host)/TCP(sport=src_port,dport=dport,flags="S"),timeout=10,verbose=0)
            if (resp is None):
                print("[+] %s %d \033[91m Closed \033[0m" % (self.host,dport))
            elif resp.haslayer("TCP"):
                if resp["TCP"].flags=="SA":  # 0x12
                    send_rst = sr(IP(dst=self.host)/TCP(dport=dport,flags="AR"),timeout=10,verbose=0)
                    print("[+] %s %d \033[92m open \033[0m" % (self.host,dport))
                elif resp["TCP"].flags=="RA":  # 0x14
                    print("[+] %s %d \033[91m Closed \033[0m" % (self.host,dport))


if __name__ == "__main__":
    task = PortScanClass("39.97.232.156",[9000,443,8000])
    task.TCPConnect()

