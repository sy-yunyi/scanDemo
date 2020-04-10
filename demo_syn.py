import time
import random
import socket
import sys
from struct import *
import pdb

def checksum(msg):
    ''' Check Summing '''
    s = 0
    for i in range(0,len(msg),2):
        # pdb.set_trace()
        w = ((msg[i]) ) + ((msg[i+1])<< 8)
        s = s+w
        s = (s>>16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def IP_headchecksum(IP_head):
   checksum = 0
   headlen = len(IP_head)
   i=0
   while i<headlen:
       temp = unpack('!H',IP_head[i:i+2])[0]
       checksum = checksum+temp
       i = i+2
   checksum = (checksum>>16) + (checksum&0xffff)
   checksum = checksum+(checksum>>16)
   return ~checksum

def CreateSocket(source_ip,dest_ip):
    ''' create socket connection '''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as msg:
        print ('Socket create error: ',str(msg))
        sys.exit()
    ''' Set the IP header manually '''
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    return s
def CreateIpHeader(source_ip, dest_ip):
    ''' create ip header '''
    # packet = ''
    # ip header option
    headerlen = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    id = random.randrange(18000,65535,1)
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 10
    saddr = socket.inet_aton ( source_ip )
    daddr = socket.inet_aton ( dest_ip )
    hl_version = (version << 4) + headerlen
    ip_header = pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    return ip_header

def create_tcp_syn_header(source_ip, dest_ip, dest_port):
    ''' create tcp syn header function '''
    source = random.randrange(32000,62000,1) # randon select one source_port 
    seq = 0
    ack_seq = 0
    doff = 5
    
    ''' tcp flags '''
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (8192)    # max windows size
    check = 0
    urg_ptr = 0
    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn<<1) + (rst<<2) + (psh<<3) + (ack<<4) + (urg<<5)
    tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
    
    ''' headers option '''
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton( dest_ip )
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    tcp_checksum = checksum(psh)
    pdb.set_trace()
    ''' Repack the TCP header and fill in the correct checksum '''
    tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
    
    return tcp_header


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        source_ip = s.getsockname()[0]
    finally:
        s.close()
 
    return source_ip

def syn_scan(source_ip, dest_ip, des_port) :
    s = CreateSocket(source_ip, dest_ip)
    ip_header = CreateIpHeader(source_ip, dest_ip)
    tcp_header = create_tcp_syn_header(source_ip, dest_ip, des_port)
    packet = ip_header + tcp_header
    s.sendto(packet, (dest_ip, 0))
    data = s.recvfrom(1024) [0][0:]
    ip_header_len = (ord(data[0]) & 0x0f) * 4
    ip_header_ret = data[0: ip_header_len - 1]
    tcp_header_len = (ord(data[32]) & 0xf0)>>2
    tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len - 1]#SYN/ACK flags 
    if(ord(tcp_header_ret[13]) == 0x12):
        print  ("[+] %d open" % des_port)
	
if __name__ == "__main__":
    syn_scan("223.104.64.216","39.156.69.79",8080)
