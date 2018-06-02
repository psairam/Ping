from socket import *
from struct import pack
from random import randint
from binascii import crc_hqx
from time import time


class IpHeader:

    def __init__(self, src_addr, dest_addr, ttl, protocol=1):
        self.version = 4 # version should be changd
        self.header_length = 5
        self.tos = 0
        self.total_length = 20
        self.id = randint(0,0xFFFF)
        self.frag = 0
        self.ttl = ttl
        self.protocol = protocol # check icmpv6 protocol number
        self.checksum = 0
        self.src_addr = inet_aton(src_addr)
        self.dst_address = inet_aton(dest_addr)
        self.ver_hl = (self.version << 4) + self.header_length

    def calc_checksum(self):
        msg = pack("!BBHHHBBH4s4s", self.ver_hl, self.tos, self.total_length, self.id, self.frag, self.ttl, self.protocol, self.checksum, self.src_addr, self.dst_address)
        chksum=crc_hqx(msg,0) & 0xFFFF
        return chksum
        # sum = 0
        # countTo = (len(msg) / 2) * 2
        # count = 0
        # while count < countTo:
        #     thisVal = ord(msg[count + 1]) * 256 + ord(msg[count])
        #     sum += thisVal
        #     sum = sum & 0xffffffff
        #     count = count + 2
        #
        # if countTo < len(msg):
        #     sum += ord(msg[len(msg) - 1])
        #     sum = sum & 0xffffffff
        #
        # sum = (sum >> 16) + (sum & 0xffff)
        # sum +=  (sum >> 16)
        # answer = ~sum
        # chksum = answer & 0xffff
        #
        # checksum = chksum >> 8 | (chksum << 8 & 0xff00)
        #
        # return checksum

    def header(self,checksum):
        pkt = pack("!BBHHHBBH4s4s", self.ver_hl, self.tos, self.total_length, self.id, self.frag, self.ttl, self.protocol, checksum, self.src_addr, self.dst_address)
        return pkt


class IcmpHeader:

    def __init__(self, seq_num):
        self.code = 8
        self.type = 0
        self.checksum = 0
        self.id = randint(0,0xffff)
        self.seq_num = seq_num


    def calc_checksum(self):
        b = pack("!BBHHH", self.code, self.type, self.checksum, self.id, self.seq_num)
        # sum = 0
        # countTo = (len(msg) / 2) * 2
        # count = 0
        # while count < countTo:
        #     thisVal = ord(msg[count + 1]) * 256 + ord(msg[count])
        #     sum += thisVal
        #     sum = sum & 0xffffffff
        #     count = count + 2
        #
        # if countTo < len(msg):
        #     sum += ord(msg[len(msg) - 1])
        #     sum = sum & 0xffffffff
        #
        # sum = (sum >> 16) + (sum & 0xffff)
        # sum +=  (sum >> 16)
        # answer = ~sum
        # chksum = answer & 0xffff
        #
        # checksum = chksum >> 8 | (chksum << 8 & 0xff00)
        #
        # return checksum
        so=[]
        for i in range(0,len(b),2):
            b1=bin(b[i])
            b2=bin(b[i+1])
            s1=str(b1[2:])
            s2=str(b2[2:])
            if(len(s1)<8):
                s1=(8-len(s1))*'0'+s1
            if(len(s2)<8):
                s2=(8-len(s2))*'0'+s2
            s3=s1+s2
            so.append(s3)
        t=0
        for i in so:
            t+=int(i,2)
        if(t>65535):
            return (131071-t)
        else:
            return (65535-t)


    def header(self,checksum):
        pkt = pack("!BBHHH", self.code, self.type, checksum, self.id, self.seq_num)
        return pkt





if __name__ == '__main__':
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    send_sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    recv_sock.bind(("0.0.0.0", 0x800))
    recv_sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    recv_sock.setblocking(0)
    recv_sock.settimeout(10)

    src_addr=[(i.connect(('8.8.8.8', 53)), i.getsockname()[0], i.close()) for i in [socket(AF_INET, SOCK_DGRAM)]][0][1] #should be able to get both ipv4 and ipv6 address

    dest = input("enter the website that you want to find the route: ")
    dest_addr = gethostbyname(dest) #should be able to get both ipv4 and ipv6 address

    ttl = 1
    addre = ''
    print("max 30 hops")

    while addre != dest_addr and ttl<30:

        ip = IpHeader(src_addr, dest_addr, ttl)
        ip_checksum = ip.calc_checksum()
        ipheader = ip.header(ip_checksum)

        icmp = IcmpHeader(ttl)
        icmp_checksum = icmp.calc_checksum()
        icmpheader = icmp.header(icmp_checksum)

        packet = ipheader+icmpheader
        start_time = time()
        send_sock.sendto(packet, (dest_addr, 0))
        try:
            pkt, addr = recv_sock.recvfrom(4096)
            end_time = time()

            addre = addr[0]
            dn=getfqdn(addre)
            total_time = round(end_time-start_time,3)*1000
            print("%2d, %4d, %15s, %s",ttl,total_time,addre,dn)
            print(ttl, total_time,"ms ", addre, dn)
        except:
            print(ttl," *","    *","    *")
        ttl += 1
