import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading
from networkApp import NetworkApplication
import NetworkApplications

UDP_CODE = NetworkApplications.UDP_CODE
ICMP_ECHO_REQUEST = NetworkApplications.ICMP_ECHO_REQUEST
MAX_DATA_RECV = NetworkApplications.MAX_DATA_RECV
MAX_TTL = NetworkApplications.MAX_TTL

class ICMPPing(NetworkApplication):
    
    def __init__(self, args):
        host = None
        # 1. Look up hostname, resolving it to an IP address
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return

        print('Ping to: %s (%s)...' % (args.hostname, host))

        # 1. Create an ICMP socket 
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 2. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 3. Send ping probes and collect responses 
        numPings = args.count
        seq_num = 0
        numPingsSent = numPings
        rtts = [] 
        while(numPings > 0):

            # 4. Do one ping approximately every second
            rtt, ttl, packetSize, seq = self.doOnePing(host, args.timeout, seq_num)

            # 5. Print out the RTT (and other relevant details) using the printOneResult method
            if rtt is not None:
                self.printOneResult(host, packetSize, rtt*1000, seq, ttl) 
                rtts.append(rtt)

            # 6. Sleep for a second
            time.sleep(1) 

            # 7. Update sequence number and number of pings
            seq_num += 1
            numPings -= 1

        # 8. Print loss and RTT statistics (average, max, min, etc.)
        self.printAdditionalDetails(args.hostname, numPingsSent, rtts)
        
        # 9. Close ICMP socket
        self.icmpSocket.close()

    # Receive Echo ping reply
    def receiveOnePing(self, destinationAddress, packetID, sequenceNumSent, timeout):
        
        # 1. Wait for the socket to receive a reply
        echoReplyPacket = None
        isTimedout = False
        try:
            echoReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
        except socket.timeout as e:
            isTimedout = True

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        timeRecvd = time.time()
        if isTimedout: # timeout
            return None, None, None, None

        # 3. Extract the IP header: 

        # The first 20 bytes is the IP header:  
        # (see: https://en.wikipedia.org/wiki/IPv4#/media/File:IPv4_Packet-en.svg):
        # 0          4             8          16          24           32 bits
        # |  Version | IP Hdr  Len |     TOS   |      Total Length     |
        # |         Identification             |Flag |  Fragment offset|
        # |        TTL             |  Protocol |     Header Checksum   |
        # |           Source IP  Address(32 bits, i.e., 4 bytes)       |
        # |           Destination IP Address (32 bits, i.e., 4 bytes)  |
        # |     Option (up to 40 bytes) this is an optional field      |

        ip_header = echoReplyPacket[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (version_ihl & 0x0F)

        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4

        payloadSize = total_length - ip_header_len

        # Now parse the ICMP header:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        #        <Optional timestamp (8 bytes) for     |
        #        a stateless ping>                     |        
        icmpHeader = echoReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, p_id, sequenceNumReceived = struct.unpack('!BBHHH', icmpHeader)

        # 5. Check that the ID and sequence numbers match between the request and reply
        if packetID != p_id or sequenceNumReceived != sequenceNumSent:
            return None, None, None, None

        # 6. Return the time of Receipt
        return timeRecvd, ttl, payloadSize, sequenceNumReceived

    # NOTE: This method can be re-used by ICMP traceroute
    # Send Echo Ping Request
    def sendOnePing(self, destinationAddress, packetID, sequenceNumber, ttl=None, dataLength=0):
        # 1. Build ICMP header
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNumber)
        
        # 2. Checksum ICMP packet using given function
        # include some bytes 'AAA...' in the data (payload) of ping
        data = str.encode(dataLength * 'A')
        my_checksum = self.checksum(header+data)

        # 3. Insert checksum into packet
        # NOTE: it is optional to include an additional 8-byte timestamp (time when probe is sent)
        # in which case, a stateless ping can be implemented: the response will contain
        # the sending time so no need to keep that state, 
        # but we don't do that here (instead, we record sending time state in step 5)
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packetID, sequenceNumber)

        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 4. Send packet using socket
        self.icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # 5. Record time of sending (state)
        timeSent = time.time()
        return timeSent

    def doOnePing(self, destinationAddress, timeout, seq_num):

        # 3. Call sendOnePing function
        packetID = random.randint(1, 65535)
        timeSent = self.sendOnePing(destinationAddress, packetID, seq_num, dataLength=48)

        # 4. Call receiveOnePing function
        timeReceipt, ttl, packetSize, seq = self.receiveOnePing(destinationAddress, packetID, seq_num, timeout)

        # 5. Compute RTT
        rtt = None
        if timeReceipt is None:
            print("Error receiveOnePing() has timed out")
        else:
            rtt = timeReceipt - timeSent

        # 6. Return total network delay, ttl, size and sequence number
        return rtt, ttl, packetSize, seq