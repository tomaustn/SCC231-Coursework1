#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

### REMOVE BELOW
from networkApp import NetworkApplication
from icmpPing import ICMPPing
### REMOVE ABOVE


import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading
# NOTE: Do NOT import other libraries!

UDP_CODE = socket.IPPROTO_UDP
ICMP_ECHO_REQUEST = 8
MAX_DATA_RECV = 65535
MAX_TTL = 30

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.231.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='udp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_m = subparsers.add_parser('mtroute', aliases=['mt'],
                                         help='run traceroute')
        parser_m.set_defaults(timeout=2, protocol='udp')
        parser_m.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_m.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_m.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_m.set_defaults(func=MultiThreadedTraceRoute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        return args

# A partially implemented traceroute 
class Traceroute(ICMPPing):

    def __init__(self, args):
        args.protocol = args.protocol.lower()

        # 1. Look up hostname, resolving it to an IP address
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s traceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))

        # 2. Initialise instance variables
        self.isDestinationReached = False

        # 3. Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 4. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 5. Run traceroute
        self.runTraceroute()

        # 6. Close ICMP socket
        self.icmpSocket.close()

    def runTraceroute(self):

        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        ttl = 1

        while(ttl <= MAX_TTL and self.isDestinationReached == False):
            if args.protocol == "icmp":
                self.sendIcmpProbesAndCollectResponses(ttl)

            elif args.protocol == "udp":
                self.sendUdpProbesAndCollectResponses(ttl)
            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
            ttl += 1

    # TODO: send 3 ICMP traceroute probes per TTL and collect responses
    def sendIcmpProbesAndCollectResponses(self, ttl):

        hopAddr = None
        icmpType = None
        pktKeys = []
        hopAddrs = dict()
        rtts = dict()

        numBytes = 48
        dstPort = 1024 # arb

        for i in range(3):
            # 1. Send one ICMP traceroute probe
            timeSent = self.sendOnePing(self.dstAddress, random.randint(1, 65535), ttl, dataLength=numBytes)

            # 2. Record a unique key (sequence number) associated with the probe
            pktKeys.append(i)

            replyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()

            if not replyPacket:
                continue

        seqNum, icmpType = self.parseICMPTracerouteResponse(replyPacket)

        if self.dstAddress == hopAddr and icmpType == 3:
            self.isDestinationReached = True

        if seqNum == i:
            rtts[i] = timeRecvd - timeSent
            hopAddrs[i] = hopAddr

        self.printMultipleResults(ttl, pktKeys, hopAddrs, rtts, args.hostname)
 
        #TODO

    # Send 3 UDP traceroute probes per TTL and collect responses
    def sendUdpProbesAndCollectResponses(self, ttl):
        
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        numBytes = 52
        dstPort = 33439
        
        for _ in range(3): 
            # 1. Send one UDP traceroute probe
            dstPort += 1
            timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)

            # 2. Record a unique key (UDP destination port) associated with the probe
            pkt_keys.append(dstPort)

            # 3. Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # 4. Extract destination port from the reply
            dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
        
            # 5. Check if we reached the destination 
            if self.dstAddress == hopAddr and icmpType == 3:
                self.isDestinationReached = True

            # 6. If the response matches the request, record the rtt and the hop address
            if dstPort == dstPortReceived:
                rtts[dstPort] = timeRecvd - timeSent
                hop_addrs[dstPort] = hopAddr

        # 7. Print one line of the results for the 3 probes
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)

    # Parse the response to UDP probe 
    def parseUDPTracerouteResponse(self, trReplyPacket):

        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # 3. Compute the IP header length
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        # 4. Parse the outermost ICMP header which is 8 bytes long:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        # This header contains type, Code and Checksum + 4 bytes of padding (0's)
        # We only care about type field
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 3 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, dst_port, _, _ = struct.unpack('!HHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])

        return dst_port, icmpType
    
    # TODO: parse the response to the ICMP probe
    def parseICMPTracerouteResponse(self, trReplyPacket):
        ipHeader = struct.unpack('!BBHHHBBH4s4s', trReplyPacket[:20]) # first 20 bytes of packet
        ipHeaderLenField = (ipHeader[0] & 0x0F)
        ipHeaderLen = ipHeaderLenField * 4
        
        # Parse first 8 bytes of ICMP header
        icmpHeader = struct.unpack('!BBHHH', trReplyPacket[ipHeaderLen:ipHeaderLen + 8])
        icmpType = icmpHeader[0]

        if icmpType == 3 or icmpType == 11: # destination unreachable or time exceeded
            innerIp = ipHeaderLen + 8
            innerIpHeader = struct.unpack('!BBHHHBBH4s4s', trReplyPacket[innerIp:innerIp + 20])
            innerIpHeaderLenField = (innerIpHeader[0] & 0x0F) * 4
            innerIcmpHeader = struct.unpack('!BBHHH', trReplyPacket[innerIp + innerIpHeaderLenField:innerIp + innerIpHeaderLenField + 8])
            seqNum = innerIcmpHeader[0]

        elif icmpType == 0: # echo reply -> extract sequence number
            seqNum = icmpHeader[3] # test if 3 or 4 later

        return seqNum, icmpType

    #TODO  

    def receiveOneTraceRouteResponse(self):

        timeReceipt = None
        hopAddr = None
        pkt = None

        # 1. Receive one packet or timeout
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            hopAddr = addr[0]
        
        # 2. Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None

        # 3. Return the packet, hop address and the time of receipt
        return pkt, hopAddr, timeReceipt

    def sendOneUdpProbe(self, destAddress, port, ttl, dataLength):

        # 1. Create a UDP socket
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)

        # 2. Use a socket option to set the TTL in the IP header
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 3. Send the UDP traceroute probe
        udpSocket.sendto(str.encode(dataLength * '0'), (destAddress, port))

        # 4. Record the time of sending
        timeSent = time.time()

        # 5. Close the UDP socket
        udpSocket.close()

        return timeSent

# TODO: A multi-threaded traceroute implementation
class MultiThreadedTraceRoute(Traceroute):

    def __init__(self, args):
        # 1. Initialise instance variables (add others if needed)
        args.protocol = args.protocol.lower()
        self.timeout = args.timeout
        self.send_complete = threading.Event()
        # NOTE you must use a lock when accessing data shared between the two threads
        self.lock = threading.Lock()
        self.dstAddress = None
        self.isDestinationReached = False

        self.dataPool = {
            "rtts" : dict(), # ttl:{port/seq: rtt}
            "hop_addrs" : dict(), # ttl:{port/seq: addr}
            "pkt_keys" : dict() # ttl: [ports/seqs]
        }

        # 2. Create a thread to send probes
        self.send_thread = threading.Thread(target=self.send_probes)

        # 3. Create a thread to receive responses 
        self.recv_thread = threading.Thread(target=self.receive_responses)

        # 4. Start the threads
        self.send_thread.start()
        self.recv_thread.start()

        # 5. Wait until both threads are finished executing
        self.send_thread.join()
        self.recv_thread.join()

        # 6. TODO Print results
            
    # Thread to send probes (to be implemented, a skeleton is provided)
    def send_probes(self):

        ttl = 1
        while ttl <= MAX_TTL and not self.isDestinationReached:

            with self.lock: # thread-safe access to shared data
                self.dataPool["rtts"][ttl] = dict()
                self.dataPool["hop_addrs"][ttl] = dict()
                self.dataPool["pkt_keys"][ttl] = []

            # Send three probes per TTL
            for _ in range(3):
                self.runTraceroute()  
                # if args.protocol == "icmp":
                #     self.sendIcmpProbesAndCollectResponses(ttl)
                #     pass # TODO: Remove this once this method is implemented       
                    
                # elif args.protocol == "udp":
                #     self.sendUdpProbesAndCollectResponses(ttl)
                #     pass # TODO: Remove this once this method is implemented       

                # Sleep for a short period between sending probes
                time.sleep(0.05)  # Small delay between probes

            ttl += 1

        # A final sleep before notifying the receive thread to exit
        time.sleep(args.timeout)
        # Notify the other thread that sending is complete
        self.send_complete.set()
        
        pass # TODO: Remove this once this method is implemented       

    # Thread to receive responses (to be implemented, a skeleton is provided)
    def receive_responses(self):

        # Keep receiving responses until notified by the other thread
        while not self.send_complete.is_set():

            if args.protocol == "icmp":
                pass # TODO: Remove this once this method is implemented       

            elif args.protocol == "udp":
                pass # TODO: Remove this once this method is implemented       

        pass # TODO: Remove this once this method is implemented       



# A basic multi-threaded web server implementation

# You can test the web server as follows: 
# First, run the server in the terminal: python3 NetworkApplications.py web 
# Then, copy the following and paste to a browser's address bar: 127.0.0.1:8080/index.html
# NOTE: the index.html file needs to be downloaded from the Moodle (Dummy HTML file)
# and copied to the folder where you run this code
class WebServer(NetworkApplication):

    def __init__(self, args):
        print('Web Server starting on port: %i...' % args.port)
        
        # 1. Create a TCP socket 
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Bind the TCP socket to server address and server port
        serverSocket.bind(("", args.port))
        
        # 3. Continuously listen for connections to server socket
        serverSocket.listen(100)
        print("Server listening on port", args.port)
        
        while True:
            # 4. Accept incoming connections
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # 5. Create a new thread to handle each client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

        # Close server socket (this would only happen if the loop was broken, which it isn't in this example)
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            # 1. Receive request message from the client
            message = connectionSocket.recv(MAX_DATA_RECV).decode()

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]

            # 3. Read the corresponding file from disk
            with open(filename[1:], 'r') as f:  # Skip the leading '/'
                content = f.read()

            # 4. Create the HTTP response
            response = 'HTTP/1.1 200 OK\r\n\r\n'
            response += content

            # 5. Send the content of the file to the socket
            connectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            connectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            connectionSocket.close()

# TODO: A proxy implementation 
class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

        pass # TODO: Remove this once this method is implemented       
            

# NOTE: Do NOT delete the code below
if __name__ == "__main__":
        
    args = setupArgumentParser()
    args.func(args)