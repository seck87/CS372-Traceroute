# Name: Murat Seckin Kuvandik
# OSU Email: kuvandim@oregonstate.edu
# Course: CS372
# Citations for the following code structure:
# Date: 02/14/2024
# Copied from /OR/ Adapted from /OR/ Based on:
# Textbook: Computer Networking: A Top-Down Approach 8th Edition, James F. Kurose, Keith W. Ross
# Source URLs:
# https://www.cloudflare.com/learning/network-layer/what-is-a-computer-port/#:~:text=What%20are%20the%20different%20port,File%20Transfer%20Protocol%20(FTP).
# https://aws.amazon.com/what-is/icmp/
# https://www.educative.io/answers/what-is-the-python-struct-module
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
# https://en.wikipedia.org/wiki/Ping_(networking_utility)
# https://en.wikipedia.org/wiki/File:Cmd-ping.png **Standart ping program output/report
# https://en.wikipedia.org/wiki/Traceroute
# https://datatracker.ietf.org/doc/html/rfc1739#page-5
# https://datatracker.ietf.org/doc/html/rfc1739#page-7
# https://docs.python.org/3/library/struct.html
# https://inspector.dev/how-to-round-numbers-in-python-fast-tips/#:~:text=The%20simplest%20way%20to%20round,rounded%20to%20the%20nearest%20integer.
# https://flexiple.com/python/python-new-line
# https://www.sciencedirect.com/topics/computer-science/packet-loss-rate#:~:text=The%20reliability%20of%20a%20communication,total%20number%20of%20packets%20sent.
# https://canvas.oregonstate.edu/courses/1946206/pages/programming-project-primer-traceroute-faq?module_item_id=23965635
# https://edstem.org/us/courses/51611/discussion/4241558
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
# https://www.learndatasci.com/solutions/python-valueerror-too-many-values-unpack/
# https://www.w3schools.com/python/python_try_except.asp
# https://www.w3schools.com/python/ref_func_round.asp
# https://stackoverflow.com/questions/5306756/how-to-print-a-percentage-value
# https://www.reddit.com/r/learnpython/comments/4lo0sj/how_to_make_a_dictionary_with_intervals_as_keys/
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-5
# https://www.geeksforgeeks.org/traceroute-implementation-on-python/
# https://www.hellotech.com/guide/for/how-to-run-a-traceroute-windows-10
# https://stackoverflow.com/questions/4271740/how-can-i-use-python-to-get-the-system-hostname
# https://stackoverflow.com/questions/2575760/python-lookup-hostname-from-ip-with-1-second-timeout
# https://edstem.org/us/courses/51611/discussion/4315409
# https://edstem.org/us/courses/51611/discussion/4277060
# https://www.programiz.com/python-programming/break-continue
# https://www.tutorialspoint.com/how-to-align-text-strings-using-python
# skeleton code provided at: https://canvas.oregonstate.edu/courses/1946206/assignments/9512468?module_item_id=23965633

# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:

    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 5                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output
        __address = None
        __Rtt = None
        __Timeout = None
        __traceRouteFlag = False        # Functions will not print if called by traceroute

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getIPAdress(self):
            return self.__address[0]

        def getRtt(self):
            return self.__Rtt

        def checkTimeout(self):
            return self.__Timeout

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setTraceRouteFlag(self, boolean):
            self.__traceRouteFlag = boolean

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm (looks like the link doesn't work any more so check below) 
            # https://web.archive.org/web/20220414173629/http://www.networksorcery.com/
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.

            # Confirm the following items received are the same as what was sent:
            # sequence number
            # packet identifier
            # raw data

            # Retrieve the items from reply packet
            sequenceNumberReceived = icmpReplyPacket.getIcmpSequenceNumber()
            packetIdentifierReceived = icmpReplyPacket.getIcmpIdentifier()
            rawDataReceived = icmpReplyPacket.getIcmpData()

            # Initialize sent items
            sequenceNumberSent = self.getPacketSequenceNumber()
            packetIdentifierSent = self.getPacketIdentifier()
            rawDataSent = self.getDataRaw()

            # Check sequence number match and set the boolean value in reply packet
            if sequenceNumberReceived == sequenceNumberSent:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
            else:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(False)

            # Check packet identifier match and set the boolean value in reply packet
            if packetIdentifierReceived == packetIdentifierSent:
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            else:
                icmpReplyPacket.setIcmpIdentifier_isValid(False)

            # Check raw data match and set the boolean value in reply packet
            if rawDataReceived == rawDataSent:
                icmpReplyPacket.setIcmpData_isValid(True)
            else:
                icmpReplyPacket.setIcmpData_isValid(False)

            # Share sent data with reply object
            icmpReplyPacket.setSequenceNumberOriginal(sequenceNumberSent)
            icmpReplyPacket.setPacketIdentifierOriginal(packetIdentifierSent)
            icmpReplyPacket.setRawDataOriginal(rawDataSent)

            # Set the valid data variable in the IcmpPacket_EchoReply class based the outcome of the data comparison,
            # after confirming the items received are the same as what was sent.

            if (icmpReplyPacket.getIcmpSequenceNumber_isValid() and icmpReplyPacket.getIcmpIdentifier_isValid()
                    and icmpReplyPacket.getIcmpData_isValid()):
                icmpReplyPacket.setIsValidResponse(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)


        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, printOption):
            if not self.__icmpTarget or not self.__destinationIpAddress:
                self.setIcmpTarget("127.0.0.1")

            if printOption:
                print(f"\nPinging ({self.__icmpTarget}) {self.__destinationIpAddress}")

            with socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as mySocket:
                mySocket.settimeout(self.__ipTimeout)
                mySocket.bind(("", 0))
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))
                try:
                    self.__sendPacket(mySocket)
                    return self.__receiveAndProcessReply(mySocket)
                except timeout:
                    self.__Timeout = True
                    if not self.__traceRouteFlag:
                        print("  *        *        *        *        *    Request timed out (By Exception).")
                    return None, 0, 1

        def __sendPacket(self, mySocket):
            mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))

        def __receiveAndProcessReply(self, mySocket):
            start_time = time.time()
            recvPacket, addr = mySocket.recvfrom(1024)
            self.__address = addr
            timeReceived = time.time()
            icmpType, icmpCode = recvPacket[20:22]

            # Assign values to object
            self.__icmpType = icmpType
            self.__icmpCode = icmpCode

            self.__Rtt = round((timeReceived - start_time) * 1000)

            # Check different ICMP types
            if icmpType == 0:  # Echo Reply
                return self.__handleEchoReply(recvPacket, addr, timeReceived, start_time, not self.__traceRouteFlag)
            else:
                return self.__handleIcmpError(icmpType, icmpCode, addr, start_time, timeReceived, not self.__traceRouteFlag)

        def __handleEchoReply(self, recvPacket, addr, timeReceived, start_time, printBoolean):
            icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
            self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
            if printBoolean:
                icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
            rtt = self.__calculateRtt(recvPacket, timeReceived)

            if icmpReplyPacket.isValidResponse():
                return rtt, 1, 0
            else:  # packet not valid
                return None, 0, 1

        def __handleIcmpError(self, icmpType, icmpCode, addr, start_time, timeReceived, printBoolean):
            if printBoolean:
                errorMessage = self.__getIcmpErrorMessage(icmpType, icmpCode)
                print(f"  TTL={self.getTtl()}    RTT={(timeReceived - start_time) * 1000:.0f} ms    {errorMessage}    {addr[0]}")
            return None, 0, 1

        def __calculateRtt(self, recvPacket, timeReceived):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
            rtt = (timeReceived - timeSent) * 1000
            return round(rtt)

        def __getIcmpErrorMessage(self, icmpType, icmpCode):

            errorMessages = {
                1: 'Unassigned',
                2: 'Unassigned',
                3: 'Destination Unreachable',
                4: 'Source Quench (Deprecated)',
                5: 'Redirect',
                6: 'Alternate Host Address (Deprecated)',
                7: 'Unassigned',
                8: 'Echo',
                9: 'Router Advertisement',
                10: 'Router Solicitation',
                11: 'Time Exceeded',
                12: 'Parameter Problem',
                13: 'Timestamp',
                14: 'Timestamp Reply',
                15: 'Information Request (Deprecated)',
                16: 'Information Reply (Deprecated)',
                17: 'Address Mask Request (Deprecated)',
                18: 'Address Mask Reply (Deprecated)',
                19: 'Reserved (for Security)',
                range(20, 30): 'Reserved (for Robustness Experiment)',
                30: 'Traceroute (Deprecated)',
                31: 'Datagram Conversion Error (Deprecated)',
                32: 'Mobile Host Redirect (Deprecated)',
                33: 'IPv6 Where-Are-You (Deprecated)',
                34: 'IPv6 I-Am-Here (Deprecated)',
                35: 'Mobile Registration Request (Deprecated)',
                36: 'Mobile Registration Reply (Deprecated)',
                37: 'Domain Name Request (Deprecated)',
                38: 'Domain Name Reply (Deprecated)',
                39: 'SKIP (Deprecated)',
                40: 'Photuris',
                41: 'ICMP messages utilized by experimental\n        mobility protocols such as Seamoby',
                42: 'Extended Echo Request',
                43: 'Extended Echo Reply',
                range(44, 253): 'Unassigned',
                253: 'RFC3692-style Experiment 1',
                254: 'RFC3692-style Experiment 2',
                255: 'Reserved'
            }

            type3Codes = {
                0: 'Net Unreachable',
                1: 'Host Unreachable',
                2: 'Protocol Unreachable',
                3: 'Port Unreachable',
                4: "Fragmentation Needed and Don't Fragment was Set",
                5: 'Source Route Failed',
                6: 'Destination Network Unknown',
                7: 'Destination Host Unknown',
                8: 'Source Host Isolated',
                9: 'Communication with Destination Network is Administratively Prohibited',
                10: 'Communication with Destination Host is Administratively Prohibited',
                11: 'Destination Network Unreachable for Type of Service',
                12: 'Destination Host Unreachable for Type of Service',
                13: 'Communication Administratively Prohibited',
                14: 'Host Precedence Violation',
                15: 'Precedence cutoff in effect'
            }

            type11Codes = {
                0: 'Time to Live exceeded in Transit',
                1: 'Fragment Reassembly Time Exceeded',
            }

            if icmpType == 3:
                return f"Error Type = {icmpType} Error Name = {errorMessages[icmpType]} Code = {icmpCode} Code Description = {type3Codes[icmpCode]}"

            if icmpType == 11:
                return f"Error Type = {icmpType} Error Name = {errorMessages[icmpType]} Code = {icmpCode} Code Description= {type11Codes[icmpCode]}"

            return f"Error Type = {icmpType} Error Name = {errorMessages[icmpType]} Code = {icmpCode}"

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # Create variables within the IcmpPacket_EchoReply class that identify whether each value that can be obtained
        # from the class is valid.
        __IcmpSequenceNumber_isValid = False
        __IcmpIdentifier_isValid = False
        __IcmpData_isValid = False

        # Following values will be received from IcmpPacket object
        __sequenceNumberOriginal = None
        __packetIdentifierOriginal = None
        __rawDataOriginal = None

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # For example, the IcmpPacket_EchoReply class has an IcmpIdentifier. Create a variable, such as
        # IcmpIdentifier_isValid, along with a getter function, such as getIcmpIdentifier_isValid() so you can easily
        # track and identify which data points within the echo reply are valid.

        def getIcmpSequenceNumber_isValid(self):
            return self.__IcmpSequenceNumber_isValid

        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid

        # Get methods for additional data

        def getSequenceNumberOriginal(self):
            return self.__sequenceNumberOriginal

        def getPacketIdentifierOriginal(self):
            return self.__packetIdentifierOriginal

        def getRawDataOriginal(self):
            return self.__rawDataOriginal

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # For example, the IcmpPacket_EchoReply class has an IcmpIdentifier. Create a variable, such as
        # IcmpIdentifier_isValid, along with a setter function, such as setIcmpIdentifier_isValid(), so you can easily
        # track and identify which data points within the echo reply are valid.

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__IcmpSequenceNumber_isValid = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue

        def setIcmpData_isValid(self, booleanValue):
            self.__IcmpData_isValid = booleanValue

        # Set methods for additional data

        def setSequenceNumberOriginal(self, sequenceNumber):
            self.__sequenceNumberOriginal = sequenceNumber

        def setPacketIdentifierOriginal(self, identifier):
            self.__packetIdentifierOriginal = identifier

        def setRawDataOriginal(self, rawData):
            self.__rawDataOriginal = rawData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]

            # RTT = (timeReceived - timeSent) * 1000
            # RTT = (timeReceived - struct.unpack("d", self.__recvPacket[28:28 + struct.calcsize("d")])[0]) * 1000

            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )


            # Identify if the echo response is valid and report the error information details. For example, if the raw
            # data is different, print to the console what the expected value and the actual value.

            if self.__isValidResponse is False:
                print("\n--------------- Start of debugging messages ---------------")
                print("Echo response is INVALID. Only the mismatched values are shown below. ")
                if self.__IcmpSequenceNumber_isValid is False:
                    print(f"Sequence number (expected: {self.__sequenceNumberOriginal} actual: {self.getIcmpSequenceNumber()})")
                if self.__IcmpIdentifier_isValid is False:
                    print(f"Packet indentifier (expected: {self.__packetIdentifierOriginal} actual: {self.getIcmpIdentifier()})")
                if self.__IcmpData_isValid is False:
                    print(f"Raw data (expected: {self.__rawDataOriginal} actual: {self.getIcmpData()})")
                print("---------------- End of debugging messages ----------------")


            if self.__isValidResponse is True:
                print("\n--------------- Start of debugging messages ---------------")
                print("Echo response is VALID.")
                print(f"Sequence number (expected: {self.__sequenceNumberOriginal} actual: {self.getIcmpSequenceNumber()})")
                print(f"Packet indentifier (expected: {self.__packetIdentifierOriginal} actual: {self.getIcmpIdentifier()})")
                print(f"Raw data (expected: {self.__rawDataOriginal} actual: {self.getIcmpData()})")
                print("---------------- End of debugging messages ----------------")


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        rttContainerList = []
        numberOfSentPackets = 0
        numberOfReceivedPackets = 0
        numberOfLostPackets = 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            # icmpPacket return received rtt here
            # sendEchoRequest() only returns rtt value if reply packet is valid () and icmpType is 0.
            numberOfSentPackets += 1
            rtt, packetsReceived, packetsLost = icmpPacket.sendEchoRequest(True)  # Build IP, return rtt
            rttContainerList.append(rtt)
            numberOfReceivedPackets += packetsReceived
            numberOfLostPackets += packetsLost

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # None would be present in rttContainerList only if ICMP response code is 0 but packet is not valid
        # Packet would not be valid if one of these items does not match for sent and received packet: sequence number,
        # packet identifier and raw data.

        if rttContainerList and None not in rttContainerList:  # No invalid packets
            self.printRttToConsole(rttContainerList, numberOfSentPackets, numberOfReceivedPackets, numberOfLostPackets, host)
        else:  # Invalid packets

            # Number of invalid packets received, present as None in rttContainerList
            numberOfNone = 0

            # Count and remove them from the rttContainerList
            while None in rttContainerList:
                numberOfNone += 1
                rttContainerList.remove(None)

            if not rttContainerList:
                self.notPrintRttToConsole(numberOfSentPackets, numberOfReceivedPackets, numberOfLostPackets,
                                   host)
                return

            # Add invalid packets to the numberOfLostPackets
            numberOfLostPackets += numberOfNone

            self.printRttToConsole(rttContainerList, numberOfSentPackets, numberOfReceivedPackets, numberOfLostPackets,
                                   host)

    def printRttToConsole(self, rttList, sent, received, lost, host):
        print(f"\n-----------------------------------------------------------")
        print(f"Ping statistics for {host}:")
        print(f"    Packets: Sent = {sent}, Received = {received}, Lost = {lost}, Packet Loss Rate = {round(lost/sent) * 100}% ")
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min(rttList)}, Maximum = {max(rttList)}, Average = {round(sum(rttList)/len(rttList))}")
        print(f"-----------------------------------------------------------")

    def notPrintRttToConsole(self, sent, received, lost, host):
        print(f"\n-----------------------------------------------------------")
        print(f"Ping statistics for {host}:")
        print(f"    Packets: Sent = {sent}, Received = {received}, Lost = {lost}, Packet Loss Rate = {round(lost/sent) * 100}% ")
        print("There was no calculation of the approximate round trip time")
        print(f"-----------------------------------------------------------")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

        print(f"Tracing route to [{host}] over a maximum of 30 hops:\n")

        for ttl in range(1, 31):

            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            # Set TTL
            icmpPacket.setTtl(ttl)

            # Set traceroute flag on object, True = not print, False = print
            icmpPacket.setTraceRouteFlag(True)

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = ttl
            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            # Send the packet and retrieve icmp type and code
            icmpPacket.sendEchoRequest(False)

            # Show hops
            hop = ttl

            # What happens if we receive nothing????????????
            # For hops that do not respond (like 8 and 16 in the screenshot), you can record a * without identifying
            # the specific ICMP type and code, since no response was received. You don't need to identify the type and
            # code for no responses. (source: https://edstem.org/us/courses/51611/discussion/4315409)
            if icmpPacket.checkTimeout() is True:
                # print(f"Hop = {hop}, RTT = * ms, ICMP Type = *, ICMP Code = *, IP Address = *, Request timed out")
                star = "*"
                timedOut = "Request timed out"
                print(f"Hop = {hop : >2}, RTT = {star : >4} ms, ICMP Type = {star : >2}, ICMP Code = {star : >2}, IP Address = {timedOut : >18}")
                continue

            # Show RTTs
            rtt = icmpPacket.getRtt()
            # Show icmp type and code
            icmpType = icmpPacket.getIcmpType()
            icmpCode = icmpPacket.getIcmpCode()
            # Show IP adress
            ipAdress = icmpPacket.getIPAdress()

            # Print information to screen
            print(f"Hop = {hop : >2}, RTT = {rtt : >4} ms, ICMP Type = {icmpType : >2}, ICMP Code = {icmpCode : >2}, IP Address = {ipAdress : >18}")

            # Stop the loop if icmpType is 0 (echo response from target)
            if icmpType == 0:
                print("\nTrace complete.\n")
                break

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #

def main():

    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")


if __name__ == "__main__":
    main()
