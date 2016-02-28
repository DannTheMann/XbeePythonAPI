#!/usr/bin/python
# Look at organising framing... 
 
import random, serial, time, threading, requests, os, unicodedata
 
from enum import Enum
class FrameContent(Enum):
    TRANSMIT=0x10
    RECEIVE=0x90
    STATUS=0x8B
 
class StatusPacket:
 
    def __init__(self, nodesource, packet):
        self.rawPacket = packet
        self.source = nodesource
        self._unloadPacket()
 
    def _unloadPacket(self):
        # 4-11 Offset for source
        # 15 - len-1 payload
        self.success = self.rawPacket[8]
 
	def getSource(self):
		return self.source
 
    def getSuccess(self):
        return self.success
 
    def wasSuccessful(self):
        return True if self.success == 0x00 else False
 
class MessagePacket:
 
    FRAME_TERMINATION_CHAR = '!'
 
    def __init__(self, nodesource, nodename, packet):
        self.end = False
        self.source = nodesource
        self.rawPacket = packet
        self.frameID = 0
        self.nodename = nodename
        self._unloadPacket()
 
    def _unloadPacket(self):
        # 4-11 Offset for source
        # 15 - len-1 payload
        self.payload = bytearray()
        if self.rawPacket[len(self.rawPacket)-2] == ord('!'):
            self.end = True
            self.payload.extend(self.rawPacket[15:len(self.rawPacket)-2])
        else:
            self.payload.extend(self.rawPacket[15:len(self.rawPacket)-1])
 
    def appendPayload(self, packet, nodename):

    	#print "Appending payload...\r\n"
    	for byte in packet:
    		print hex(byte),
    	print "\r\n"

        if packet[len(packet)-2] == ord('!'):
            self.end = True
            self.payload.extend(packet[15:len(packet)-2])
        else:
            self.payload.extend(packet[15:len(packet)-1])
        self._incrementedFrameID()
        #if self.end == True:
        	#print "Ended:",self.getPayloadAsString()
 
	def getSource(self):
		return self.source
 
    def getPayload(self):
        return self.payload
 
    def getPayloadAsString(self):
        return unicodedata.normalize('NFKD', self.payload.decode("utf-8")).encode('ascii', 'ignore')
 
    def getContents(self):
        return self.getPayloadAsString() if self.endOfFragmentation() == True else None
 
    def endOfFragmentation(self):
        return self.end
 
    def getFrameID(self):
        return self.frameID
 
    def _incrementedFrameID(self):
        self.frameID += 1

    def getNodeName(self):
    	return self.nodename
 
class XbeeAPI:
 
    ESCAPE = 0x7D # Escape byte
    START_BYTE = 0x7E # Start byte
 
    BROADCAST_ADDRESS = 0xFFFF #Broadcast address byte
    ZB_BROADCAST_ADDRESS = 0xFFFE # When 16bit address unknown, broadcast or locate
    BROADCAST_RANGE = 0x00 # By default the maximum is 10 hops
 
    RESERVED = bytearray(b"\x7E\x7D\x11\x13") # Reserved hex values
 
    RX_16_RSSI_OFFSET = "2"
    RX_64_RSSI_OFFSET = "8"
 
    DEFAULT_FRAME_ID = "1"
    NO_RESPONSE_FRAME_ID = "0" # Frame ID for no ACK from XBee
    FRAME_TERMINATION_CHAR = '!'
 
    # Two chars reserved in payload
    # 
    MAX_TRANSMIT_RF_DATA = 72.0 # Maximum amount of bytes that can be transferred per frame
    TRANSMIT_OPTIONS = 0x00
    TRANSMIT_STATUS_LENGTH = 11 # The length of a transmit status packet
    DESTINATION_NODES_FILE = "destination_nodes.txt"
 
 
 
    # List of received packets, 
    receivedMessages = []
     # The most recent response to whichever message we've sent.
     # Will determine whether a packet has been sent/received
    receivedStatus = None
 
    destinationNodes = {} # Empty dictionary, mapping data storage  (Name:HexAddress)
 # Serial buffer to handle data coming into the pi from serial
 
    def __init__(self, serialPort):
        self.serialPort = serialPort
        self.serial = serial.Serial(self.serialPort)    
        print "Adding BROADCAST node: 00 00 00 00 00 00 FF FF."
        self.destinationNodes['broadcast'] = '00 00 00 00 00 00 FF FF'
        self.rxBuffer = bytearray()
        self.triggered = False
        print "Starting read serial thread."
        self.readThread = threading.Thread(target=self.readSerial).start()
        print "Sending heartbeat to every listening nodes..."
        self._getKnownNodes()
 
    def sendMessage(self, node, message):
		receiver = None
		if isinstance(node, str):
			address = self.getAddress(node)
			if address == None:
				#print "Error,",node,"does not exist on address dict."
				return 
			address = address.replace('0x0', '0x00').replace('0x','')	
			receiver = bytearray.fromhex(address)
		else:
			receiver = node;
 
		return self._transmitMessage(receiver, message)
 
    # Returns the XBee 64 bit or 16 bit address
    def getAddress(self, node):
        return self.destinationNodes[node] if node in self.destinationNodes else None

    def getAddressName(self, node):
    	for key in self.destinationNodes.keys():
    		if self.destinationNodes[key] == node:
    			return key
    	return "Unknown"
 
    def _addDestination(self, node):
        for nodes in self.destinationNodes.values():
			newNode = ""
			for byte in node:
				newNode+=hex(byte)
			newNode = str(newNode.replace('0x', ''))
			nodes = str(nodes).replace('0x', '').replace(' ', '')
			if nodes == newNode:
				return

        self.sendMessage(node, "HB#:")
        time.sleep(.25)
        if self.receivedStatus == None or self._txStatus() == False: # Failed to contact the node
			return
        packet = self._searchForPacketContaining("HB#:")
        if packet == None:
			return
        self._saveToFile(packet)
 
    def _searchForPacketContaining(self, search):
        for packet in self.receivedMessages:
			if packet.getPayloadAsString().startswith(search):
				return packet
        return None
 
 
    # Takes message and node, gets the 64bit address of the node
    # and splits the message into frames to send to the 64bit address
    # will return values based on results of function
    # 0 = successfully transmitted all frames
    # 1 = payload too big, more than 255 frames required
    # 2 = Invalid node, does not exist on network
    # 3 = Failed to transmit data to device, could not reach node
    def _transmitMessage(self, destination, message):
 
        if destination == None:
            #print "Cannot proceed, destination does not exist"
            return 2
 
        #print "Length of message:",len(message)
 
        framesNeeded = int(round((len(message) / self.MAX_TRANSMIT_RF_DATA)+0.5)) # Way to handle rounding up integer division (i.e 74/72=2 instead of 1)
        if framesNeeded > 255:
        	return 1
        self.txMessage = message
        for i in range(0, framesNeeded):
 
            #print "Frame",i,"being formed..."
            packet = bytearray()
            packet.append(self.START_BYTE) # Starting delimiter
            packet.append(0x00) #MSB Length
 
 			# Chunk the msg into smaller messages 
 			# Then these are sent in frames
            msg = self._getMessageChunk(i, self.txMessage)
            frame = self._produceFrame(destination, i, FrameContent.TRANSMIT, msg)
            #packet.append(len(frame)-1) # We know the length of the frame now we've produced it
 
            for byte in frame:
                packet.append(byte)
            #packet.append(self._checkSum(frame))
 
            #print "Sent frame!"
 
            success = self._sendPacket(packet)
            timeout = 0
            while not success and timeout < 10:
                #print "Failed to send frame",i,". Retrying..."
                success = self._sendPacket(packet)
                time.sleep(1)
                timeout+=1
            if timeout >= 10:
            	#print "Failed to reach node!"
            	return 3
 
 
        return 0
            #if not _validateTransmitStatusPacket(i+1): #If we could not verify that packet was received, resend. 
            #   i-=1 
 
    def _getMessageChunk(self, index, message):
 
        if len(message) > self.MAX_TRANSMIT_RF_DATA: # Do we have more frames to send yet?
            self.txMessage = message[int(self.MAX_TRANSMIT_RF_DATA):]
            return message[:(int(self.MAX_TRANSMIT_RF_DATA))]
        else: # Else this is the last frame
            message += self.FRAME_TERMINATION_CHAR # End of message, use as an end termination character
            self.txMessage = message
            return message
 
    def _produceFrame(self, node, frameID, frameContent, payload):
 
        # Frame type and frame ID
        frame = bytearray()
        frame.append(15 + len(payload)) # The length of the frame from offset 3 to checksum
        frame.append(frameContent) # Add frame content ID
        frame.append(0x01)
 
        #64 bit address
        for byte in node:
            frame.append(byte)
 
        #16bit address
        frame.append(0xFF)
        frame.append(0xFE)
             
        #Broadcast range
        frame.append(self.BROADCAST_RANGE)
        #Options for transmit
        frame.append(self.TRANSMIT_OPTIONS)

        frame.append(ord(str(frameID))) # The Id of the frame
        frame.extend(payload)
 
        #self.frame.append(frameID) # Structured sequence for framing...
        #return self.frame
        frame.append(self._checkSum(frame[1:])) # Calculate check sum of the frame

        escapedFrame = bytearray()
        for char in frame:
           if char in self.RESERVED:
               escapedFrame.append(0x7D)
               escapedFrame.append(char ^ 0x20) # XOR to avoid misinterpreted escape command
           else:
               escapedFrame.append(char)
 
 
        return escapedFrame
 
    def _sendPacket(self, packet):
        self.serial.write(packet) # Packet is sent to XBee and handled there on
        time.sleep(2.5) # Wait 2.5 seconds to allow for transmission status response... 
        return self._txStatus()
 
    def _txStatus(self):        
        if self.receivedStatus == None:
            #print "No response!"
            return False
        return self.receivedStatus.wasSuccessful()
 
        #return False if self.receivedStatus == None or not self.receivedStatus.getSuccess == b'\x00' else True
 
    def _validateReceivedPacket(self, potentialPacket):
        bytesIn = bytearray()
        bytesIn.extend(potentialPacket)
 
        # Checks whether the frame is of the minimum size needed
        # 9 bytes is the minimum length of a rx frame without a payload
        # This removes the need to check against escaped characters also
        if (len(bytesIn) - bytesIn.count(bytes(b'0x07D')) < 9):
            return False

        bytesIn = self.unescape(bytesIn) 

        if bytesIn == None:
        	return False

        length = bytesIn[1]
 
        # Does the packet match the length it claims?
        # Especially useful to detect when we've only got 'half' a packet
        if length > (len(bytesIn[2:])-1): 
            return False
 
        checksum = hex(bytesIn[len(bytesIn)-1])
        frameType = hex(bytesIn[2])

        if (sum(bytesIn[2:3+length]) & 0xFF) != 0xFF:
        	return False
 		
        if frameType == hex(FrameContent.RECEIVE):
            #nodeSource = bytesIn[4:11].decode("utf-8")
            nodeSource = (bytesIn[3:11])
            try:
                frameID = int(chr(bytesIn[14]))
            except:
                frameID = 1 # Packet does not need a frame ID
             
            # Loop through every message received
            # If we're expecting more frames for a particular packet
            # We must form the entire packet correctly
            self._addDestination(nodeSource)
            for message in self.receivedMessages:
                if not message.endOfFragmentation(): 
                    if message.getSource() == nodeSource: 
                        if message.getFrameID() == (frameID-1):
                            message.appendPayload(bytesIn, self.getAddressName(nodeSource))
                            return True
 
            # Add new packet to list of received packets
            self.receivedMessages.append(MessagePacket(nodeSource, self.getAddressName(nodeSource), bytesIn))
            return True
        elif frameType == hex(FrameContent.STATUS):
            nodeSource = (bytesIn[5:7])
            self.receivedStatus = StatusPacket(nodeSource, bytesIn)
            return True
        else:
            #print "Unidentified packet!"
            return False

    def unescape(self, packet):
    	# The last byte is an escape character which cannot be escaped
    	if packet[-1] == 0x7D:
    		return None

    	unescaped = bytearray()
    	skipNextByte = False
    	for i in range(len(packet)):
    		if skipNextByte:
    			skipNextByte = False
    			continue
    		if packet[i] == 0x7D: # The escape character
    			unescaped.append(packet[i+1] ^ 0x20) # Unescape this byte
    			skipNextByte = True # We know that the next character has been escaped so we need to skip it
    		else:
    			unescaped.append(packet[i]) #otherwise we add to our array and carry on
    	return unescaped

 
    def readSerial(self):
        try:
            while True:
                #print "Messages logged:",len(self.receivedMessages)
                #print "Waiting to receive..."
                tdata = self.rxBuffer # Grabs any previous packet data we may have missed
 
                tdata.append(self.serial.read()) # Block until we receive data
                time.sleep(1) # Let data pool in serial input buffer
                remaining = self.serial.inWaiting()
                tdata.extend(self.serial.read(remaining))
 
                self.serial.flushInput() # Clear the serial input buffer
                self.serial.flushOutput()
                # If we've collected more than on packet
                # Splits the potential multiple packets recieved
                packets = tdata[1:].split(bytes(b'\x7E'))   
 
                #print "Packets found:",len(packets)

                self.rxBuffer = bytearray() # Clear the rxBuffer and prepare for any malformed packets
 
                for potentialPacket in packets:
                    if not self._validateReceivedPacket(potentialPacket): # Attempt to validate the packet, if false then add the data to the rxBuffer
                        #print "Invalid packet..."
                        self.rxBuffer.extend(potentialPacket)
                        if self.triggered == True: # The packet is corrupted
                        	self.triggered = False
                        	self.rxBuffer = bytearray()
                        self.triggered = True
                        break
 
                #print "\r\n"
        except KeyboardInterrupt:
            print "Exiting read thread..."
                 
 
    def _checkSum(self, packet):
        return (0xFF - (sum(packet) & 0xFF))
 
    # def _validateTransmitStatusPacket(self, bytesIn):
 
    #     try:
 
    #         if len(bytesIn) < 11:
    #             return False #Not a full packet
 
    #         if not hex(ord(bytesIn[0])) == START_BYTE:
    #             return False #Not the start of a packet
 
    #         if not hex(ord(bytesIn[3]) == FrameContent.STATUS.value):
    #             return False #Not the correct frame content type
 
    #         if not hex(ord(bytesIn[4]) == hex(frameID)):
    #             return False #Not the frame we're expecting
 
    #         deliveryStatus = hex(bytesIn[8]) # Get the delivery hex value
    #         checkSum = hex(bytesIn[10])
    #         calculateCheckSum = hex(0xFF-(len(packet[2:]) & 0xFF))
 
    #         if not checkSum == calculateCheckSum:
    #             return False # Checksum did not match the actual checksum
 
    #         if deliveryStatus == 0x00:
    #             return True # Successfully received
    #         else:
    #             # An error occurred and the packet was not received correctly
    #             return False
 
    #     except:
    #         return False
 
    def testHex(self):
        #print "Sending... 7E 00 11 10 01 00 13 A2 00 40 C1 FD 49 FF FE 00 00 48 65 79 CF"
        #print "Sending... 7E 00 12 10 01 00 00 00 00 00 00 FF FF FF FE 00 00 30 65 79 21 C4"
        self.serial.write(bytearray.fromhex('7E 00 11 10 01 00 13 A2 00 40 C1 FD 49 FF FE 00 00 48 65 79 CF'))
        self.serial.write(bytearray.fromhex('7E 00 12 10 01 00 00 00 00 00 00 FF FF FF FE 00 00 30 65 79 21 C4'))
 
    def _is_non_zero_file(self, fpath):  # Is the file empty
            return True if self.isFile(fpath) and os.path.getsize(fpath) > 0 else False
    
    def _isFile(self, fpath): # Does the file exist
            return True if os.path.isfile(fpath) else False
 
    def _getKnownNodes(self):
        if self._isFile(self.DESTINATION_NODES_FILE):
            f = open(self.DESTINATION_NODES_FILE, 'r')
            rawNodes = f.read()
            for nodes in rawNodes.split(","):
            	if len(nodes)>0:
                	self.destinationNodes[nodes.split(":")[0]] = nodes.split(":")[1]#
                	print "Added",nodes.split(":")[0], ":",nodes.split(":")[1]
            f.close()   
 

        result = self.sendMessage("broadcast", "HB#") # (HB=HeartBeat)Send broadcast and wait for any devices to talk back...
        while not result == 0:
			print "Broadcast failed! Retrying in 10 seconds..."
			time.sleep(10) # wait ten seconds
			self.sendMessage("broadcast", "HB#") 
        time.sleep(3)
        print "Sent broadcast... saving any newly found node."
        f = open(self.DESTINATION_NODES_FILE, 'a')
        for rxPacket in self.receivedMessages: # Loop through all received packets within the last 3 seconds
            if not rxPacket.getPayloadAsString and rxPacket.getPayloadAsString.startswith("HB#"): # If the packet was a heartbeat response
                name = rxPacket.getPayloadAsString.split("#")[1] # The name of the node responding
                if not name in self.destinationNodes: # We have found a node that is not registered on our network
                		self._saveToFile(rxPacket)
                print "Response from:", name
 		f.close()
 		print "Finished finding nodes."
 
 
    def _ackAndRemoveMessage(self, packet):
        self.receivedMessages.remove(packet)    
 
    def _saveToFile(self, packet):
		f = open(self.DESTINATION_NODES_FILE, 'a')
		name = packet.getPayloadAsString().split(":")[1]
		newNode = ""
		for byte in packet.getSource():
			newNode += hex(byte)
		newNode = newNode.replace('0x', ' 0x')
		newNode = newNode[1:]
		self.destinationNodes[name] = newNode
		f.write(name + ":" + newNode + ",")
		f.close()
		print "Added",name,":",newNode
		self._ackAndRemoveMessage(packet)
 

 
print "Starting Xbee API..."
try:
    xbee = XbeeAPI("/dev/ttyAMA0")
    #xbee.sendMessage("clock", "Hello there end router!")
except KeyboardInterrupt:
    print "Exiting"
#xbee.testHex()
#print "Response: ",(xbee.sendMessage("clock", "Hello Mate, how's the weather down in Spain these days? I've heard many a thing about those redheaded men running wild down."))
#xbee.testHex()
#xbee.sendMessage("clock", "Hello World")