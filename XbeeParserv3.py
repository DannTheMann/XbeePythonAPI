#!/usr/bin/python

import random, serial, time, threading, requests, os

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
		return hex(self.success) == 0x00

class MessagePacket:

	def __init__(self, nodesource, packet):
		self.end = False
		self.source = nodesource
		self.rawPacket = packet
		self._unloadPacket()

	def _unloadPacket(self):
		# 4-11 Offset for source
		# 15 - len-1 payload
		self.payload = bytearray()
		if self.rawPacket[len(self.rawPacket)-2] == bself.FRAME_TERMINATION_CHAR:
			print "Found end termination"
			self.end = True
			self.payload.extend(self.rawPacket[15:len(self.rawPacket)-2])
		else:
			self.payload.extend(self.rawPacket[15:len(self.rawPacket)-1])

	def appendPayload(self, packet):
		print packet[len(packet)-1]
		print packet[len(packet)-2]
		if packet[len(packet)-2] == bself.FRAME_TERMINATION_CHAR:
			print "Found end termination"
			self.end = True
			self.payload.extend(packet[15:len(packet)-2])
		else:
			self.payload.extend(packet[15:len(packet)-1])

	def getSource(self):
		return self.source

	def getPayload(self):
		return self.payload

	def getPayloadAsString(self):
		return self.payload.decode("utf-8")

	def endOfFragmentation(self):
		return self.end

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
	receivedStatus = None!

	destinationNodes = {} # Empty dictionary, mapping data storage  (Name:HexAddress)

	def __init__(self, serialPort, destinationAddress):
		self.serialPort = serialPort
		self.serial = serial.Serial(self.serialPort)
		self.destinationAddress = destinationAddress	
		self.destinationNodes.add('broadcast':'00 00 00 00 00 00 FF FF')
		self.RxBuffer = bytearray()
		self.readThread = threading.Thread(target=self.readSerial).start()
		self._getKnownNodes()

	def sendMessage(self, node, message):
		return self._transmitMessage(node, message)

	# Returns the XBee 64 bit or 16 bit address
	def getAddress(self, node):
		return self.destinationAddress[node]

	# Takes message and node, gets the 64bit address of the node
	# and splits the message into frames to send to the 64bit address
	# will return values based on results of function
	# 1 = successfully transmitted all frames
	# 2 = Failed to transmit all frames, payload too long
	# 3 = Failed to transmit data to device, could not reach node
	def _transmitMessage(self, destination, message):

		if destination == None:
			print "Cannot proceed, destination does not exist"
			return

		print "Length of message:",len(message)

		framesNeeded = int(round((len(message) / self.MAX_TRANSMIT_RF_DATA)+0.5)) # Way to handle rounding up integer division (i.e 74/72=2 instead of 1)
		print "Frames needed for message:",framesNeeded
		self.txMessage = message
		for i in range(0, framesNeeded):

			print "Frame",(i+1),"being formed..."

			packet = bytearray()
			packet.append(self.START_BYTE) # Starting delimiter
			packet.append(0x00) #MSB Length

			msg = self._getMessageChunk(i, self.txMessage)
			frame = self._produceFrame(destination, i, FrameContent.TRANSMIT, msg)
			packet.append(len(frame))

			for byte in frame:
				packet.append(byte)
			packet.append(self._checkSum(frame))

			print "Sent frame!"
			if not self._sendPacket(packet):
				return 3

		return 1
			#if not _validateTransmitStatusPacket(i+1): #If we could not verify that packet was received, resend. 
			#	i-=1 

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
		self.frame = bytearray()
		self.frame.append(frameContent) # Add frame content ID
		self.frame.append(0x01)

		#64 bit address
		#self.frame.append(frameID) # The Id of the frame
		receiver = bytearray.fromhex(self.getAddress(node))
		for byte in receiver:
			self.frame.append(byte)

		#16bit address
		self.frame.append(0xFF)
		self.frame.append(0xFE)
			
		#Broadcast
		self.frame.append(self.BROADCAST_RANGE)
		#Options
		self.frame.append(self.TRANSMIT_OPTIONS)

		for char in payload:
			self.frame.append(char)

		return self.frame

		#escapedFrame = bytearray()
		#for char in self.frame[14:]:
		#	if char in self.RESERVED:
		#		escapedFrame.append(0x7D)
		#		escapedFrame.append(char ^ 0x20) # XOR to avoid misinterpreted escape command
		#	else:
		#		escapedFrame.append(char)


		#return escapedFrame

	def _sendPacket(self, packet):
		self.serial.write(packet) # Packet is sent to XBee and handled there on
		time.sleep(2.5)
		return self._txStatus(packet)

	def _txStatus(self, packet):		
		if self.receivedStatus == None:
			print "Received Status is not defined!"
			return False
		return self.receivedStatus.wasSuccessful

	def _validateReceivedPacket(self, potentialPacket):
		bytesIn = bytearray()
		bytesIn.extend(potentialPacket)

		length = bytesIn[2]
		frameType = hex(bytesIn[3])
		checksum = hex(bytesIn[len(potentialPacket)-1])

		if frameType == hex(FrameContent.RECEIVE):

			#nodeSource = bytesIn[4:11].decode("utf-8")
			nodeSource = (bytesIn[4:10])
			# Need to append data here at some point
			for message in self.receivedMessages:
				if not message.endOfFragmentation():
					if message.getSource() == nodeSource:
						message.appendPayload(potentialPacket)
						print message.getPayloadAsString()
						return

			self.receivedMessages.append(MessagePacket(nodeSource, potentialPacket))
		elif frameType == hex(FrameContent.STATUS):

			nodeSource = (bytesIn[5:7])

			self.receivedStatus = StatusPacket(nodeSource, potentialPacket)
		else:
			print "None or the above!"

	def readSerial(self):
		while True:

			print "Size:",len(self.receivedMessages)
			print "Waiting to receive..."
			tdata = bytearray()

			tdata.append(self.serial.read())           # Wait forever for anything	
			time.sleep(1) # Wait a second	
			remaining = self.serial.inWaiting()
			tdata.extend( self.serial.read(remaining))
			
			print "Printing received data..."

			print "Received data."

			packets = tdata[1:].split(bytes(b'\x7E'))	# Splits the potential multiple packets recieved

			print "Packets found:",len(packets)

			self.serial.flushInput()
			self.serial.flushOutput()

			for potentialPacket in packets:
				for byte in potentialPacket:
					print byte,
				self._validateReceivedPacket(potentialPacket)

	def _receiveFrame(self, frameID):
		print "Size:",len(self.receivedMessages)
		remaining = self.serial.inWaiting()
		while remaining:
			chunk = self.serial.read(remaining)
			remaining -= len(chunk)
			self.RxBuffer.extend(chunk)		

		packets = self.RxBuffer.split(bytes(bSTART_BYTE))	# Splits the potential multiple packets recieved

		for potentialPacket in packets:
			self._validateReceivedPacket(potentialPacket) # Verify every potential packet

		if self._validateReceivedPacket(packets[-1]):
			self.RxBuffer = bytearray()
		else:
			self.RxBuffer = packets[-1]

		return self.RxPacket.popleft() if self.RxPacket else None
				

	def _checkSum(self, packet):
		print (0xFF - (sum(packet) &0xFF))
		#print "",(sum(packet[3:])
		return (0xFF - (sum(packet) &0xFF))

	def _validateTransmitStatusPacket(self, bytesIn):

		try:

			if len(bytesIn) < 11:
				return False #Not a full packet

			if not hex(ord(bytesIn[0])) == START_BYTE:
				return False #Not the start of a packet

			if not hex(ord(bytesIn[3]) == FrameContent.STATUS.value):
				return False #Not the correct frame content type

			if not hex(ord(bytesIn[4]) == hex(frameID)):
				return False #Not the frame we're expecting

			deliveryStatus = hex(bytesIn[8]) # Get the delivery hex value
			checkSum = hex(bytesIn[10])
			calculateCheckSum = hex(0xFF-(len(packet[2:]) & 0xFF))

			if not checkSum == calculateCheckSum:
				return False # Checksum did not match the actual checksum

			if deliveryStatus == 0x00:
				return True # Successfully received
			else:
				# An error occurred and the packet was not received correctly
				return False

		except:
			return False

	def testHex(self):
		print "Sending... 7E 00 11 10 01 00 13 A2 00 40 C1 FD 49 FF FE 00 00 48 65 79 CF"
		self.serial.write(bytearray.fromhex('7E 00 11 10 01 00 13 A2 00 40 C1 FD 49 FF FE 00 00 48 65 79 CF'))

   	def _is_non_zero_file(self, fpath):  # Is the file empty
      		return True if self.isFile(fpath) and os.path.getsize(fpath) > 0 else False
   
   	def _isFile(self, fpath): # Does the file exist
      		return True if os.path.isfile(fpath) else False

	def _getKnownNodes(self):
		if _self.isFile(DESTINATION_NODES_FILE):
			f = open(self.DESTINATION_NODES_FILE, 'r')
			rawNodes = f.read()
			for nodes in rawNodes.split(",")
				self.destinationNodes[nodes.split(":")[0]] = nodes.split(":")[1]
			f.close()	

		sendMessage("broadcast", "HB#") # (HB=HeartBeat)Send broadcast and wait for any devices to talk back...
		time.sleep(3)

		for rxPacket in self.receivedMessages: # Loop through all received packets within the last 3 seconds
			if rxPacket.getPayloadAsString.startswith("HB#"): # If the packet was a heartbeat response
				name = rxPacket.getPayloadAsString.split("#")[1] # The name of the node responding
				if not name in self.destinationNodes: # We have found a node that is not registered on our network
					self.destinationNodes[name] = rxPacket.getSource # Update our dictionary map
					f = open(self.DESTINATION_NODES_FILE, 'a') # Save to our destination node file
					f.write(name + ":" + rxPacket.getSource)
				_ackAndRemoveMessage(rxPacket) #Acknowledge read and remove from list

	def _ackAndRemoveMessage(self, packet):
		self.receivedMessages.remove(packet)	


		
		


print "Starting..."

xbee = XbeeAPI("/dev/ttyAMA0", sensors)
#xbee.testHex()
#print "Response: ",(xbee.sendMessage("clock", "Hello Mate, how's the weather down in Spain these days? I've heard many a thing about those redheaded men running wild down."))
#xbee.testHex()
#xbee.sendMessage("clock", "Hello World")

