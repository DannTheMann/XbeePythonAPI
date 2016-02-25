#!/usr/bin/python

import random, serial, time, threading, requests, os

from enum import Enum
class FrameContent(Enum):
	TRANSMIT='0x01'
	RECEIVE='0x90'
	STATUS='0x8B'

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
	MAX_TRANSMIT_RF_DATA = "72" # Maximum amount of bytes that can be transferred per frame
	TRANSMIT_OPTIONS = 0x00
	TRANSMIT_STATUS_LENGTH = 11 # The length of a transmit status packet

	def __init__(self, serialPort, destinationAddress):
		self.serialPort = serialPort
		self.serial = serial.Serial(self.serialPort)
		self.destinationAddress = destinationAddress	
		#self.packet = array('c') #D Define our packet as a character array

		#for nodeNames in self.destinationAddress:
			#if self.destinationAddress[nodeNames] = "0x0000000000000000": # Coordinator address
				#self.destinationAddress[nodeNames] = "0x0000000000000000FFFE" # Append broadcast to 16 bit address
			#else if self.destinationAddress[nodeNames] = "0x000000000000FFFF": # Broadcast address
				#self.destinationAddress[nodeNames] = "0x0000000000000000FFFE" 
			#if not len(self.destinationAddress[nodeNames]) > 18: # User has NOT already filled in the 16 bit field
				#self.destinationAddress[nodeNames] = self.destinationAddress[nodeNames] % "0xFFFE" # Add broadcast and assume destination address is unknown

		# If the address supplied is greater than 16 bytes = 64bit address, 
		# else 16 bit address			
		#self.64bitAddress =  True if len(self.destinationAddress) > 4 else False: 
		self.RxBuffer = bytearray()
		self.readThread = threading.Thread(target=self.readSerial).start()

	def sendMessage(self, node, message):
		#We use the standard options, 0x00 
		#Because we want an ACK from the receiver
		payload = self.BROADCAST_RANGE # Place the Broadcast Radius on the frame payload
		payload.append(self.TRANSMIT_OPTIONS) # Place the transmission options on the frame payload
		payload.append(message) # Add the content of the message
		self._transmitMessage(node, payload)

	# Returns the XBee 64 bit or 16 bit address
	def getAddress(self, node):
		return destinationAddress[node]

	def _produceFrame(node, frameID, frameContent, payload):

		if not frameID:
			return None

			self.frame[0] = frameContent.value # Add frame content ID
			self.frame[1] = frameID
			frame.append(self.getAddress(node))
			frame.append(payload)

			escapedFrame = ""
			for char in frame[0:]:
				if char in RESERVED:
					escapedFrame.append('0x7D')
					escapedFrame.append(char ^ '0x20') # XOR to avoid misinterpreted escape command
				else:
					escapedFrame.append(char)

			return escapedFrame

		#if frameContent == FrameContent.TRANSMIT: # Send Frame Request

	def _receiveMessage(self):

		# 
		# Read in serial
		# 
		# Read serial 
		print "Hello"
	

	def _validateReceivedPacket(self, potentialPacket):
		bytesIn = bytearray()
		bytesIn.extend(potentialPacket)

		if not len(bytesIn) > 7: # Not long enough to be receive packet
			return False
		#if not hex(ord(potentialPacket[0])) == START_BYTE:
		#	return False
		if not hex(ord(potentialPacket[3])) == FrameContent.RECEIVE.value: # Not the correct frame ID
			return False
		
		if not ord(bytesIn[1]) == (len(bytesIn[2:])-1):
			return False # Length does not match frame length in LSB

		checkSum = hex(ord(potentialPacket[len(bytesIn)-1]))

		if not 0xFF-(sum(packet[2:])-1 & 0xFF) == checkSum:
			return False # Non matching CheckSum

		return True
		

	def readSerial(self):
#		while True:
#			print "Waiting..."
#			self.serial.flushInput() # Get rid of any incoming/outgoing data
#			self.serial.flushOutput()
#			tdata = self.serial.read()           # Wait forever for anything
#			print "Found data!"
#			time.sleep(3)              # Sleep (or inWaiting() doesn't give the correct value)
#			print "Slept for 3 seconds..."
#			data_left = self.serial.inWaiting()  # Get the number of characters ready to be read
#			tdata += self.serial.read(data_left) # Do the read and combine it with the first character
#			print tdata
#		while True:
			self.serial.flushInput()
			self.serial.flushOutput()
			tdata = self.serial.read()           # Wait forever for anything
			print "Waiting..."
			time.sleep(3) 			
			remaining = self.serial.inWaiting()
			while remaining:
				chunk = self.serial.read(remaining)
				remaining -= len(chunk)
				self.RxBuffer.extend(chunk)		
			print "Received data."
			#packets = self.RxBuffer.split(bytes(self.START_BYTE))	# Splits the potential multiple packets recieved

			#for potentialPacket in packets:
				#self._validateReceivedPacket(potentialPacket) # Verify every potential packet

			#if self._validateReceivedPacket(packets[-1]):
			#	self.RxBuffer = bytearray()
			#else:
			#	self.RxBuffer = packets[-1]

			for byte in self.RxBuffer:
				print hex(byte)

			#return self.RxPacket.popleft() if self.RxPacket else None



	def _receiveFrame(self, frameID):
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



	def _transmitMessage(self, destination, message):

		framesNeeded = (len(message)-MAX_TRANSMIT_RF_DATA-1) / MAX_TRANSMIT_RF_DATA # Way to handle rounding up integer division (i.e 74/72=2 instead of 1)

		for i in range(0, framesNeeded):
			packet[0] = START_BYTE # Starting delimiter
			packet[1] = '0x00' #MSB Length
			# Use i+1 to avoid having a frame 0
			frame = produceFrame(destination, (i+1), FrameContent.TRANSMIT, message)
			packet += frame
			packet[len(frame)] = self._checkSum(frame)
			sendPacket(packet)
			if not _validateTransmitStatusPacket(i+1): #If we could not verify that packet was received, resend. 
				i-=1 
				

	def _sendPacket(self, packet):

		for byte in packets:
			print hex(byte)

		self.serial.write(packet) # Packet is sent to XBee and handled there on

	def _checkSum(self, packet):
		return 0xFF-(sum(packet[2:])-1 & 0xFF)

	def _transmitStatus(self, frameID):
		bytesIn = bytearray()
		while len(bytearray) < TRANSMIT_STATUS_LENGTH:
			bytesIn.append(self.serial.read())

		return self._validateTransmitStatusPacket(bytesIn, frameID)

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


	# def transmitMessage(message, frameID):
	# 	length = 16 + ( 72 if len(message) > 72 else len(message))
	# 	self.packet[0] = toHex(ESCAPE)
	# 	self.packet[1] = toHex('0x00') # lengthMSB
	# 	self.packet[2] = toHex(length) # lengthLSB
	# 	self.packet[3] = toHex('0x01') # Frame Type
	# 	self.packet[4] = toHex(frameID) # FrameID
	# 	# 

	# 	if self.64bitAddress:
	# 		i = 5
	# 		x = 0
	# 		for hexVal in self.destinationAddress:
	# 			self.packet[i] = toHex(self.destinationAddress[x] + self.destinationAddress[x+=1])
	# 			x+=1
	# 		# 64 bit address
	# 		self.packet[13] = toHex('0xFF')
	# 		self.packet[14] = toHex('0xFE')
	# 	else:
	# 		for i in range (5, 12): 
	# 			self.packet[i] = toHex('0x00')
	# 		# 16 bit address
	# 		self.packet[13] = toHex(self.destinationAddress[0] + self.destinationAddress[1])
	# 		self.packet[14] = toHex(self.destinationAddress[2] + self.destinationAddress[3])


	# 	self.packet[15] = toHex(BROADCAST_RANGE) # How many hops allowed to take to reach destination
	# 	self.packet[16] = toHex('0x00') # Options

	# 	# The payload of the frame (Maximum of 72 bytes)
	# 	i = 17
	# 	for character in message:
	# 		self.packet[i] = character
	# 		i += 1
	# 		if (i-17) == 72:
	# 			self.payloadIndex = i-17
	# 			break # Need to split payload down into separate frames

	# 	# checksum modulo 256
	# 	checksum = 0
	# 	for byteValue in range(3,len(self.packet)):
	# 		checksum+=byteValue
	# 	checksum = 0xFF-(checksum & 0xFF)

	# 	self.packet[i] = toHex(checksum)
	# 	self.serial.write(self.packet) # Send formatted frame to Xbee

	# 	if len(message[length:]) > 0:
	#     	transmitMessage(message[length:], frameID+=1)

	def transmitStatus():
		print "Hello"
	#def 


		# self.packet[3] = toHex('0x01')
		# self.packet[4] = 

	def getOffset(self, offset):
		return self.packet[offset]

	def toHex(self, toConvert):
		return b16decode(toConvert)

print "Starting..."
sensors = {'clock':'0013A20040CC05FA'}
xbee = XbeeAPI("/dev/ttyAMA0", sensors)
#xbee.sendMessage("clock", "Hello World")

