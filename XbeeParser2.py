 
#!/usr/bin/python

import random, serial, time, threading, requests, os

class XBeeAPI:

	def __init__(self, serialPort):
		self.serial = serial.Serial(serialPort)
		self.RxBuff = bytearray()

	def testHex(self):
		print "Sending... 7E 00 17 10 01 00 13 A2 00 40 C1 FD 49 FF FE 00 00 48 65 79 20 57 6F 72 6C 64 A7"

		# 7E = Start byte
		# 00 17 Length
		# 10 Frame Type
		# FrameId 01
		# 64bit address 00 13 A2 00 40 C1 FD 49
		# 16bit address FF FE
		# Broadcast Radius 00
		# Options 00
		# RF DATA (Hey World) 48 65 79 20 57 6F 72 6C 64

		self.serial.write(bytearray.fromhex('7E 00 17 10 01 00 13 A2 00 40 C1 FD 49 FF FE 00 00 48 65 79 20 57 6F 72 6C 64 A7'))
		print "Trying to recieve..."
		self.receiveSerial()

	def sendStr(self, msg, addr=0xFFFF, options=0x00, frameid=0x01):
		return self.send(msg.encode('utf-8'), addr, options, frameid)

	def send(self, msg, addr=0xFFFF, options=0x01, frameid=0x00):
		if not msg:
			return 0
 
 		#7e 00 10 01 00 ff ff 01 48 65 6c 6c 6f 20 57 6f 72 6c 64 e3
		hexs = '7E 00 {:02X} 01 {:02X} {:02X} {:02X} {:02X}'.format(
			len(msg) + 5,           # LSB (length)
			frameid,
			(addr & 0xFF00) >> 8,   # Destination address high byte
			addr & 0xFF,            # Destination address low byte
			options
		)
 
		frame = bytearray.fromhex(hexs)
		#  Append message content
		frame.extend(msg)
 
       	# Calculate checksum byte
		frame.append(0xFF - (sum(frame[3:]) & 0xFF))
 
       	# Escape any bytes containing reserved characters
		frame = self.escape(frame)
 	
		print("Tx: " + self.format(frame))
		return self.serial.write(frame)

	def escape(self, msg):
		escaped = bytearray()
		reserved = bytearray(b"\x7E\x7D\x11\x13")
  
		escaped.append(msg[0])
		for m in msg[1:]:
			if m in reserved:
				escaped.append(0x7D)
				escaped.append(m ^ 0x20)
			else:
				escaped.append(m)

		return escaped

	def format(self, msg):
		return " ".join("{:02x}".format(b) for b in msg)

	def receiveSerial(self):
			self.serial.flushInput()
			self.serial.flushOutput()
			#tdata = self.serial.read()           # Wait forever for anything
			print "Waiting..."
			time.sleep(3) 	
			print "Finished sleeping..."		
			remaining = self.serial.inWaiting()
			print "Remain: ", remaining
			while remaining:
				chunk = self.serial.read(remaining)
				remaining -= len(chunk)
				self.RxBuff.extend(chunk)	
			for byte in self.RxBuff:
				print hex(byte)	
			print "Received data."		

	def receive(self):
		remaining = self.serial.inWaiting()
		while remaining:
			chunk = self.serial.read(remaining)
			remaining -= len(chunk)
			self.RxBuff.extend(chunk)
  
		msgs = self.RxBuff.split(bytes(b'\x7E'))
		for msg in msgs[:-1]:
			self.validate(msg)
 
		self.RxBuff = (bytearray() if self.validate(msgs[-1]) else msgs[-1])
 		self.RxMessages = self.RxBuff

		if self.RxMessages:
 			return self.RxMessages.popleft()
		else:
			return None

	def validate(self, msg):
         # 9 bytes is Minimum length to be a valid Rx frame
         #  LSB, MSB, Type, Source Address(2), RSSI,
         #  Options, 1 byte data, checksum
		if (len(msg) - msg.count(bytes(b'0x7D'))) < 9:
			return False
  
        # All bytes in message must be unescaped before validating content
		frame = self.unescape(msg)
 
		LSB = frame[1]
        # Frame (minus checksum) must contain at least length equal to LSB
		if LSB > (len(frame[2:]) - 1):
			return False
 
        # Validate checksum
		if (sum(frame[2:3+LSB]) & 0xFF) != 0xFF:
			return False
 
		print("Rx: " + self.format(bytearray(b'\x7E') + msg))
		self.RxMessages.append(frame)
		return True

	def unescape(self, msg):
		if msg[-1] == 0x7D:
            # Last byte indicates an escape, can't unescape that
			return None
  
		out = bytearray()
		skip = False
		for i in range(len(msg)):
			if skip:
				skip = False
				continue
 
			if msg[i] == 0x7D:
				out.append(msg[i+1] ^ 0x20)
				skip = True
			else:
				out.append(msg[i])
 
		return out

print "Starting..."
xbee = XBeeAPI("/dev/ttyAMA0")
xbee.testHex()
#xbee.send("Hello World")