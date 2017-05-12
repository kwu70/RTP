#!/usr/bin/python

import sys
import random
import struct
import string
import Queue
import thread
import threading
import os
import binascii
from socket import *
from hashlib import *


SYN = 0x1
ACK = 0x2
NCK = 0x3
FIN = 0x4
networkThread = None
NUMRETRYTIMES = 10

#Global Variables
isConnected = False
seqNum = 0
ackNum = 0
sourcePort = 0
destPort = 0
destIP = 0
recvQueue = ""
sendQueue = ""
sock = None
currWindowSize = 10
currOtherWindowSize = 0
endProgram = 0

#Declare error codes
SUCCESS = 0
FAILTOCONNECT = 1
ERROR_CLOSED = 2
#Declare enum for current state
CLOSED = 0
ESTABLISHED = 1
ENDING = 2
ALMOST_DONE = 3
COLLISION = 4
WAITING = 5
LAST_MESSAGE = 6
TIMEOUT = 7
state = CLOSED

#CRC (Cyclic Redundancy Check)
#formula: f(x) = D*(2^r) XOR R = d + r
# D: is the date to be sent
# r: number of bits in generator R
# R: pattern that will be appended to the data
#
#  ------- d ------- -- r --
#  --------------------------
# |		Data		|	R	|
#  --------------------------
#
# d+r is sent to the receiving end and is checked with the following:
#
# if (((f(x)%R) == 0)
#		then no error
# else non zero detected, error
#
#Runs the provided crc32 checksum in binascii
def getChecksum(buf):
	return binascii.crc32(buf) &0xffffffff

# establish a connection between host and server
# @param socket - the socket that is being used for the connection.
# @param serverIP - the IP address of the server to connect to in string format.
# @param serverPort - the port number of the server to connect to as an integer.
# @param debugMode - whether to print debug output or not.
def connect(socket, serverIP, serverPort, debugMode):
	global seqNum, destPort, destIP, sock, isConnected, ackNum, currOtherWindowSize, state, endProgram, networkThread
	#Set up global variables
	endProgram = 0
	sock = socket
	socket.settimeout(5)
	destIP = serverIP
	destPort = serverPort
	address = (destIP, destPort)

	#If it's connected, we don't wanna connect again.
	if(isConnected):
		if (debugMode):
			print "Failed to establish connection, a connection already exists."
		raise Exception('Connection already exists')

	#establish a connection between host and server
	if(debugMode):
		print "Establishing connection to the Server " + serverIP + " : " + str(serverPort)
	packet = buildPacket(seqNum, ackNum, SYN, currWindowSize, "")
	response = ""
	retryTimes = 0
	loop = False
	#Loop until we are sure that the server received our packets
	while(retryTimes < NUMRETRYTIMES and not loop):
		socket.sendto(packet, address)
		retry = True
		while(retry):
			try:
				response, returnAddress = socket.recvfrom(1000)
				if(returnAddress == address):
					seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
					if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and ackNumber == seqNum + 1 and flags == SYN|ACK):
						retry = False
						loop = True
					else:
						retry = True
					retryTimes = 0
			except timeout:
				retry = False
		retryTimes += 1
		if(retryTimes < NUMRETRYTIMES and debugMode):
			print "Resending Authentication request to the server."

	#If we never got a response, let's get outta here.
	if(retryTimes == NUMRETRYTIMES):
		if(debugMode):
			print "Connection closed because server isn't responding."
		raise Exception('Server is not responding, dropping connection.')

	if(debugMode):
		print "Received SYNACK, sending random string"

	#Our next sequence number needs to be equal to the ACKNUM
	seqNum = seqNum + 1
	currOtherWindowSize = windowSize

	#Create randomVal to be sent to server to be hashed.
	randomVal = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(64))
	#Expected ackNum
	ackNum = seqNumber + 1
	packet = buildPacket(seqNum, ackNum, 0, currWindowSize, randomVal)
	if(debugMode):
		print TearPacket(packet)
	#First while loop is so that we can retry up to three times or until we get the data we want.
	response = ""
	retryTimes = 0
	loop = False
	while(retryTimes < NUMRETRYTIMES and not loop):
		socket.sendto(packet, address)
		retry = True
		while(retry):
			try:
				response, returnAddress = socket.recvfrom(1000)
				if(returnAddress == address):
					seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
					if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and seqNumber == ackNum):
						retry = False
						loop = True
					retryTimes = 0
			except timeout:
				retry = False
		retryTimes += 1
		if(retryTimes < NUMRETRYTIMES and debugMode):
			print "Resending packet to the host."

	if(retryTimes == NUMRETRYTIMES):
		if(debugMode):
			print "Connection closed because server isn't responding."
		raise Exception('Server is not responding, dropping connection.')	

	if(debugMode):
		print "Received hash of random string, comparing values."

	#Now we have received the MD5 of the string we sent.
	m = md5()
	m.update(randomVal)
	if(m.digest() != data):
		raise Exception('Hash server sent is not equal to the hash we need!')

	#Hash is valid, let's ACK and get this party started
	seqNum = ackNumber
	ackNum = len(data) + seqNumber
	packet = buildPacket(seqNum, ackNum, ACK, currWindowSize, "")
	if(debugMode):
		print "Value is correct! Finishing up establishment of connection."

	#Since it's the lastACK, we will send it if we get any new data from the server, or stop sending it.
	response = ""
	retryTimes = 0
	loop = False
	while(retryTimes < NUMRETRYTIMES and not loop):
		socket.sendto(packet, address)
		retry = True
		while(retry):
			try:
				response, returnAddress = socket.recvfrom(1000)
				if(returnAddress == address):
					seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
					if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and seqNumber == ackNum):
						retry = False
						loop = True
					retryTimes = 0
			except timeout:
				retry = False
				loop = True
		retryTimes += 1
		if(retryTimes < NUMRETRYTIMES and debugMode):
			print "Resending packet to the host."

	if(retryTimes == NUMRETRYTIMES):
		if(debugMode):
			print "Connection closed because server isn't responding."
		raise Exception('Server is not responding, dropping connection.')	

	#Now we are connected, so let's spin things up!
	isConnected = True
	seqNum = seqNum + 1
	state = ESTABLISHED
	#Spin up send and receive threads
	networkThread = threading.Thread(target=networkIO, args=(socket,debugMode))
	networkThread.start()
	
	if(debugMode):
		print "Established Connection!"

def accept(socket, debugMode):
	global seqNum, destPort, destIP, sock, isConnected, ackNum, currOtherWindowSize, state, endProgram, networkThread
	endProgram = 0
	sock = socket
	while 1:
		#We want to wait forever for a connection.
		socket.settimeout(None)
		retry = True
		while(retry):
			try:
				response, returnAddress = socket.recvfrom(1000)
				seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
				if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and flags == SYN):
					retry = False
			except Exception as e:
				if(debugMode):
					print e
				retry = True
			if(debugMode):
				print "Retrying"
		if(debugMode):
			print "Received SYN packet, sending SYNACK"

		#Set up global variables with new data we received. Then, send SYNACK
		currOtherWindowSize = windowSize
		ackNum = seqNumber + 1
		packet = buildPacket(seqNum, ackNum, SYN|ACK, currWindowSize, "")
		destIP = returnAddress[0]
		destPort = returnAddress[1]
		address = returnAddress
		#First while loop is so that we can retry up to three times or until we get the data we want.
		response = ""
		retryTimes = 0
		loop = False
		socket.settimeout(5)
		while(retryTimes < NUMRETRYTIMES and not loop):
			socket.sendto(packet, address)
			retry = True
			while(retry):
				try:
					response, returnAddress = socket.recvfrom(1000)
					if(returnAddress == address):
						seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
						if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and seqNumber == ackNum):
							retry = False
							loop = True
				except timeout:
					retry = False
			retryTimes += 1
			if(retryTimes < NUMRETRYTIMES and debugMode):
				print "Resending packet to the client."

		if(retryTimes == NUMRETRYTIMES):
			if(debugMode):
				print "Connection closed because client isn't responding."
			continue


		if (debugMode):
			print "Received Random string, sending hash."

		#Get md5 of the string.
		m = md5()
		m.update(data)
		hashVal = m.digest()
		seqNum = seqNum + 1
		ackNum = seqNumber + len(data)
		packet = buildPacket(seqNum,ackNum, 0, currWindowSize, hashVal)
		#First while loop is so that we can retry up to three times or until we get the data we want.
		response = ""
		retryTimes = 0
		loop = False
		socket.settimeout(5)
		while(retryTimes < NUMRETRYTIMES and not loop):
			socket.sendto(packet, address)
			retry = True
			while(retry):
				try:
					response, returnAddress = socket.recvfrom(1000)
					if(returnAddress == address):
						seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
						if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and seqNumber == ackNum and flags == ACK):
							retry = False
							loop = True
				except timeout:
					retry = False
			retryTimes += 1
			if(retryTimes < NUMRETRYTIMES and debugMode):
				print "Resending packet to the client."

		if(retryTimes == NUMRETRYTIMES):
			if(debugMode):
				print "Connection closed because client isn't responding."
			continue

		if(debugMode):
			print "Successfully established a connection!"

		#initalize variables
		isConnected = True
		seqNum = ackNumber
		ackNum = ackNum + 1
		state = ESTABLISHED
		#Start send a recieve threads.
		networkThread = threading.Thread(target=networkIO, args=(socket,debugMode))
		networkThread.start()
		#networkThread = thread.start_new_thread(networkIO,(socket,debugMode))
		break

#Simply add to our sendQueue buffer.
def send(socket, data):
	global sendQueue
	#need to implement
	sendQueue = sendQueue + data

#Remove from our buffer if there is data in it.
def recv(socket, bufferSize):
	global recvQueue
	while len(recvQueue) == 0:
		if(state != ESTABLISHED):
			raise Exception('Connection closed!')
	size = bufferSize if (len(recvQueue) > bufferSize) else len(recvQueue)
	data = recvQueue[:size]
	recvQueue = recvQueue[size:]
	return data



# This is a blocking call that will teardown the connection between the two connected hosts. //This call will be benign if there is no connection established.
# @param socket - the socket that is being used for the connection.
# @param debugMode - indicates whether it is debugMode or not.
def close(socket, debugMode):
	global endProgram
	#Probably want to make sure both send and receive threads are closed here.
	endProgram = 1
	networkThread.join()
	#Look into functionality of receiving packets
	global seqNum, destPort, destIP, sock, isConnected, ackNum, currOtherWindowSize, state
	address = (destIP,destPort)
	retryTimes = 0
	#If we are already closed, don't start sending packets.
	if(state == CLOSED):
		if(debugMode):
			print "ERROR: Connection already closed!"
		return ERROR_CLOSED
	socket.settimeout(5)
	if(state == ESTABLISHED):
		state = ENDING
		if(debugMode):
			print "Connection currently established...sending FIN"
		packet = buildPacket(seqNum, ackNum, FIN, currWindowSize, "")
		seqNum = seqNum + 1
		response = ""
		loop = False
		while(retryTimes < NUMRETRYTIMES and not loop):
			socket.sendto(packet, address)
			retry = True
			while(retry):
				try:
					response, returnAddress = socket.recvfrom(1000)
					if(returnAddress == address):
						seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
						if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and (seqNumber == ackNum or ackNumber >= seqNum)):
							retry = False
							loop = True
				except timeout:
					retry = False
			retryTimes += 1
			if(retryTimes < NUMRETRYTIMES and debugMode):
				print "Resending packet to the host."

		#If at any point the other host doens't respond, pretend we closed the connection.
		if(retryTimes == NUMRETRYTIMES):
			if(debugMode):
				print "Connection closed because host isn't responding."
			state = CLOSED
			socket.close()
			return SUCCESS

		if(flags == FIN):
			if(debugMode):
				print "Received FIN! Sending ACK and transitioning to collision state."
			#Go into the collision state!
			#Send an ACK
			packet = buildPacket(ackNumber, ackNum, ACK, currWindowSize, '')
			#First while loop is so that we can retry up to three times or until we get the data we want.
			response = ""
			loop = False
			while(retryTimes < NUMRETRYTIMES and not loop):
				socket.sendto(packet, address)
				retry = True
				while(retry):
					try:
						response, returnAddress = socket.recvfrom(1000)
						if(returnAddress == address):
							seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
							if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and flags == ACK):
								retry = False
								loop = True
					except timeout:
						retry = False
				retryTimes += 1
				if(retryTimes < NUMRETRYTIMES and debugMode):
					print "Resending packet to the host."

			if(retryTimes == NUMRETRYTIMES):
				if(debugMode):
					print "Connection closed because host isn't responding."
				state = CLOSED
				socket.close()
				return SUCCESS

			if(debugMode):
				print "Received ACK, going to Timeout state"

			response = ""
			retry = True
			while(retry):
				try:
					socket.recvfrom(1000)
				except timeout:
					retry = False

			if(debugMode):
				print "Connection Closed!"

			state = CLOSED
			socket.close()
			return SUCCESS
		if(flags == ACK):
			#Go to the almost done state!
			if(debugMode):
				print "Received ACK, waiting for FIN"
			socket.settimeout(None)
			while(retry):
				try:
					response, returnAddress = socket.recvfrom(1000)
					if(returnAddress == address):
						seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
						if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and flags == FIN):
							retry = False
				except timeout:
					retry = true

			if(debugMode):
				print "Received FIN, sending ACK and starting timeout"

			packet = buildPacket(seqNum, seqNumber + 1, ACK, currWindowSize, "")

			socket.settimeout(6)
			response = ""
			loop = False
			resend = True
			while(retryTimes < NUMRETRYTIMES and not loop):
				if(resend):
					socket.sendto(packet, address)
				retry = True
				while(retry):
					try:
						response, returnAddress = socket.recvfrom(1000)
						retry = False
						loop = True
						resend = False
						if(returnAddress == address):
							seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
							if(flags == FIN):
								retry = False
								resend = True
								loop = False

					except timeout:
						retry = False
						loop = True
						resend = False
				retryTimes += 1
				if(retryTimes < NUMRETRYTIMES and debugMode):
					print "Resending packet to the host."
			
			if(debugMode):
				print "Connection Closed!"

			state = CLOSED
			socket.close()
			return SUCCESS

	elif(state == WAITING):
		#Send the FIN, Recv ACK , then close.
		if(debugMode):
			print "Connection currently waiting...sending FIN"
		packet = buildPacket(seqNum, ackNum, FIN, currWindowSize, "")
		seqNum = seqNum + 1
		#First while loop is so that we can retry up to three times or until we get the data we want.
		response = ""
		loop = False
		while(retryTimes < NUMRETRYTIMES and not loop):
			socket.sendto(packet, address)
			retry = True
			while(retry):
				try:
					response, returnAddress = socket.recvfrom(1000)
					if(returnAddress == address):
						seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
						if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and flags == ACK):
							retry = False
							loop = True
				except timeout:
					retry = False
			retryTimes += 1
			if(retryTimes < NUMRETRYTIMES and debugMode):
					print "Resending packet to the host."

		if(debugMode):
			print "Connection closed!"
			state = CLOSED
			return SUCCESS

#Creates a packet for us
def buildPacket(seqNum, ackNum, flags, windowSize, data):
	#4 bytes seqNum
	#4 bytes ackNum
	#2 bytes flags
	#1 byte window
	#1 byte checksum
	#string data
	packet = struct.pack('IIHB',seqNum,ackNum,flags,windowSize) + data
	checksum = getChecksum(packet)
	packet = struct.pack('IIHBI',seqNum,ackNum,flags,windowSize,checksum) + data
	return packet

#Decomposes a packet for us
def TearPacket(packet):
	return struct.unpack_from('IIHBI', packet[:16], offset=0) + (packet[16:],)

#Verifies the checksum for us
#Need to do header and data
def VerifyChecksum(checksum,data,seqNum,ackNum,flags,windowSize):
	packet = struct.pack('IIHB',seqNum,ackNum,flags,windowSize) + data
	checksumPacket = getChecksum(packet)
	if(checksumPacket == checksum):
		return True
	return False

#Changes our window size for the receiver.
def setmaxwindowsize(windowSize):
	global currWindowSize
	if(windowSize <= 10 and windowSize > 0):
		currWindowSize = windowSize

#Performs all of our network IO
def networkIO(socket, debugMode):
	global seqNum, destPort, destIP, sock, ackNum, currOtherWindowSize, state, recvQueue, sendQueue,endProgram
	address = (destIP, destPort)
	acknowledged = True
	resend = False
	numWaitTimes = currWindowSize
	while 1:
		if(state != ESTABLISHED or endProgram == 1):
			print "Exiting"
			thread.exit()
		#If we have packets to send, send up to our max windowSize
		#Also, we will send more once we have been acknowledge, or if we need to resend.
		if(len(sendQueue) != 0 and (acknowledged == True or resend == True)):
			currSeqNum = seqNum
			numToSend = currOtherWindowSize
			numGrabbed = 0
			while(numToSend > 0 and len(sendQueue) != numGrabbed):
				sizeToGet = 980
				if(len(sendQueue) < 980):
					sizeToGet = len(sendQueue)
				packet = buildPacket(currSeqNum, 0, 0, currWindowSize, sendQueue[(currOtherWindowSize-numToSend)*980:(currOtherWindowSize-numToSend)*980+sizeToGet])
				socket.sendto(packet, address)
				currSeqNum = currSeqNum + len(sendQueue[(currOtherWindowSize-numToSend)*980:(currOtherWindowSize-numToSend)*980+sizeToGet])
				numGrabbed = numGrabbed + sizeToGet
				numToSend = numToSend - 1
			acknowledged = False
			numWaitTimes = currWindowSize
			if(debugMode):
				print "Sent " + str(currOtherWindowSize - numToSend)

		socket.settimeout(2)
		retry = True
		#Try and get packets, give the other end a 5 second response time before we send more!
		while(retry):
			try:
				response, returnAddress = socket.recvfrom(1000)
				if(returnAddress == address):			
					seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
					verified = VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize)
					#If it's valid, and its a new data packet or ACK packet, then we go this route.
					if(verified == True and (seqNumber == ackNum or ackNumber > seqNum)):
						currOtherWindowSize = windowSize
						#If it's an ACK, let's get rid of the appropriate data in our send queue.
						#and update our variables.
						if(flags == ACK):
							if(debugMode):
								print "Received ACK"
							sendQueue = sendQueue[ackNumber-seqNum:]
							seqNum = ackNumber
							acknowledged = True
							resend = False
							numWaitTimes = currWindowSize
						#This means that we have new data.
						#Let's get as much as we can up to the window size
						elif(flags == 0):
							if(seqNumber != ackNum):
								continue
							if(debugMode):
								print "Receiving packets"
							#This is new data. Add to buffer, send ACK.
							#Iterate and grab as many as our window size dictates
							#Then, send an ACK packet.
							newAckNum = ackNum + len(data)
							recvQueue = recvQueue + data
							innerRetry = True
							numPackets = currWindowSize - 1
							while(innerRetry and windowSize != 0 and numPackets != 0):
								try:
									response, returnAddress = socket.recvfrom(1000)
									if(returnAddress == address):
										seqNumber, ackNumber, flags, windowSize, checksum, data = TearPacket(response)
										if(VerifyChecksum(checksum,data,seqNumber,ackNumber,flags,windowSize) == True and seqNumber == newAckNum):
											newAckNum = newAckNum + len(data)
											recvQueue = recvQueue + data
											numPackets = numPackets - 1
								except timeout:
									innerRetry = False
							ackNum = newAckNum
							packet = buildPacket(seqNum, newAckNum, ACK, currWindowSize, "")
							socket.sendto(packet,address)
						elif(flags == FIN):
							if(debugMode):
								print "Received FIN"
							#We receive a FIN packet, it's time to go.
							#Send an ACK
							ackNum = seqNumber + 1
							packet = buildPacket(seqNumber, ackNum, ACK, currWindowSize, "")
							socket.sendto(packet,address)
							state = WAITING
						retry = False
					#Take this route, if it's a valid packet, that is not a FIN or ACK, that's seqNumber
					#is less than what we want, resend an ACK. We can assume that the other end didn't receive it.
					elif(verified and flags != FIN and flags != ACK and seqNumber < ackNum):
						packet = buildPacket(seqNum, ackNum, ACK, currWindowSize, "")
						socket.sendto(packet,address)
						retry = False
			except timeout: 
				#If we timeout, do not wait for more packets, head back to the send queue.
				#If we still haven't been acknowledged, we need to resend the data.
				retry = False
				if(acknowledged == False and numWaitTimes == 0):
					resend = True
				numWaitTimes = numWaitTimes-1
			except Exception:
				state = CLOSED