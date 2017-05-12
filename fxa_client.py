import sys
import argparse
import random
import struct
import string
import thread
import os
import rtp
from socket import *
from hashlib import *

def Main():
	parser = argparse.ArgumentParser(description='Client for File Transfer')
	parser.add_argument('port', type=int, help='Port you want the client to bind to (must be an even number).')
	parser.add_argument('ip', type=str, help='the IP address of NetEmu')
	parser.add_argument('emuPort', type=int, help='the UDP port number of NetEmu')
	parser.add_argument('-d', action='store_true', help='Enables debug mode of the server interface.')
	args = parser.parse_args()

	debugMode = args.d
	clientPort = args.port
	emuIP = args.ip
	emuPort = args.emuPort

	#Server port needs to be between 0 and 65535 or they are invalid data.
	if (clientPort < 0) or (clientPort > 65535) or (clientPort%2 == 1):
		print "ERROR: Invalid Server port number! Must be between 0 and 65535 and an even number."
		exit()

	if ((emuPort < 0) or (emuPort > 65535)):
		print "ERROR: Invalid Port number for NetEmu. It must be between 0 and 65535."
		exit()

	#Check to see if the emuIP is in the correct IP format
	try:
	    inet_aton(emuIP)
	    # legal
	except error:
		if debugMode:
			print "Inputted server isn't an IP address. Trying DNS lookup..."
		try:
			emuIP = gethostbyname(emuIP)
		except:
			print "Invalid Hostname provided! Please change your inputs and try again..."
			exit()


	#Create a socket with AF_INET family, and SOCK_DGRAM type (a.k.a UDP)
	s = socket(AF_INET, SOCK_DGRAM)
	#s = socket(AF_INET, SOCK_STREAM)
	s.bind(('',clientPort))

	#Perform setup and binding then wait for a command

	WaitForCommands(s, emuIP, emuPort, debugMode)

def WaitForCommands(socket, serverIP, serverPort, debugMode):
	while 1:
		input = raw_input("Please enter a command: ")
		if(input == "disconnect"):
			#Call disconnect RxP here.
			rtp.close(socket, debugMode)
			if(debugMode):
				print "Connection closed."
			sys.exit()
		elif(input == "connect"):
			#rtp.connect(socket, serverIP, serverPort, debugMode)
			#Call connect here.
			if(debugMode):
				print "Establishing connection to the Server " + serverIP + " : " + str(serverPort)
			try:
				#Try to connect to the server. If it doesn't exists exit the program.
				rtp.connect(socket, serverIP, serverPort, debugMode)
			except Exception as e:
				print "Unable to connect to the server! Make sure the server is online! " + str(e)
				continue

			if(debugMode):
				print "Established connection to the Server."
		elif(input[:3] == "get"):
			filename = input[4:]
			filenameLen = len(filename)
			get = struct.pack(">I", 0)
			#Call start sending a get with the filename using send etc.

			#Header for transfers
			#1 byte for get or post. 0 for get, 1 for post. Ability to expand later.
			#4 bytes for filename length
			#filename length bytes for the filename
			try:
				rtp.send(socket,get + struct.pack(">I",filenameLen) + filename)
			except:
				print "Failed to send get request! Server most likely closed the connection."
				rtp.close(socket,debugMode)
				continue

			if(debugMode):
				print "Sent get request to the server"

			#Header for file sending
			#8 bytes for file length
			#file length bytes for file
			try:
				fileLength = ""
				bufSize = 4
				while len(fileLength) != 4:
					fileLength += rtp.recv(socket,bufSize)
					bufSize = 4 - len(fileLength)
			except Exception as e:
				print "Server closed the connection! Exiting..." + str(e)
				rtp.close(socket,debugMode)
				continue

			fileLength = struct.unpack(">L", fileLength)[0]

			if(fileLength == 0):
				print "File doesn't exist!! Please try a different file!"
				continue

			if(debugMode):
				print "File length is going to be " + str(fileLength)

			fileData = open(filename, 'w')
			#Get fileData
			try:
				data = ""
				bufSize = fileLength
				end = 1
				while (bufSize != 0) and (end):
					data = rtp.recv(socket,bufSize)
					bufSize = bufSize - len(data)
					if (bufSize == 0):
						end = 0
					fileData.write(str(data))
			except:
				print "Failed to get all of the file! Deleting file and closing the connection!"
				rtp.close(socket,debugMode)
				fileData.close()
				os.remove(filename)
				continue

			fileData.close()

			print "File successfully retreived!"
		elif(input[:3] == "put"):
			filename = input[4:]
			filenameLen = len(filename)
			put = struct.pack(">I", 1)
			if(not os.path.isfile(filename)):
				print "Not a file!"
				continue
			else:
				openFile = open(filename, "r")
				fileLen = os.path.getsize(filename)

			if(debugMode):
				print "File length is " + str(fileLen)


			#Call start sending a get with the filename using send etc.

			#Header for transfers
			#1 byte for get or post. 0 for get, 1 for post. Ability to expand later.
			#4 bytes for filename length
			#filename length bytes for the filename
			try:
				rtp.send(socket,put + struct.pack(">I",filenameLen) + filename)
			except:
				print "Failed to send get request! Server most likely closed the connection."
				rtp.close(socket,debugMode)
				continue

			if(debugMode):
				print "Sent get request to the server"

			#Header for file sending
			#8 bytes for file length
			#file length bytes for file

			fileLen = struct.pack(">L", fileLen)

			try:
				rtp.send(socket,fileLen)
				if(openFile != None):
					for line in openFile:
						rtp.send(socket,line)
			except Exception as e:
				print "Unable to send the whole file to the server... " + str(e)
				break

			print "File successfully sent!"
			#Start doing post stuff here if we implement it.
		elif(input[:6] == "window"):
			#Change window size with RxP method.
			rtp.setmaxwindowsize(int(input[7:]))
		else:
			print "Invalid command"



if __name__ == '__main__':
	Main()