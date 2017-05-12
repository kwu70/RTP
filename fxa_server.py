
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
	try:
		thread.start_new_thread(WaitForCommands, ())
	except Exception as e:
		print e
		print "ERROR: Couldn't start thread for command input...exiting."
		exit()

	parser = argparse.ArgumentParser(description='Server for File Transfer')
	parser.add_argument('port', type=int, help='Port you want the server to bind to (must be odd number).')
	parser.add_argument('ip', help='the IP address of NetEmu')
	parser.add_argument('emuPort', type=int, help='the UDP port number of NetEmu')
	parser.add_argument('-d', action='store_true', help='Enables debug mode of the server interface.')
	args = parser.parse_args()

	debugMode = args.d
	serverPort = args.port
	emuIP = args.ip
	emuPort = args.emuPort

	#Server port needs to be between 0 and 65535 or they are invalid data.
	if (serverPort < 0) or (serverPort > 65535) or (serverPort%2 == 0):
		print "ERROR: Invalid Server port number! Must be between 0 and 65535 and an odd number."
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
	s.bind(('',serverPort))
	
	while 1:
		rtp.accept(s, debugMode)

		while 1:
			try:
				bufSize = 8
				request = ""
				while len(request) != 8:
					request += rtp.recv(s,bufSize)
					bufSize = 8 - len(request)
			except Exception as e:
				print "Client disconnected. Waiting for new clients... " + str(e)
				break

			typeReq = struct.unpack(">I", request[:4])[0]
			fileNameLen = struct.unpack(">I", request[4:])[0]

			if(debugMode):
				print "Request type " + str(typeReq) + " file name length " + str(fileNameLen)

			if(typeReq == 0):
				try:
					bufSize = fileNameLen
					filename = ""
					while len(filename) != fileNameLen:
						filename += rtp.recv(s,bufSize)
						bufSize = fileNameLen - len(filename)
				except:
					print "Client disconnected. Waiting for new clients..."
					break

				if(debugMode):
					print "File name is " + filename

				if(os.path.isfile(filename)):
					openFile = open(filename, "r")
					fileLen = os.path.getsize(filename)
				else:
					openFile = None
					fileLen = 0

				if(debugMode):
					print "File length is " + str(fileLen)

				fileLen = struct.pack(">L", fileLen)

				try:
					rtp.send(s,fileLen)
					if(openFile != None):
						for line in openFile:
							rtp.send(s,line)
				except Exception as e:
					print "Unable to send the whole file to the client..." + str(e)
					break

				if(debugMode):
					if(fileLen == 0):
						print "No file found on the server."
					else:
						print "Successfully sent the file to the client."
			elif(typeReq == 1):
				try:
					bufSize = fileNameLen
					filename = ""
					while len(filename) != fileNameLen:
						filename += rtp.recv(s,bufSize)
						bufSize = fileNameLen - len(filename)
				except:
					print "Client disconnected. Waiting for new clients..."
					break

				if(debugMode):
					print "File name is " + filename

				#Header for file sending
				#8 bytes for file length
				#file length bytes for file
				try:
					fileLength = ""
					bufSize = 4
					while len(fileLength) != 4:
						fileLength += rtp.recv(s,bufSize)
						bufSize = 4 - len(fileLength)
				except Exception as e:
					print "Client closed the connection! Exiting..." + str(e)
					rtp.close(s,debugMode)
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
						data = rtp.recv(s,bufSize)
						bufSize = bufSize - len(data)
						if (bufSize == 0):
							end = 0
						fileData.write(str(data))
				except:
					print "Failed to get all of the file! Deleting file and closing the connection!"
					rtp.close(s,debugMode)
					fileData.close()
					os.remove(filename)
					continue

				fileData.close()

				print "File successfully retreived!"

		rtp.close(s,debugMode)

def WaitForCommands():
	while 1:
		input = raw_input("Please enter a command: ")
		if(input == "terminate"):
			os._exit(0)
		elif(input[:6] == "window"):
			#Change window size with RxP method.
			rtp.setmaxwindowsize(int(input[7:]))
		else:
			print "Invalid command"



if __name__ == '__main__':
	Main()