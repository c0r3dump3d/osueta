#!/usr/bin/python
# -*- coding: utf-8 -*-

__license__="""
osueta (OpenSSH User Enumeration Timing Attack)

Version 0.7

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


from osumain import main

if __name__=="__main__":
    main()
