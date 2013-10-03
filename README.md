        ***************************************************************************
        *                  ___                 ___ ___ _  _                       *
        *                 / _ \ _ __  ___ _ _ / __/ __| || |                      *
        *                | (_) | '_ \/ -_) ' \\__ \__ \ __ |                      *
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
        ***************************************************************************


What's OSUETA?
==============

        Osueta it's a  simple script to exploit the OpenSSH User Enumeration Timing Attack:

        http://cureblog.de/openssh-user-enumeration-time-based-attack/
        http://seclists.org/fulldisclosure/2013/Jul/88
        http://www.devconsole.info/?p=341



Installing:
===========

        # apt-get install python-ipy python-nmap python-paramiko
        git clone https://github.com/osueta/osueta.git


Usage:
======

        osueta.py [-h] [-H HOST] [-p PORT] [-L UFILE] [-U USER] [-d DELAY]
                 [-v VARI]

        optional arguments:
                -h, --help  show this help message and exit
                -H HOST     Host to attack
                -p PORT     Host port
                -L UFILE    Username list file
                -U USER     Username
                -d DELAY    Time delay in seconds
                -v VARI     Make variations of the user name (default yes)
                
Example:
========

        ./osueta.py -H 192.168.1.6 -p 22 -U root -d 30 -v yes
