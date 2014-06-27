#!/usr/bin/python
############################################################################################
#
# File: satregister.py
# Desc: Register with the UM Red Hat Satellite, including the ability to unregister from 
#        previous a Satellite, provide profile, activation keys, and asset information 
#        for the machine
#       Must provide a username/password combination of a Org Admin that exists on the Satellite
#        (if unregistering from a, the same username/password combination must exist on both)
# Options: Provided with the --help option
#
# Version history:
#	1.3: 6/27/14 dsglaser - Added EPEL, ELRepo and Org specific public keys to script
#	1.2: 6/24/14 dsglaser - Changed python xmlrpc exception handling so it works on Python <2.6
#	1.1: 6/23/14 dsglaser - Fixed dry run check on LSA removal selection
# 	1.0: 6/17/14 dsglaser - Initial creation
#
############################################################################################

### import various libs needed for the python script
import xmlrpclib
import sys
import getopt
from string import atoi, atoi_error
import datetime
import os
import re
import subprocess
import fileinput
import socket
import getpass
import platform

##############################################################################################
# Variable descriptions:
#
# SATELLITE_URL: The URL of the previous Satellite server.
# NEW_SATELLITE_URL: The URL of the new Satellite server.
# login: Userid of an org admin on (both) Satellite(s).
# password: Password for the account on (both) Satellite(s).
#      (this information can be provided in an external file or prompted at runtime)
# ORG_KEY: URL of the location of your organization's channel key for packages
# WIKI_URL: URL of documentation location for activation key information
# VERBOSE: Toggle verbosity of output
# DRY: Toggle whether the run will be real or pretend
# FORCE: Enable the 'forcing' of the machine to register to the Satellite, needed if the 
#         machine was previously registered to a Satellite or to RHN directly
# unregister: Toggle whether to unregister the machine from the Satellite listed in SATELLITE_URL
# profilename: Profile name to register the system with. Defaults to 'hostname', is set via 
#               user prompt
# credentialsFileName: The file with login and password information. A 2 line file with the 
#                       login on the first line and the password on the second.
# building: Profile information - building the machine is located in
# room: Profile information - room the machine is located in
# busowner: Profile information - the business owner of the machine. This overrides the 'rack' 
#            variable since there is no 'owner' variable and custom keys are only available 
#            to systems with the provisioning entitlement enabled.
# autoupdate: Toggle to enable "Autoupdate Errata" on a system after registration. 
#
# Less used variables
# SYSIDFILE: The file where the machine's systemid file is located
# GPGKEYFILE: File(s) where the GPG key for Red Hat is located
# UP2DATEFILE: The file that defines what Satellite to talk to for patches
# srvinfo: A Python dict for constructing the profile information. Do not change

##############################################################################################

login = ""
password = ""
SATELLITE_URL = "http://rhn.lsa.umich.edu/rpc/api"
NEW_SATELLITE_URL = "http://rhn.miserver.it.umich.edu/rpc/api"
WIKI_URL = "https://wiki.umms.med.umich.edu/x/OKPwBg"
ORG_KEY = "http://www.umich.edu/~umrhn/scripts/msis/templates/RPM-GPG-KEY-University_of_Michigan_MSIS"
VERBOSE = False
DRY = False
FORCE = "yes"
unregister = False
profilename = socket.gethostname()
credentialsFileName = ""
building = ""
room = ""
busowner = ""
autoupdate = False
servinfo = {}

SYSIDFILE = "/etc/sysconfig/rhn/systemid"
GPGKEYFILE = ["/usr/share/rhn/RPM-GPG-KEY", "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"]
UP2DATEFILE = ["/etc/sysconfig/rhn/up2date"]

def usage():
     print "Script to register machines with the UM Red Hat Satellite (and optionally remove"
     print " them from an old Satellite"
     print ""
     print "Optional Arguments:"
     print "   -u,   --unregister        Unregister system from old Satellite. Without"
     print "				  this the system will only register with the new ITS sat"
     print "   -l,   --login=FILE        FILE should be a two-line file, where the first line is"
     print "                             the account name used to log into the satellite, and"
     print "                             the second line is the password associated with the"
     print "                             account."
     print ""
     print ""
     print "Profile Arguments:"
     print "   -p,   --profile=PROFILENAME The name of the profile that you'd like the machine"
     print "                             if different than the hostname currently set on the"
     print "                             system"
     print "   -a,   --activationkeys=KEY Comma separated list of activation keys used "
     print "                             to register the machine with. Keys can be found at"
     print "                  		 " + WIKI_URL
     print "   -A,   --autoupdate	 Set machine for auto-errata update."
     print "   -b,   --building=BLDG    Set building location for system."
     print "   -r,   --room=ROOM         Set room location for system."
     print "   -o,   --busowner=BUS      uniquid of business owner for the system (overrides the 'rack' variable)."
     print "Other Arguments:"
     print "   -h,   --help              Display this help and exit"
     print "   -v,   --verbose           Display the logging messages to stdout as well."
     print "   -f,   --force             Force registeration to a Satellite (rhnreg_ks --force)."
     print "   -D,   --dry               Do output as normal, except make no changes."
     print ""
     return

try:
        opts, args = getopt.getopt(sys.argv[1:], "p:l:a:b:r:o:hvufAD", ["login=",
                          "activationkeys=",
                          "profile=",
			  "building=",
			  "room=",
			  "busowner=",
                          "help",
                          "verbose",
                          "dry"])
except getopt.GetoptError:
        usage()
        sys.exit(1)

for opt, arg in opts:
        if opt in ("-h", "--help"):
                usage()
                sys.exit(0)
        elif opt in ("-v", "--verbose"):
                VERBOSE = True
        elif opt in ("-p", "--profile"):
                profilename = arg
        elif opt in ("-l", "--login"):
                credentialsFileName = arg
	elif opt in ("-a", "--activationkeys"):
		keylist = arg
	elif opt in ("-b", "--building"):
		building = arg
	elif opt in ("-r", "--room"):
		room = arg
	elif opt in ("-o", "--busowner"):
		busowner = arg
	elif opt in ("-u", "--unregister"):
		unregister = 1
	elif opt in ("-f", "--force"):
		FORCE = "--force"
	elif opt in ("-A", "--autoupdate"):
		autoupdate = 1
        elif opt in ("-D", "--dry"):
                DRY = True
        elif opt in ("-s", "--send"):
                SEND = True

###If we aren't root, exit
if not os.geteuid() == 0:
	sys.exit("** You must run this script as root **")


###If login wasn't provided at the top of the file, try to load it from the credentials file
if login == "" or password == "":
	if credentialsFileName != "":
		try:
			credentialsFile = open(credentialsFileName, 'r')
			login = credentialsFile.readline()
			password = credentialsFile.readline()
			credentialsFile.close()
		except IOError:
			print "Credentials file not found, please input login details:"
			login = raw_input("Login: ")
			password = getpass.getpass()

###Ask the user to input the login and password since it wasn't added earlier
if login == "" or password == "":
	login = raw_input("Login: ")
	password = getpass.getpass()

###At this point, if we still have no login info, then die.
if login == "" or password == "":
	print "Login not provided either in file, via credentials file, or manually input. Exiting"
        sys.exit(4)

# Verify if we are running in 'dry' mode
if DRY == True:
        out = "Doing a DRY RUN------Profile will NOT be deleted (if selected) and system will not be registered with a Satellite!"
        print out

###Connect to the server if we are unregistering
if unregister == True :
	try:
		client = xmlrpclib.Server(SATELLITE_URL, verbose=0)
		out = "Connected to %s successfully." % SATELLITE_URL
		if VERBOSE : print out
	except:
		out = "Unable to connect to server %s\nExiting\n" % SATELLITE_URL
		if VERBOSE : print out
		sys.exit(2)

	###Open a session
	try:
		session = client.auth.login(login, password)
		out = "Session created with login = %s and supplied password" % login
		if VERBOSE : print out
	except:
		out = "Unable to create session with login = %s and supplied password\n" % login
		print out
		sys.exit(3)

	###Parse the systemid file for the current systemid
	fileexists = os.path.isfile(SYSIDFILE)
	if fileexists == 1:
		idfile=open(SYSIDFILE)
		strings=re.findall(r'ID-\d{10}',idfile.read())
		word=strings[0]
		word=word[3:]
		if VERBOSE : print "System ID for system is: " + word
		found = "yes"
	else:
		print "System does not have a local systemid file, will not attempt to unregister from old satellite"
		found = "no"

	###Find the system based on the systemid on the old Satellite, if it is not there, skip
	try:
		if found == "yes" : 
			client.system.getName(session,int(word))
			found = "yes"
	except Exception, err:
		found = "no"
		print "System not found on "+SATELLITE_URL+", skipping unregistration"

	###Delete the System on the old Satellite
	if found == "yes":
		try:
			print "Deleting system with SystemID: "+word
			if DRY != True: client.system.deleteSystems(session,int(word))
		except Exception, err:
			found = "no"
			print "System not found on "+SATELLITE_URL+", skipping unregistration"

	###Close the session
	client.auth.logout(session)
	out = "Exited normally.\n"+SATELLITE_URL+" Session closed."
	if VERBOSE : print out

###Set up machine for new Satellite
for file in GPGKEYFILE:
	if os.path.isfile(file):
		if VERBOSE : print ("Importing " + file)
		if DRY != True : subprocess.call(["rpm","--import", file], stdout=None, stderr=None)

if VERBOSE : print ("installing ITS SSL Cert")
if DRY != True : subprocess.call(["/bin/rpm","-Uvh","http://rhn.miserver.it.umich.edu/pub/rhn-org-trusted-ssl-cert-1.0-5.noarch.rpm"],stderr=None,stdout=None)

###Alter the UP2DATEFILE to point to the new Satellite. This works for RHEL6 (subscribed to LSA), 
###   RHEL6 (unsubscribed), and RHEL7 (unsubscribed)
if VERBOSE : print "Changing from current Satellite to ITS Satellite, if needed"
if DRY != True:
	for line in fileinput.input(UP2DATEFILE,inplace=1):
		line = re.sub("xmlrpc.rhn.redhat.com","rhn.miserver.it.umich.edu",line.rstrip())
		print(line)

	for line in fileinput.input(UP2DATEFILE,inplace=1):
		line = re.sub("rhn.lsa.umich.edu","rhn.miserver.it.umich.edu",line.rstrip())
		print(line)

	for line in fileinput.input(UP2DATEFILE,inplace=1):
		line = re.sub("enter.your.server.url.here","rhn.miserver.it.umich.edu",line.rstrip())
		print(line)

	for line in fileinput.input(UP2DATEFILE,inplace=1):
		line = re.sub("^sslCACert\=.*$","sslCACert=/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT",line.rstrip())
		print(line)

###Build new profile information
###Let user know how the machine was registered
print "Registering system with following information"
print "Activation Key list: " + keylist
if FORCE == "--force" :
	print "Force = yes"
else:
	print "Force = no"
if profilename != "" :
	print "Profile Name: " + profilename
else:
	print "Using default profile for machine"
if autoupdate :
	print "Auto Update Errata: yes"
else:
	print "Auto Update Errata: no"
print "Building: " + building
print "Room: " + room
print "Business Owner: " + busowner

###Register system with new Satellite
print "Registering system on ITS Satellite with above information"
if DRY != True : subprocess.call(["/usr/sbin/rhnreg_ks",FORCE,"--activationkey="+keylist,"--profilename="+profilename])

###Import new GPG keys

###Import LSA Key for shared packages
if VERBOSE : print ("Importing LSA GPG Key")
if DRY != True : subprocess.call(["/bin/rpm","--import","http://rhn.lsa.umich.edu/umks/keys/stewards-gpg-key"],stderr=None,stdout=None)

###Import the ELRepo Key
if VERBOSE : print ("Importing ELRepo Key")
if DRY != True : subprocess.call(["/bin/rpm","--import","https://www.elrepo.org/RPM-GPG-KEY-elrepo.org"],stderr=None,stdout=None)

###Import the EPEL Key based on the OS version
dist = platform.linux_distribution()
if dist < '6' :
	if VERBOSE : print ("Importing EPEL 5 Key")
	if DRY != True : subprocess.call(["/bin/rpm","--import","http://download.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-5"],stderr=None,stdout=None)

elif dist[1] >= '6' or dist[1] < '7' :
	if VERBOSE : print ("Importing EPEL 6 Key")
	if DRY != True : subprocess.call(["/bin/rpm","--import","http://download.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-6"],stderr=None,stdout=None)

else: 
	if VERBOSE : print ("Importing EPEL 7 Key")
	if DRY != True : subprocess.call(["/bin/rpm","--import","http://download.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7"],stderr=None,stdout=None)

###Import Organization key if ORG_KEY is set
if ORG_KEY != "" :
	if VERBOSE : print ("Importing "+ ORG_KEY)
	if DRY != True : subprocess.call(["/bin/rpm","--import",ORG_KEY],stderr=None,stdout=None)

###Open an API session to set system details
try:
        its = xmlrpclib.Server(NEW_SATELLITE_URL, verbose=0)
       	if VERBOSE : "Connected to %s successfully." % NEW_SATELLITE_URL
except:
      	print "Unable to connect to server %s\nExiting\n" % NEW_SATELLITE_URL
       	sys.exit(2)
try:
       	newsession = its.auth.login(login, password)
       	if VERBOSE : "Session created with login = %s and supplied password" % login
except:
       	print "Unable to create session with login = %s and supplied password\n" % login
       	sys.exit(3)

###Parse the systemid file for the current systemid
fileexists = os.path.isfile(SYSIDFILE)
if fileexists == 1:
	idfile=open(SYSIDFILE)
	strings=re.findall(r'ID-\d{10}',idfile.read())
	word=strings[0]
	word=word[3:]
	if VERBOSE : print "NEW System ID for system is: " + word
	found = "yes"
else:
       	print "System does not have a local systemid file, will not attempt set details"
	sys.exit(3)

###Find the system based on the systemid as currently set. (if we registered to a satellite, or to 
###  a new satellite, it should exist). If it is not there, skip
try:
	if found == "yes" : 
		its.system.getDetails(newsession,int(word))
except Exception, err:
	found = "no"
	print "System not found on "+NEW_SATELLITE_URL+" Satellite skipping set details"
	sys.exit(3)

###Build a Python dict with the variables set earlier
servinfo = {"profile_name" : profilename, "auto_errata_update" : bool(autoupdate), "building" : building, "room" : room, "rack" : busowner}

###Set the system details
if DRY != True : its.system.setDetails(newsession,int(word),servinfo)

###Close session
its.auth.logout(newsession)
if VERBOSE: print "Exited normally.\n" + NEW_SATELLITE_URL+ " Session closed."
