#/usr/bin/python -tt

#Use command pip install scapy to install scapy which is required to run this script.
import socket
from os import geteuid,path
from scapy.all import *
import shutil 
import os
import os.path
from platform import system,python_version
import sys,argparse
from time import gmtime, strftime
import datetime
import hashlib
from optparse import OptionParser
import time
from threading import Thread

try:
    import scapy
except ImportError:
    del scapy
    from scapy import all as scapy

 
def assure_path_exists(path):
	
	dir = os.path.dirname(path)
       	if not os.path.exists(dir):
		print "[*] Directory Not Found ...Created New Directory. "
        	os.makedirs(dir) 


		


if __name__ == '__main__':
	print "Author Rohan,Himanshu,Sumedh,Ashwin."
	print "\n This Script is Solely Developed for Educational Purpose. Any Attempt to uses this script commerically is prohibited. Any modification to this script if made should be first informed to rohank.kulkarni3@yahoo.in"
	
	argument_parser = argparse.ArgumentParser(description="************************************************************************** \n \tRash is Written to Monitor DNS Server. \n **************************************************************************")
	
	argument_parser.add_argument("-p", "--print", help="Dns lookup for the given query.", metavar="<print>" , dest="printme")
	argument_parser.add_argument("-c", "--check", help="Check DNS Server is alive.", metavar="<check>" , dest="check")
	argument_parser.add_argument("-sw", "--sniff", help="Sniff DNS queries on Port 53 and Write DNS Sniffed Packet Output to Text File. ", metavar="<sniff>" , dest="sniffme")
	
	argument_parser.add_argument("-d", "--dest", help="Specify Destination File Path.", metavar="<destination>" , dest="destination")
	argument_parser.add_argument("-bs", "--bkp", help="Take Zone File Backup and Specify Source File Path", metavar="<backup>" , dest="backup")
	argument_parser.add_argument("-m", "--md5", help="Calculate Md5 of Zone Files and Compare Source and Backup File for Integrity Check.", metavar="<md5>" , dest="md5")
	argument_parser.add_argument("-zp", "--zoneprint", help="Prints Zone File Resouce Records With Mappings.", metavar="<zoneprint>" , dest="zoneprint")
	
	user_arguments = argument_parser.parse_args()

	if geteuid() != 0:
        	print "\n[+] ERROR: This program requires root priviledges to function properly.\n"
        	exit()
	# Check for Linux.
	if system() != "Linux":
		print "\n[+] ERROR: This program is designed to run on Linux systems.\n"
		exit()

	if user_arguments.printme:
		
		print socket.gethostbyname(sys.argv[2])

	elif user_arguments.check:
		hostname = sys.argv[2]
		print "****************************************************************"
		response = os.system("ping -c 1 " + hostname)

		if response == 0:
			print "___________________________________________________________________________"
    			print "Server is Responding"
			print "___________________________________________________________________________"
		else:
			print "___________________________________________________________________________"
  			print "Server Not Responding"
			print "___________________________________________________________________________"
		

	elif user_arguments.sniffme:
		try:
			print "****************************************************************************"
			
			print "Starting Dns Packet Sniffing on Interface "+ sys.argv[2] +" Current System Time is ",strftime("%a, %d %b %Y %X ", gmtime())
			fob = open("IP.txt","w")
			
			def querysniff(pkt):
				if IP in pkt:
                			ip_src = pkt[IP].src
                			ip_dst = pkt[IP].dst 
		  
                			if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
		
                       				print (str(ip_src) + " is going to " + str(ip_dst)+ " : " + "query is : (" + pkt.getlayer(DNS).qd.qname + ")" )
					
					fob.write("\n****************************************************************************************")
					fob.write("\n"+pkt[IP].src+' going to '+pkt[IP].src+" : "+pkt.getlayer(DNS).qd.qname)
					fob.write("\n________________________________________________________________________________________")

			sniff(iface = sys.argv[2],filter = "port 53", prn = querysniff, store = 0)
			fob.close()
			
			
			print ("\n[*] Shutting Down...")
		except Exception:
			pass


	elif user_arguments.backup:
		
				
		temp = "bak"
		a = sys.argv[2]
		b = sys.argv[4]
			
		modifiedTime = os.path.getmtime(sys.argv[2]) 

		timeStamp =  datetime.datetime.fromtimestamp(modifiedTime).strftime("%b-%d-%y-%H_%M_%S")


		assure_path_exists(b)
		
		
		fin_path = sys.argv[4]+"bak_"+timeStamp
		# copy file to desktop
		kk = "cp "+sys.argv[2]+" "+fin_path
		print kk
		uu = os.system(kk)
		
		#move file from Dekstop To dest folder
		#mov = "mv "+fin_path+" "+sys.argv[4]
		#print mov

		if uu ==0:
			print "Successfully Copied"
		else:
			print "failed"

		
		
		
	elif user_arguments.md5:
		
		orig_file_md5 = hashlib.md5(open(sys.argv[2],'rb').read()).hexdigest()
		print "Source File Md5 value is: "+orig_file_md5
		dest_file_md5_read = raw_input("Specify Destination Path of backed Up Zone File: ")
		try:
	
			dest_file_md5 = hashlib.md5(open(dest_file_md5_read,'rb').read()).hexdigest()
			print "Destination File md5 Value is: "+dest_file_md5
			choice = raw_input("Do u want to check integrity of source file with back up file(yes/no): ")
			if choice =='yes':
				print "in 1srt if"
				
				with open(dest_file_md5_read) as file_to_check:
					
					data = file_to_check.read()    
    # pipe contents of the file through
   					md5_returned = hashlib.md5(data).hexdigest()
				#else:
					#print "Alert!!! File has been tampered Check Your Zone File"
				if orig_file_md5 == md5_returned:
					print "No Manipulation of entries in zone file.."
				else:
					print "Alert!! Please recheck your zone files md5 not matching!!"
			
			else:
				sys.exit(1)
		except OSError:
			print "Excption Occured "+OSError
	elif user_arguments.zoneprint:
			pat = sys.argv[2]
			if os.path.isfile(pat): 
				print "Reading Resource Records from Specified File Path......Please Wait"
				time.sleep(5)
				searchfile = open(pat, "r")
				for line in searchfile:
					if "SOA" or "NS" or "A" or "PTR" or "CNAME" or "MX" or "SRV" or "AAAA" or "TXT" or "DNSKEY" in line: print "\n"+line
				searchfile.close()
			else:
				print "Wrong path Entered!!"
				
			
			
		
	else:
		print "***********************************************************************"
        	print "\n Invalid Arguments Use --help or -h!!"
		print "\n***********************************************************************"
	
	
		





