import sys, os, subprocess
from pwd import getpwnam  
import fileinput

mount_list = []
def fun_for_write():
            fd = open("/etc/fstab", 'r')
            for line in fd.readlines():
                l = []
                if '#' not in line:
			mnt_src = line.split()[0]
			mnt_dest = line.split()[1]
			mnt_fs = line.split()[2]
			if 'user' in line:
				mnt_user = 1
			else:
				mnt_user = 0
			l.append(mnt_src)
			l.append(mnt_dest)
			l.append(mnt_fs)
			l.append(mnt_user)
			mount_list.append(l)                  




def fun_for_sudo():
            global l1
            fd = open("./sudoers", 'r')
            lines = [i for i in open("./sudoers") if i[:-1]]
            for line in lines:
                if '#' not in line and 'Default' not in line:
			command = line.split()[1].split('=')[1].strip('(').strip(')')
                        if command == 'ALL':
                                command = -1
			if line.rstrip().startswith('%'):
                                fh = open('./groups', 'r')
				for i in fh.readlines():
                                    if i.split(':')[0] == line.split()[0].strip('%'):
					users = i.split(':')[3].lstrip()
                                        for usr in users.split(','):
					   if usr != '':
						usr = getpwnam(usr.strip()).pw_uid
						l = []
						l.append(usr)
						l.append(command)
						l.append(line.split()[2].rstrip())
						l1.append(l)
                        if '%' not in line:
                            l = []
                            l.append(getpwnam(line.split()[0]).pw_uid)
                            l.append(command)
                            l.append(line.split()[2])
                            l1.append(l)

	    print l1

   
def fun_update_pass(myfile):
            lines = [i for i in open(myfile) if i[:-1]]
            usr = lines[0].split(':')[0]
	    for line in fileinput.input("./passwd", inplace=1):
		    if usr in line:
		         print "%s" % (lines[0]),
		    else:
		         print line.strip()
	    print "Done"

l1 = []
fun_for_sudo()
fun_update_pass('./bhu')

