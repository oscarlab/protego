import sys, os, pyinotify
from optparse import OptionParser
from pwd import getpwnam
from spwd import getspnam
from grp import getgrnam
import fileinput


mountfile = "/etc/fstab"
sudofile = "/etc/sudoers"
groupdir = "/etc/groups"
shadowdir = "/etc/shadows"
passwddir = "/etc/passwds"
gshadowdir = "/etc/gshadows"
groupfile = "/etc/group"
shadowfile = "/etc/shadow"
passwdfile = "/etc/passwd"
gshadowfile = "/etc/gshadow"
bindfile = "/etc/bind"
pppdfile = "/etc/ppp/options"
mount_helper = "/etc/proc_mount_writer"
sudo_helper = "/etc/proc_setuid_writer"
bind_helper = "/etc/proc_bind_writer"
pppd_helper = "/etc/proc_pppd_writer"

def fun_for_sudo():
	global sudofile
	global groupfile
	l1 = []
	fd = open(sudofile, 'r')
	lines = [i for i in open(sudofile) if i[:-1]]
	for line in lines:
		runaslist = []
		if '#' not in line and 'Default' not in line:
			if 'NOPASSWD' in line:
				nopass = 1
			else:
				nopass = 0
			if 'sudoedit' in line:
				sudoedit = 1
			else:
				sudoedit = 0
			runas = line.split()[1].split('=')[1].strip('(').strip(')')
			if runas == 'ALL':
					runaslist.append(-1)
			else:
				print '\n'+str(runas.split(','))+'\n'
				for run in runas.split(','):
					runaslist.append(getpwnam(run).pw_uid)
			if line.rstrip().startswith('%'):
				fh = open(groupfile, 'r')
				for i in fh.readlines():
					if i.split(':')[0] == line.split()[0].strip('%'):
						users = i.split(':')[3].lstrip()
						for usr in users.split(','):
							if usr != '':
								usr = getpwnam(usr.strip()).pw_uid
								for run in runaslist:
									l = []
									l.append(usr)
									l.append(run)
									l.append(line.split()[2].rstrip())
									l.append(nopass)
									l.append(sudoedit)
									l1.append(l)
				fh.close()
			if '%' not in line:
				l = []
				l.append(getpwnam(line.split()[0]).pw_uid)
				if runas == 'ALL':
					l.append(-1)
				else:
					l.append(getpwnam(runas).pw_uid)
				l.append(line.split()[2])
				l.append(nopass)
				l.append(sudoedit)
				l1.append(l)
	fd.close()
	return l1

def fun_for_mount():
	global mountfile
	mount_list = []
	fd = open(mountfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		l = []
		if line and not line.startswith('#'):
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
	fd.close()
	return mount_list
	
def fun_for_pppd():
	global pppdfile
	defaultRoute = 1
	fd = open(pppdfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		if line and not line.startswith('#'):
			if 'nodefaultroute' in line:
				defaultRoute = 0
				break
	fd.close()
	return defaultRoute

def fun_for_bind():
	global bindfile
	bind_list = []
	fd = open(bindfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		l = []
		if line and not line.startswith('#'):
			port = line.split()[0]
			user = getpwnam(line.split()[1]).pw_uid
			path = line.split()[2]
			l.append(port)
			l.append(user)
			l.append(path)
			bind_list.append(l)
	fd.close()
	return bind_list

def fun_for_passwd():
	global passwdfile
	passwd_list = []
	fd = open(passwdfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		l = []
		if line and not line.startswith('#'):
			user = line.split(':')[0]
			details = line
			l.append(user)
			l.append(details)
			passwd_list.append(l)
	fd.close()
	return passwd_list

def fun_for_shadow():
	global shadowfile
	shadow_list = []
	fd = open(shadowfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		l = []
		if line and not line.startswith('#'):
			user = line.split(':')[0]
			details = line
			l.append(user)
			l.append(details)
			shadow_list.append(l)
	fd.close()
	return shadow_list

def fun_for_group():
	global groupfile
	group_list = []
	fd = open(groupfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		l = []
		if line and not line.startswith('#'):
			user = line.split(':')[0]
			details = line
			l.append(user)
			l.append(details)
			group_list.append(l)
	fd.close()
	return group_list

def fun_for_gshadow():
	global gshadowfile
	gshadow_list = []
	fd = open(gshadowfile, 'r')
	for line in fd.readlines():
		line = line.rstrip()
		l = []
		if line and not line.startswith('#'):
			user = line.split(':')[0]
			details = line
			l.append(user)
			l.append(details)
			gshadow_list.append(l)
	fd.close()
	return gshadow_list

def diff(a, b):
	l = []
	for i in b:
		if i not in a:
			l.append(i)
	return l

def mount_IN_MODIFY(event):
	global global_mount_list
	global mount_helper
	sample_list = fun_for_mount()
	diff_list = diff(global_mount_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "running proc mount write : "+mount_helper+" "+str(diff_l[0])+" "+str(diff_l[1])+" "+str(diff_l[3])
			os.system(mount_helper+' '+str(diff_l[0])+' '+str(diff_l[1])+' '+str(diff_l[3]))
	global_mount_list = sample_list

def sudo_IN_MODIFY(event):
	global global_sudo_list
	global sudo_helper
	sample_list = fun_for_sudo()
	diff_list = diff(global_sudo_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "running proc setuid write : "+sudo_helper + " " + str(diff_l[0])+" "+str(diff_l[1])+" "+str(diff_l[2])+" "+str(diff_l[3])+" "+str(diff_l[4])
			os.system(sudo_helper+' '+str(diff_l[0])+' '+str(diff_l[1])+' '+str(diff_l[2])+' '+str(diff_l[3])+" "+str(diff_l[4]))
	global_sudo_list = sample_list
			
def bind_IN_MODIFY(event):
	global global_bind_list
	sample_list = fun_for_bind()
	diff_list = diff(global_bind_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "running proc bind write "+str(diff_l[0])+" "+str(diff_l[1])+" "+str(diff_l[2])
			os.system(bind_helper+' '+str(diff_l[0])+' '+str(diff_l[1])+' '+str(diff_l[2]))
	global_bind_list = sample_list
	
def pppd_IN_MODIFY(event):
	global global_pppd_defroute
	pppd_def = fun_for_bind()
	if(pppd_def != global_pppd_defroute):
		print "running proc pppd write "+str(pppd_def)
		os.system(pppd_helper+' '+str(pppd_def))
	global_pppd_defroute = pppd_def
	
def group_IN_MODIFY(event):
	global groupfile
	try:
		getgrnam(event.name)
	except:
		return
	print "MODIFY : File " + os.path.join(event.path, event.name) + " is modified."
	fun_update_file(os.path.join(event.path, event.name),groupfile)
	os.system('service nscd restart')
	
	
def passwd_IN_MODIFY(event):
	global passwdfile
	try:
		getpwnam(event.name)
	except:
		return
	print "MODIFY : File " + os.path.join(event.path, event.name) + " is modified."
	fun_update_file(os.path.join(event.path, event.name),passwdfile)
	os.system('service nscd restart')

def shadow_IN_MODIFY(event):
	global shadowfile
	try:
		getspnam(event.name)
	except:
		return
	print "MODIFY : File " + os.path.join(event.path, event.name) + " is modified."
	fun_update_file(os.path.join(event.path, event.name),shadowfile)
	os.system('service nscd restart')
	
	
def gshadow_IN_MODIFY(event):
	global gshadowfile
	try:
		getgrnam(event.name)
	except:
		return
	print "MODIFY : File " + os.path.join(event.path, event.name) + " is modified."
	fun_update_file(os.path.join(event.path, event.name),gshadowfile)
	os.system('service nscd restart')
	
def groupfile_IN_MODIFY(event):
	global global_group_list
	sample_list = fun_for_group()
	diff_list = diff(global_group_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "Group changed : "+str(diff_l[0])
			fun_write_back_file(os.path.join(groupdir,str(diff_l[0])), str(diff_l[1]))
	global_group_list = sample_list
	
	
def passwdfile_IN_MODIFY(event):
	global global_passwd_list
	sample_list = fun_for_passwd()
	diff_list = diff(global_passwd_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "passwd changed : "+str(diff_l[0])
			fun_write_back_file(os.path.join(passwddir,str(diff_l[0])), str(diff_l[1]))
	global_passwd_list = sample_list
	
def shadowfile_IN_MODIFY(event):
	global global_shadow_list
	sample_list = fun_for_shadow()
	diff_list = diff(global_shadow_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "shadow changed : "+str(diff_l[0])
			fun_write_back_file(os.path.join(shadowdir,str(diff_l[0])), str(diff_l[1]))
	global_shadow_list = sample_list
	
def gshadowfile_IN_MODIFY(event):
	global global_gshadow_list
	sample_list = fun_for_gshadow()
	diff_list = diff(global_gshadow_list, sample_list)
	if(len(diff_list)):
		for diff_l in diff_list:
			print "gshadow changed : "+str(diff_l[0])
			fun_write_back_file(os.path.join(gshadowdir,str(diff_l[0])), str(diff_l[1]))
	global_gshadow_list = sample_list
	

def fun_update_file(single_file,global_file):
	try:
		if os.path.getmtime(global_file) < os.path.getmtime(single_file):
			return
	except:
		return
	lines = [i for i in open(single_file) if i[:-1]]
	usr = lines[0].split(':')[0]
	for line in fileinput.input(global_file, inplace=1):
		if usr == line.split(':')[0]:
			print "%s" % (lines[0]),
		else:
			print line.strip()
	print "Done"
	
def fun_write_back_file(single_file,data):
	usr = data.split(':')[0]
	for line in fileinput.input(single_file, inplace=1):
		if usr == line.split(':')[0]:
			print "%s" % (data),
		else:
			print line.strip()
	print "Done"
	
def dafault_handler(event):
	print "Default handler called. Please check."


wm = pyinotify.WatchManager()

mountmask = pyinotify.IN_MODIFY
sudomask = pyinotify.IN_MODIFY
groupmask = pyinotify.IN_MODIFY
passwdmask = pyinotify.IN_MODIFY
shadowmask = pyinotify.IN_MODIFY
gshadowmask = pyinotify.IN_MODIFY
bindmask = pyinotify.IN_MODIFY
pppdmask = pyinotify.IN_MODIFY
notifier = pyinotify.Notifier(wm, dafault_handler)

wm.add_watch(mountfile, mountmask, mount_IN_MODIFY)
wm.add_watch(sudofile, sudomask, sudo_IN_MODIFY)
wm.add_watch(groupdir, groupmask, group_IN_MODIFY)
wm.add_watch(passwddir, passwdmask, passwd_IN_MODIFY)
wm.add_watch(shadowdir, shadowmask, shadow_IN_MODIFY)
wm.add_watch(gshadowdir, gshadowmask, gshadow_IN_MODIFY)
wm.add_watch(bindfile, bindmask, bind_IN_MODIFY)
wm.add_watch(pppdfile, pppdmask, pppd_IN_MODIFY)
wm.add_watch(groupfile, groupmask, groupfile_IN_MODIFY)
wm.add_watch(passwdfile, passwdmask, passwdfile_IN_MODIFY)
wm.add_watch(shadowfile, shadowmask, shadowfile_IN_MODIFY)
wm.add_watch(gshadowfile, gshadowmask, gshadowfile_IN_MODIFY)

l = fun_for_mount()
sudo_l= fun_for_sudo()
bind_l = fun_for_bind()
passwd_l = fun_for_passwd()
shadow_l = fun_for_shadow()
group_l = fun_for_group()
gshadow_l = fun_for_gshadow()
bind_l = fun_for_bind()
pppd_def = fun_for_pppd()
global_mount_list = []
global_sudo_list = []
global_bind_list = []
global_passwd_list = []
global_shadow_list = []
global_group_list = []
global_gshadow_list = []
global_mount_list = l
global_sudo_list = sudo_l
global_bind_list = bind_l
global_pppd_defroute = pppd_def
global_passwd_list = passwd_l
global_shadow_list = shadow_l
global_group_list = group_l
global_gshadow_list = gshadow_l
print "Initial mount list : ", global_mount_list
print "Initial sudoers list : ", global_sudo_list

for entry in global_mount_list:
	print "running proc mount write : "+mount_helper+" "+str(entry[0])+" "+str(entry[1])+" "+str(entry[3])
	os.system(mount_helper+' '+str(entry[0])+' '+str(entry[1])+' '+str(entry[3]))
	
for entry in global_sudo_list:
	print "running proc setuid write : "+sudo_helper + " " + str(entry[0])+" "+str(entry[1])+" "+str(entry[2])+" "+str(entry[3])+" "+str(entry[4])
	os.system(sudo_helper+' '+str(entry[0])+' '+str(entry[1])+' '+str(entry[2])+' '+str(entry[3])+' '+str(entry[4]))

for entry in global_bind_list:
        print "running proc bind write : "+bind_helper+" "+str(entry[0])+" "+str(entry[1])+" "+str(entry[2])
        os.system(bind_helper+' '+str(entry[0])+' '+str(entry[1])+' '+str(entry[2]))

print "running proc pppd write : "+pppd_helper+" "+str(global_pppd_defroute)
os.system(pppd_helper+' '+str(global_pppd_defroute))

while True:
	try:
		notifier.process_events()
		if notifier.check_events(None):
			notifier.read_events()
	
	except KeyboardInterrupt:
		break

notifier.stop()

sys.exit(0)
