import sys, os, pyinotify
from optparse import OptionParser

parser = OptionParser()
parser.add_option("--debug", help="print debug messages", action="store_true", dest="debug")
(options, args) = parser.parse_args()

if not len(args):
	print "Usage : " + sys.argv[0] + " [options]"
	sys.exit(1) 
else:
	myfile = args[0] 

if options.debug:
    print "I am totally opening " + myfile 

wm = pyinotify.WatchManager()
    
dirmask = pyinotify.IN_MODIFY | pyinotify.IN_DELETE | pyinotify.IN_MOVE_SELF | pyinotify.IN_CREATE | pyinotify.IN_ACCESS | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CLOSE_NOWRITE
   
global fh 
fh = open(myfile, 'r')
fh.seek(0,2)
    
class PTmp(pyinotify.ProcessEvent):
    # Check file modification
    def process_IN_MODIFY(self, event):
        if myfile not in os.path.join(event.path, event.name):
            return
        else:
    	    print "MODIFY : File " + myfile + " is modified."  

    # Check file write on close
    def process_IN_CLOSE_WRITE(self, event):
	    print fh.readline().rstrip()
            print "CLOSE : Opened file " + myfile + " is closed."

    # Close on readOnly file
    def process_IN_CLOSE_NOWRITE(self, event):
            print "CLOSE : ReadOnly file " + myfile + " is closed."

    
    def process_IN_MOVE_SELF(self, event):
        if options.debug:
            print "MOVED : The file moved! Continuing to read from that, until a new one is created.."

    # Check file access
    def process_IN_ACCESS(self, event):
	print "ACCESS : File " + myfile + " is accessed"
	
    # Check file creation. If file is created after deletion with same name, it will be still monitored
    def process_IN_CREATE(self, event):
        if myfile in os.path.join(event.path, event.name):
            global fh
            fh.close
            fh = open(myfile, 'r')
            if options.debug:
                print "My file was created! I'm now catching up with lines in the newly created file." 
            for line in fh.readlines():
                print line.rstrip()
            fh.seek(0,2)
        return


notifier = pyinotify.Notifier(wm, PTmp())

index = myfile.rfind('/')
wm.add_watch(myfile[:index], dirmask)

while True:
    try:
        notifier.process_events()
        if notifier.check_events():
            notifier.read_events()
    except KeyboardInterrupt:
        break

notifier.stop()
fh.close()

sys.exit(0)
