#!/bin/env python

## Following script should ssh to hosts and change root password
## It should support multithreading
## author: sergii.diachenko@bskyb.com

## prerequisities : pexpect.2.4 , python2.6+ , wil.py 

# Import os/sys modules and set libpath
import socket, sys, os, datetime
sys.path.append(sys.path[0]+os.sep+'lib')

# import other modules
import getpass,pexpect
import thread,time,Queue as queue
import re

from wil import sshConnection, checkConnectivity, sshException
#import task, Command, qproducer, qconsumer
#from guppy import hpy   ## For memory profiling
#import Queue

safePrint = thread.allocate_lock()

result = []

## Global constant variables
NUM_THREADS = 20
TIMEOUT = 60
LOG_VERBOSITY = 5# 1-5, 5 is the max
USER_ROOT='root'

taskQueue = queue.Queue()

class ChangeRootPassword():
    """Root password changer class"""
    def __init__(self,hostList,credentials,newRootPassword,pwdComplexityCheck=True,logfile=None,user=USER_ROOT):
        ## credentials - list of dicts (user, password)
        assert isinstance(credentials,list), "Credentials should be list type!"
        assert isinstance(newRootPassword,str), "ERROR. New root password is not string value"
        assert isinstance(hostList,list), "ERROR. Invalid host_list value"
        assert isinstance(user,str), "ERROR. Invalid type for user supplied"
        self.credentials = credentials
        self.newRootPassword = newRootPassword
        self.hostList = hostList
        if not logfile:
            logfile = 'root_pass_change.out'
        self.logger = logger(logfile)
        self.user = user

        ## Reg exp definitions
        self.RE_IN_SUDOPASS         = '(?i)sudo password: ?$'
        self.RE_OUT_SUDORESTRICTED  = '(?i)is not in the sudoers file'
        self.RE_IN_NEWPASS          = '(?i)new .*password: ?$'
        self.RE_OUT_PASSUPDATED     = '(all authentication tokens updated successfully|password successfully changed|Passwd successfully changed)'
        self.RE_OUT_ERRORS          = '(?i)(only root can specify a user name.|passwords do(\'| no)t match|Sorry|Passwords must differ)'
        self.RE_IN_OLDPASS          = '(?i)Old password:'
        self.RE_IN_HPUXCHOISE       = '(?i)Enter choice here:'

        self.ROOT = 'root'

        ## Check for new RootPassword complexity
        if pwdComplexityCheck:
            self.checkPasswordComplexity()

    def changePasswordTelnet(self,host,relay=None,relayCredentials=[]):
        pass

    def changePasswordSSH(self,relay=None,relayCredentials=[]):
        ## (sshConnection) -> bool
        expectList = [self.RE_IN_OLDPASS,
                      self.RE_IN_HPUXCHOISE,
                      self.RE_IN_NEWPASS,
                      self.RE_OUT_PASSUPDATED,
                      self.RE_OUT_ERRORS,
                      pexpect.EOF,
                      pexpect.TIMEOUT]
        #raise sshException('User not in sudoers file')# if login_as_admin:
        ##   execute('sudo change pass')
        ##   if success:
        ##
        ## 1. login as system admin (unixadm) user and try to change password with 'sudo' command.
        ## 2. if sysadmin login - success, but not enough credentials to run sudo - switch root.
        ## 3. if cannot login as sysadmin - try login as root directly
        host = self.hostList[0]
        for user,password in self.credentials:
            #print "Trying {0} {1}".format(user,password)
            sudoRequired = True if user != self.ROOT else False
            passwdCommand = 'passwd {user}'.format(user=self.user)
            c = sshConnection(host,user,password,jumpHost=relay, jumpCredentials=relayCredentials)
            current_root_pw = ''
            result = False
            try:
                if c.connect():
                    self.logger.write(host,3,'Logged in as {0}'.format(user))
                    ## Attempt to switch root
                    if user != self.ROOT:
                        if c.changeUser(self.ROOT,None,sudoFlag=True):
                            self.logger.write(host,3,'Switched to {0} with sudo'.format(self.ROOT))
                        else:
                            for u,p in self.credentials: 
                                if u == self.ROOT:
                                    if c.changeUser(u,p,sudoFlag=False):
                                        current_root_pw = p
                                        self.logger.write(host,3,'Switched to {0}'.format(u))
                                        break
                                    else:
                                        raise Exception("Failed switch to {}".format(self.ROOT))
                    else:
                        ## if we already logged in as root
                        current_root_pw = password
                    c.sendline(passwdCommand)
                    x = c.expect(expectList)

                    ## Query for current root password
                    if x == 0:
                        if current_root_pw:
                            c.sendline(current_root_pw)
                            x = c.expect(expectList)
                            if x == 1:
                                ## HPUX choise 'p' - pick your own password value
                                c.sendline('p')
                                x = c.expect(expectList)

                        ## if we have no info about current valid password 
                        else:
                            ## try at least first root password from credentials
                            r = False
                            for u,p in self.credentials:
                                if u == self.ROOT:
                                    c.sendline(p)
                                    x = c.expect(expectList)
                                    r = True
                                    break
                            if not r:
                                c.sendcontrol('c')
                    ## Query for new password
                    if x == 2:
                        c.sendline(self.newRootPassword)
                        x = c.expect(expectList)
                        if x == 2:
                            c.sendline(self.newRootPassword)
                            x = c.expect(expectList)
                            ## Password changed 
                            if x == 3: 
                               result = True
                               return result
                    if x == 4:
                        self.logger.write(host,3,"Error happened here, entered password don't match or denied to invoke passwd root")
                        raise sshException('Strange things happened here')
                    if x == 5:
                        self.logger.write(host,3,"EOF received")
                        raise sshException(sshException.EOF)
                    if x == 6:
                        secured_out = c.before
                        secured_out.replace(password,'*SECURED_PASSWORD*').replace(self.newRootPassword,'*SECURED_PASSWORD*')
                        self.logger.write(host,3,"Unhanlded output or timeout happened, output below:\n {0:>10}".format(secured_out))
                        raise sshException(sshException.TIMEOUT)
                else:
                    self.logger.write(host,3,"Failed to ssh as {0}".format(user))
            except Exception,e:
                self.logger.write(host,4,str(e))
            finally:
                if c.isalive():
                    c.close()

        if not result:
            self.logger.write(host,2,"Password NOT updated")

    def start(self):
        ## define variables and functions
        exitmutexes = [ thread.allocate_lock() for i in range(len(self.hostList)) ]
        thread.start_new_thread(qproducer,(1,self))
        for consum in range(min(NUM_THREADS,len(self.hostList))):
            thread.start_new_thread(qconsumer,(consum,taskQueue,exitmutexes))
        while not all(mutex.locked() for mutex in exitmutexes): time.sleep(0.25)

    def checkPasswordComplexity(self):
        pwd = self.newRootPassword
        ## TODO: define password complexity policy and implement checks
        return True

relayHost = None
relayCredentials = ()

def qproducer(idnum,changeRootPasswordObject):
    global relayHost,relayCredentials
    ## FIXME! Wrong place for these variables, just for test purposes
    # relayHost='localhost'
    # relayCredentials=('wil_test','wil_test')
    for host in changeRootPasswordObject.hostList:
        currentTask = cpTask(host,changeRootPasswordObject.newRootPassword,changeRootPasswordObject.credentials,relayHost,relayCredentials,changeRootPasswordObject.logger,user=changeRootPasswordObject.user)
        taskQueue.put(currentTask)

def qconsumer(idnum,taskQueue,exitmutexes):
    while True:
        time.sleep(0.1)
        try:
            currentTask = taskQueue.get(block=False)
        except:
            pass
        else:
            with safePrint:
                print 'consumer [{0}] get task [{1}] for processing {2} '.format(idnum, currentTask.id, currentTask.host)
            currentTask.start()
            exitmutexes[currentTask.id].acquire()   
 

class cpTask():
    tid = 0
    ## Change password task entity
    def __init__(self,host,newPassword,credentials,defRelayHost=None,defRelayCredentials=(),logger=None,user=USER_ROOT):
        assert isinstance(host,str)
        assert isinstance(newPassword,str)
        assert isinstance(credentials,list)
        assert isinstance(user,str)
        self.host = host
        self.newPassword = newPassword
        self.credentials = credentials
        self.relayHost = defRelayHost
        self.user = user
        self.relayCredentials = defRelayCredentials
        self.id = cpTask.tid
        self.logger = logger if logger else logger('')
        cpTask.tid = cpTask.tid + 1

    def start(self):
        PORT_SSH, PORT_TELNET = 22, 23
        c = None
        res = False
        if self.relayHost: 
            port_ssh_relay_avail = checkConnectivity(self.relayHost, PORT_SSH)
            if port_ssh_relay_avail:
                relayHost = self.relayHost
                relayCredentials = self.relayCredentials
        else:
            relayHost = None
        try:
            ip = socket.gethostbyname(self.host)
            self.logger.write(self.host, 4, "{h} resolved to => {ip}".format(h=self.host,ip=ip))
        except:
            res = False
            self.logger.write(self.host, 2, "Failed to resolve hostname {h}".format(h=self.host))
            return res

        ## Check TCP port availability before start connection initialization
        port_ssh_host_avail = checkConnectivity(self.host, PORT_SSH)
        port_telnet_host_avail = checkConnectivity(self.host, PORT_TELNET)

        if relayHost or port_ssh_host_avail:
            self.logger.write(self.host,4,"ssh port [{ssh_port}] responding".format(ssh_port=PORT_SSH))
            res = ChangeRootPassword([self.host],self.credentials,self.newPassword,pwdComplexityCheck=False,logfile=self.logger.get_logfile(),user=self.user).changePasswordSSH()
            if res:
                #print "Root password changed successfully on {0}".format(self.host)
                self.logger.write(self.host,1,"Password changed")
                return res
#        elif port_telnet_host_avail:
#            #self.logger.write(self.host,2,"ssh port not available")
#            pass
        else:
            self.logger.write(self.host,2,"ssh port [{ssh_port}] not responding".format(ssh_port=PORT_SSH))
            return False ## Can't establish neither ssh and TELNET connection
            ## c - our established connection at this step

class logger():

    def __init__(self,logfile):
        if not logfile:
            logfile = 'root_pass_change.out'
        self.logfile = logfile
        self.lock = thread.allocate_lock()
        self.verbosity_dict = {0: "MAIN",1: "SUCCESS", 2: "FAIL", 3: "INFO", 4: "DEBUG"}

    def write(self,host,verbosity,message,tid=0):
        global LOG_VERBOSITY
        if verbosity <= LOG_VERBOSITY:
            with self.lock as l:
                with open(self.logfile,'aw') as f:
                    f.write('{verb:<9}{host:<15} {message}\n'.format(verb=self.verbosity_dict.get(verbosity), host=host, message=message))

    def get_logfile(self):
        return self.logfile if self.logfile else None


def exclude_filter(host_list,exclude_pattern_list):
    assert isinstance(host_list,list)
    assert isinstance(exclude_pattern_list,list)
    res_host_list = host_list[:]
    for host in host_list:
        for e_pattern in exclude_pattern_list:
            e_pattern = '^%s$' % e_pattern
            m = None
            try: m = re.match(e_pattern,host)
            except: pass
            if m:
                try:
                    res_host_list.remove(host)
                except e,ValueErorr:
                    pass
    return res_host_list

if __name__=="__main__":
    from optparse import OptionParser
    import os.path
    host_list = []
    parser = OptionParser(usage="usage: %prog -f host-file ",
                          version="%prog 1.0")
    parser.add_option("-f", "--host-file",
                      action="store",
                      dest="host_file",
                      default=None,
                      help="Host file, where list of hosts stored. New line is separator.\n")

    parser.add_option("-e","--exclude-hosts",
                        action="store",
                        dest="exclude_hosts",
                        default=None,
                        help="Exclude hosts from specified file and don't process them\n")

    parser.add_option("-o", "--output-file",
                        action="store",
                        dest="output_file",
                        default="root_pass_change.out",
                        help="Log file for script\n"
                        )

    parser.add_option("-u", "--username",
                        action="store",
                        dest="username",
                        default="root",
                        help="Change password for specified user\n"
                        )

    (options, args) = parser.parse_args()
    if options.host_file:
        if os.path.exists(options.host_file):
            with open(options.host_file) as f:
                for line in f:
                    h = re.split('[# ]',line.rstrip())[0]
                    if h:
                        host_list.append(h)
        else:
            print "Specified host '{0}' file doesn't exist ".format(options.host_file)
            sys.exit(1)
    else:
        parser.error("Filename with host list not given!")
        parser.usage()

    if options.exclude_hosts:
        if os.path.exists(options.exclude_hosts):
            exclude_patterns = []
            with open(options.exclude_hosts) as f:
                for line in f:
                    exclude_patterns.append(line.rstrip())
            host_list = exclude_filter(host_list,exclude_patterns)
        else:
            print "Can't open exclude file {}".format(options.exclude_hosts)
            sys.exit(1)
    
    log_file = options.output_file
    credentials = []

    new_password = getpass.getpass("New {user} password: ".format(user=options.username))
    if  new_password:
        r_new_password = getpass.getpass("Repeat new {user} password: ".format(user=options.username))
        if not new_password == r_new_password:
            print "Entered passwords do not match"
            sys.exit(1)
    while True:
        u = raw_input('enter username to login hosts (press <Enter> to complete): ')
        if u:
            p = getpass.getpass("enter password for {0}: ".format(u))
            if not p:
                print "user {} won't be used as password not specified".format(u)
            else:
                p_ = getpass.getpass("repeat password for {0}: ".format(u))
                if p_ == p:
                    credentials.append((u,p))
        else:
            break
    if len(credentials) == 0:
        print "no suitable credentials provided"
        sys.exit(1)

    start_phrase = 'go'
    i = raw_input("Enter '{0}' if you happy to start: ".format(start_phrase))
    if i == start_phrase:
        dt = datetime.datetime.today()
        time_format = "%Y/%m/%d %H:%M"
        time_str = dt.__format__(time_format)
        run_host = socket.gethostname()
        run_user = getpass.getuser()
        if run_user == USER_ROOT: 
            run_user = os.getenv('SUDO_USER') if os.getenv('SUDO_USER') else run_user

        logger(log_file).write(run_host,0,"{change_user} password change started from {host} at {date} by {run_user}".format(change_user=options.username,host=socket.gethostname(),date=time_str,run_user=run_user))
        m = ChangeRootPassword(host_list,credentials,new_password,user=options.username,logfile=log_file)
        m.start()
        print 'Output log written to {0}'.format(log_file)
