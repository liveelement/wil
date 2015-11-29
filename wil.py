#!/bin/env python

'''
Wild ('who is lazy dog?') script aimed to run simulteneously single/multi-line command on any number of host. Command and host list can be defined in file format or passed as arguments  

It should support multithreading
author: sergii.diachenko@bskyb.com
'''
## prerequisities : pexpect.2.4

## pexpect module should be stored here
import socket, sys, os
sys.path.append(sys.path[0]+os.sep+'lib')
# Import required modules
import getpass,pexpect
import thread,threading,time,Queue as queue
import re

#import Queue


## Global constant variables
NUMCONSUMERS = 20
## To be overwritten with '-t' option, if specified
TIMEOUT = 60
#result = []


## Synchronization instruments
safePrint = thread.allocate_lock()
taskQueue = queue.Queue()

class sshConnection(pexpect.spawn):
    """ Main class for ssh connection """
    port = 22
    RE_PS1 = "[#$>] $"

    def __init__(self,host,username,password,port=None,shell="/bin/ksh",jumpHost=None,jumpCredentials=()):
        ## (self,str,str,str) -> sshConnection
        """Create instance of class sshConnection."""

        ## Assert correct values being passed to init function 
        assert isinstance(host,str)
        assert isinstance(username,str)
        assert isinstance(password,str)
        assert isinstance(shell,str)

        ## spawn new process, without arguments yet
        pexpect.spawn.__init__(self,None)
        self.host = host
        self.jumpHost = jumpHost
        self.jumpCred = jumpCredentials
        self.username = username
        self.password = password

        ## Not used yet
        self.shell = shell
        if not port:
            self.port = sshConnection.port
        else:
            assert isinstance(port,int)
            self.port=port
        def __del__(self):
            pass

    ## TODO: jumpHost connection should be implemented with connectionPool, not with direct connection - it is newbie method, should be fixed 
    def connect(self,timeout=TIMEOUT):
        '''(sshConnection,str,int) -> bool
         Establish ssh connection with remote host'''
    
        expectList = ['(?i)Are you sure you want to continue connecting',   ## Request to add RSA keys
                     '(?i)(password: ?$|Enter passphrase for key)',         ## password
                     sshConnection.RE_PS1,                                  ## PS1 = console
                     pexpect.EOF,                                           ## EOF received
                     pexpect.TIMEOUT]                                       ## timeout occured
        result = False
        try:
            if self.jumpHost:
                ## Check TCP availability of jumps host
                if not checkConnectivity(self.jumpHost,self.port):
                    raise sshException('unable to establish TCP connection {0}:{1}'.format(self.jumpHost,self.port))
                self._spawn('ssh -q {0}@{1}'.format(self.jumpCred[0],self.jumpHost))
                i = self.expect(expectList,timeout=timeout)
                if i == 0:
                    self.sendline('yes')
                    i = self.expect(expectList,timeout=timeout)
                if i == 1:
                    self.sendline(self.jumpCred[1])
                    i = self.expect(expectList,timeout=timeout)
                    if i == 1:
                        self.sendline(self.password)
                        i = self.expect(expectList,timeout=timeout)
                        if i == 1:
                            raise sshException(sshException.PASSWORD_DENIED)
                ## Successfully logged in to jumpHost
                if i == 2:
                    self.sendline('export PS1="[jumpHost $]"')
                    self.sendline('ssh -q {0}@{1}'.format(self.username,self.host))
                if i == 3:
                    raise sshException(sshException.EOF)
                if i == 4:
                    raise sshException(sshException.TIMEOUT)
            else:
                if not checkConnectivity(self.host,self.port):
                    raise sshException('unable to establish TCP connection {0}:{1}'.format(self.host,self.port))
                self._spawn('ssh -q -l {0} {1}'.format(self.username,self.host))
                #self.logfile = file('log.tmp','a')

            ## PASSWORD CHECK START
            i = self.expect(expectList,timeout=timeout)
            if i == 0:
                self.sendline('yes')
                i = self.expect(expectList,timeout=timeout)
            if i == 1:
                self.sendline(self.password)
                i = self.expect(expectList,timeout=timeout)
                if i == 1:
                    self.sendline(self.password)
                    i = self.expect(expectList,timeout=timeout) 
                    if i == 1: 
                        raise sshException(sshException.PASSWORD_DENIED)
            ## Successfully logged in
            if i == 2:
                ## Send 3 enters to ensure console returned 
                success_attempts = 0
                success_treshold = 2
                max_attempts = 3
                for i in range(max_attempts):
                    self.sendline('')
                    i = self.expect(expectList,timeout=timeout)
                    if i == 2:
                        success_attempts += 1
                    else:
                        self.sendcontrol('c')
                if success_attempts >= success_treshold:
                    result = True
                    self.efective_username = self.username
                    return result
                else:
                    raise sshException(sshException.CONSOLE_TEST)
            if i == 3: 
                raise sshException(sshException.EOF)
            if i == 4:
                raise sshException(sshException.TIMEOUT)

            ## PASSWOD CHECK END

            ## TODO: handle if original console returned
#        except sshException, e:
#            with safePrint:
#                print str(e)
#            raise sshException(str(e))
        except Exception,e:
            self.close()
            raise sshException(e)
        finally:
            return result
            
    def setTerminalSettings(self,PS1):
        '''(self,str) -> bool''' 
        ## validate settings

        ## Check if ssh connection established

        ## Set PS1 to predefined value
        pass
  
    def changeUser(self,user,password,sudoFlag=True,pbRunFlag=False):
        ## (str,str,sudoFlag=bool) -> bool
        if not self.isalive():
            raise sshException(sshException.NO_CHILD)
        expectList = [self.RE_PS1,                                                     ## user terminal accessed
                     '(?i)password: $',                                                ## User password request
                     '(?i)sudo password: ',                                            ## sudo authentication request
                     '(?i)is not in the sudoers file',
                     pexpect.TIMEOUT,                                                  ## Timeout
                     pexpect.EOF]                                                      ## EOF

        switch_command = '{0} su - {1}'.format('sudo -p "sudo password: " ' if sudoFlag else '', user)
        self.sendline(switch_command)
        e = self.expect(expectList,timeout=self.timeout)
        res = False

        ## terminal returned
        if e == 0:
            self.effective_username = user
            return True
        ## password request - 1, sudo password request - 2;
        if e == 1 or e == 2:
            p = password if e == 1 else self.password
            self.sendline(p)
            e = self.expect(expectList)
            if e == 0:
                ## Determine current username
                dest_user = self.getUserName()
                if dest_user == user:
                    self.effective_username = user
                    return True
                else:
                    pass
            if e == 1 or e == 2 :
                self.sendcontrol('c')
        if e == 3:
            pass
        if e == 4:
            self.sendcontrol('c')
        if e == 5:
            raise sshException(sshException.EOF)
            return res

    def getUserName(self):
        if not self.isalive():
            raise sshException(sshException.NO_CHILD)
        ## Should be fixed, doesn't work for Solaris 
        command = SimpleCommand('echo $LOGNAME')
        comm,status,exitCode,out = command.execute(self)
        if exitCode == 0:
            return out.rstrip()
        else:
            return None
            
    def getHostname(self):
        if not self.isalive():
            raise sshException(sshException.NO_CHILD)   
        command = SimpleCommand('uname -n')
        comm,status,exitCode,out = command.execute(self)
        if exitCode == 0:
            return out.rstrip()
        else:
            return None    

def checkConnectivity(host,port,timeout=10):
    checkResult = False
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host,port))
        checkResult = True
    except:
        pass
    finally:
        sock.close()
        return checkResult

class sshException(Exception):
    PASSWORD_DENIED = "password denied"
    EOF = "EOF received"
    TIMEOUT = "Timeout occured"
    NO_CHILD = "Child thread process no longer exist"
    CONSOLE_TEST = "Console test after login didn't passed"

    def __init__(self,value):
        self.value = value
    def __str__(self):
        return self.value

class Command():
    """
    Command class
    """
    connectionOriented = True
    cid = 0
    S_COMPLETED = "Completed"
    S_INCOMPLETE = "Incomplete"
    S_EOF = "EOF"
    S_TIMEOUT = "Timeout" 
    def __init__(self,command,timeout=TIMEOUT):
        ## (str,int) -> Command
        self.cid = Command.cid
        Command.cid += 1
        self.command = command
        self.timeout = timeout

    def execute(self,sshConnection):
    ## (self,sshConnection) -> tuple (int,str)
        pass
#  for consum in range(min(NUMCONSUMERS,len(hosts))): 
#    thread.start_new_thread(qconsumer,(consum,taskQueue ))

class SimpleCommand(Command):
    """
    Class definies simple one-line command to be executed on terminal
        command - string shell command represantation
    """
    def __init__(self,command,timeout=TIMEOUT):
        # (str,timeout)
        assert isinstance(command,str)
        Command.__init__(self,command,timeout=timeout)
    
    def __str__(self):
        return self.command

    def execute(self,connection):
        ## (self,pexpect.spawn) -> tuple (str,int,str)
        assert isinstance(connection,sshConnection)
        expectList = ['\r\n[^\n]*[$#] $',   ## PS1
                      '\r\n> $',            ## PS2
                      pexpect.EOF,
                      pexpect.TIMEOUT]
        retrieveExitCode = 'echo $?'
        out_pattern = r'^({command})\r\n({output})'.format(command='[^\n]+',output='.*')  ## PS1\r\m
        status = '' 
        out = ''
        ## check if child process still alive
        if not connection.isalive():
            raise sshException(sshException.NO_CHILD)
        connection.sendline(self.command)
        r = connection.expect(expectList,self.timeout)
        ## gather output 
        try:
            out = re.search(out_pattern,connection.before,flags=re.S).group(2)
        except:
            pass
        ## command completed and terminal returned
        if r == 0:
            ## retrieve exit code
            connection.sendline(retrieveExitCode)
            r = connection.expect(expectList,self.timeout)
            if r == 0: 
                status = Command.S_COMPLETED
                pat = re.compile(r'^(echo \$\?)\r\n(.*)')
                exitCode = int(pat.search(connection.before).groups()[1])
                return (self.command,status,exitCode,out)
        if r == 1:
            status = Command.S_INCOMPLETE
        if r == 2:
            status = Command.S_EOF
        if r == 3:
            status = Command.S_TIMEOUT
        return (self.command,status,None,out)

class MultiLineCommand(Command):
    """Multi-line command execution"""
    def __init__(self,commandList,timeout=TIMEOUT):
        if isinstance(commandList,str):
            commandList = commandList.splitlines()
        elif isinstance(commandList,list):
            pass
        Command.__init__(self,commandList,timeout=timeout)

    def __str__(self):
        return '\n'.join(self.command)

    def execute(self,conn):
        '''Execute command on specified connection '''
        ##(sshConnection) -> list (str,int,str)
        result = []
        for comm in self.command:
            c = SimpleCommand(comm)
            res = c.execute(conn)
            if res[0] != Command.S_INCOMPLETE:
                result.append(res)
        return result

## This section/class under development yet
class wild:
    def __init__(self,hosts,command,credentials,relay=None,relayCred=(),numberThreads=NUMCONSUMERS):
        ## self.username, self.hosts, self.safePrint, self.command, self.jumpHost
        assert isinstance(numberThreads,int)

        self.hosts = hosts
        self.username = credentials[0]
        self.password = credentials[1]
        self.relay = relay
        self.relayCred = relayCred
        self.taskQueue = queue.Queue()
        self.command = command
        self.numberThreads = numberThreads
        self.result = [] 

    def start(self):
        self.exitmutexes = [ thread.allocate_lock() for i in range(len(self.hosts)) ]
        thread.start_new_thread(self.qproducer,(1,))
        for consum in range(min(self.numberThreads,len(self.hosts))): 
            thread.start_new_thread(self.qconsumer,(consum,self.taskQueue))
    
    	## wait till all threads completes it's execution
    	## sleep function inserted to occupy less CPU time
        while not all(mutex.locked() for mutex in self.exitmutexes): time.sleep(0.25)
        return self.result

    def qproducer(self,idnum):
        #global username,hosts,password,safePrint,command,jumpHost
        ## self.username, self.hosts, self.safePrint, self.command, self.jumpHost
        for host in self.hosts:
            if self.command.connectionOriented:
                conn = sshConnection(host,self.username,self.password,jumpHost=self.relay, jumpCredentials=self.relayCred)
            else:
                conn = None
            currentTask = task(conn,self.command, self.exitmutexes)
            self.taskQueue.put(currentTask)
    #		with safePrint:
    #			print 'producer %d put task [%d]' % (idnum,currentTask.id)

    def qconsumer(self,idnum,taskQueue):
        while True:
            time.sleep(0.1)    
            try:
                currentTask = self.taskQueue.get(block=False)
            except:
                pass
            else:
                with safePrint:
                    print 'consumer [{id}] get task [{tid}] for processing {host} '.format(id=idnum, tid=currentTask.id, host=currentTask.connection.host)
                self.result.append(currentTask.start())
                

    ## Result processing section, no more logic overhere
    def print_result(self,format='txt',outfile=None,options=[]):
        ''' options : sep,host,command,com_status, com_exitcode, output '''
        list_options = ['sep','host','conn_state','command','com_status','com_exitcode','output']

        if not self.result:
            safe_print("Result is empty",outfile=outfile)
            return False

        if options:
            print_options = dict((k,False) for k in list_options)
            for o in options:
                if print_options.get(o) != None:
                    print_options[o] = True
        else:
            print_options = dict((k,True) for k in list_options)

        UNIQ_SEP='\n==V7D8ZX1BTOLV6SQX4WLCY2F0338ZSA6R2PVXMFTCW0KCY1WMV50CVNPKDZ3MSUNVVZMC0OUS1RH2HR9XIYWGK08X6ZYV605Z906YOSTJB192G7KT4KA1B0MP'
        for res in self.result: 
            host=res['host']
            connectionState=res['connectionState']
            output=res['output']
            safe_print('{sep}{host} {connectionState}'.format(
                        host='\nHOST: '+str(host) if print_options['host'] else '',
                        connectionState='- <{0}>'.format(connectionState) if print_options['conn_state'] else '' ,
                        sep=UNIQ_SEP if print_options['sep'] else '' ),
                        outfile=outfile
                        )

            unfinished_command_flag = False
            incomplete_command = ''
            for i in range(len(output)):
                command,status,exitCode,out = output[i]
                if not command:
                    continue
                if status == Command.S_INCOMPLETE:
                    unfinished_command_flag = True
                    incomplete_command += '\n\t'+command
                    if i != len(output):
                        continue
                    else:
                        command=incomplete_command
                elif status == Command.S_COMPLETED and unfinished_command_flag:
                    unfinished_command_flag = False
                    command = '{i}\n\t{c}'.format(i=incomplete_command,c=command)
                    incomplete_command = ''
                safe_print("{command}{out}".format(
                        command="\nCOMMAND <{status},{exitCode}>: {com}\n".format(
                            status=status if print_options['com_status'] else '', 
                            exitCode=exitCode if print_options['com_exitcode'] else '',
                            com=command) if print_options['command'] else '',

                        out=out if print_options['output'] else ''),
                            outfile=outfile)

class task:
  tid = 0
  def __init__(self,connection, command, mutexes):
    self.connection = connection
    self.command = command
    self.exitmutexes = mutexes
    self.id = task.tid
    task.tid = task.tid+1
    
  def start(self):
    global result
    connectionState = ''
    out = []
    try:
      if not self.connection:
        res = self.command.execute()
      if self.connection.connect():
        ''' Command output will have following format: 
        ${PS1}${command}\r\n
        ${OUTPUT}\r\n
        ${PS1}
        '''
        self.connection.before = ''
        out = (self.command.execute(self.connection))
        if isinstance(out,tuple): 
            out = [out]
        connectionState = "Success"
      else:
        connectionState = 'Failed'
    except sshException, e:
      connectionState = str(e)
      #print str(e)
#    except pexpect.EOF, e:
#      with safePrint:  print 'Child self exited during execution' 
#    except pexpect.TIMEOUT, e:
#      out = str(e)
    except Exception,e:
      connectionState = str(e)
    finally:
      if self.connection.isalive():
          self.connection.close()
      self.exitmutexes[self.id].acquire()
      res = {'host': self.connection.host, 'output': out, 'connectionState': connectionState}
      return res

def safe_print(message,outfile=None):
    ## Sync lock
    global safePrint
    if not outfile:
        outfile = sys.stdout
        with safePrint:
            outfile.write(str(message)+'\n')
    else:
        with safePrint:
            with open(outfile,'aw') as f:
                f.write(str(message)+'\n')

## execute script in case it was directly invoked, but not imported

###################### MAIN 
if __name__=='__main__':
    mem_prof = False
    if mem_prof:
        from guppy import hpy
        hp = hpy() ## For memory profiling
        hp.setrelheap() ## For memory profiling
    #username = raw_input('username: ')

    ## Parse options
    from optparse import OptionParser
    parser = OptionParser(usage="usage: %prog [options] [command]",
                          version="%prog 1.0")

    parser.add_option("-c", "--command-file",
                      action="store",
                      dest="command_file",
                      default=None,
                      help="Read commands from the specified file.\n Mutually exclusive with command argument")

    parser.add_option("-t", "--timeout",
                      action="store",
                      dest="timeout",
                      default=None,
                      help="Command execution timeout.")

    parser.add_option("-j", "--jump-host",
                      action="store",
                      dest="jump_host",
                      default=None,
                      help="Use jump-host as proxy server. Not used if option ommited")

    parser.add_option("-u", "--username",
                      action="store",
                      dest="username",
                      default=getpass.getuser(),
                      help="Username to connect host. By default currently logged in user")

    parser.add_option("-f", "--host-file",
                      action="store",
                      dest="host_file",
                      default=None,
                      help="Host file, where list of hosts stored. New line is separator.\nMutually exclusive with -l option.\n. '#' and ' ' considered as separators and only 1st fields read")

    ## -h option conflicting with help function
    parser.add_option("-l", "--host-list",
                      action="store",
                      dest="host_list",
                      default=None,
                      help="Host list ':' separated. ")

    parser.add_option("-N", "--num_threads",
                      action="store",
                      dest="num_threads",
                      default=NUMCONSUMERS,
                      help="Number of simulteneous threads. Actual value selected as min(hosts,threads)")

    parser.add_option("-o", "--output_options",
                      action="store",
                      dest="out_options",
                      default=[],
                      help="Coma separated options to be printed after completion. Possible options: sep,host, conn_state, command, com_status, com_exitcode, output")


    parser.add_option("-w", "--write_to_file",
                      action="store",
                      dest="out_file",
                      default=None,
                      help="Write execution output to specific file")

    (options, args) = parser.parse_args()

    hosts = []

    ## read command value, as argument on the first instance, then as option
    if options.timeout:
        timeout=int(options.timeout)
    else:
        timeout=TIMEOUT

    if args:
        command = SimpleCommand(args[0],timeout=timeout)
    elif options.command_file:
        if os.access(options.command_file,os.R_OK):
            command_list = []
            for line in open(options.command_file):
                command_list.append(line.rstrip())
            command = MultiLineCommand(command_list)
        else:
            parser.error("command file {} doesn't exist or not readable".format(options.command_file))
    else:
        parser.error("No command for execution provided!!")
        sys.exit(1)

    if options.host_file:
        if options.host_list:
            parser.error("--host-list option and --host-file options are mutually exclusive")
        else:
            if os.path.exists(options.host_file):
                    with open(options.host_file) as f:
                            for line in f:
                                    h = re.split('[# ]',line.rstrip())[0]
                                    if h:
                                            hosts.append(h)
    elif options.host_list:
        for h in options.host_list.split(":"):
            hosts.append(h)
    else:
        hosts = ['localhost']
        print "No hosts specified, assuming {0}".format(hosts[0])

    out_options = options.out_options.split(',') if options.out_options else []
    jump_host = options.jump_host
    jump_user = raw_input('Enter username [jumphost - {host}]: '.format(host=jump_host)) if jump_host else None
    jump_passwd = getpass.getpass("{user}'s password [jumphost - {host}]: ".format(host=jump_host, user=jump_user)) if jump_host else None

    username = options.username
    password = getpass.getpass("{user}'s pass: ".format(user=username))
    num_threads = int(options.num_threads)

    m = wild(hosts, command, (username,password),relay=jump_host,relayCred=(jump_user,jump_passwd),numberThreads=num_threads)
    m.start()
    m.print_result(outfile=options.out_file,options=out_options)
    # print_options = {'sep': True, 'host': True, 'conn_state': True, 'command': True, 'com_status': True, 'com_exitcode': True,'output': True }

    if options.out_file:
        safe_print("Result output stored to {file}".format(file=options.out_file))
    # def __init__(self,hosts,command,credentials,relay=None):

    if mem_prof:
        h = hp.heap() ## For memory profiling
        print h    ## For memory profiling
