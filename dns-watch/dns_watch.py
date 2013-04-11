#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2013 LMAX Ltd
# author: Radoslaw Madej
# license: GNU GPL 3.0

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


# Depends on LogWatcher.py by Giampaolo Rodolà, available at:
# http://code.activestate.com/recipes/577968-log-watcher-tail-f-log/

# ToDo:
# 1. Detect if no new data has appeared in X seconds
# 2. Make few hardcoded settings as command line options (update interval, user to run as, etc.)
# 3. Once the blacklist has been updated, they should be reloaded automatically
# 4. Remember old matches and don't trigger on the same stuff when run again on same logs

from __future__ import division
import sys
import os
import re
import time
import datetime
import urllib2
import glob
import signal

import smtplib
from email.MIMEText import MIMEText

import optparse
import ConfigParser

import pwd, grp

try:
    import LogWatcher as LogWatcher
except Exception, e:
    print "[E] Error importing LogWatch submodule! See the README... %s : %s" % (Exception, e)
    sys.exit(1)


class MailHandler:
    
    def __init__(self,config):
        
        self.sender = config['from']
        self.rcpt = config['to']
        self.subject = "[dns watch] Match on malicious domain! %s from %s"
        self.smtp = config['server']
        
    def send_notification(self, data, full_data):
        """send an email with stuff... :)"""
         
        #{'date': '18-Feb-2013', 'domain': 'lmax.com', 'client': '192.168.1.1', 'type': 'A', 'time': '12:09:59.198'}
        text = "%s %s\tQuery for %s from %s, query type %s, source: %s" %(data['date'],
                                                       data['time'],
                                                       data['domain'],
                                                       data['client'],
                                                       data['type'],
                                                       full_data)
        msg = MIMEText(text)
        msg['Subject'] = self.subject % ( data['domain'], data['client'] )
        msg['From'] = self.sender
        msg['To'] = self.rcpt
        
        s = smtplib.SMTP(self.smtp)
        s.sendmail(self.sender, [self.rcpt], msg.as_string())
        s.quit()


class ConfigFileParser:                                                                                                                                                                                                          
    """parse config file and put all data in nice dict"""                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                                                                                                                           
    config = None # object of class ConfigParser                                                                                                                                                                                 
    global_settings = {}  # dict to store local system related settings                                                                                                                                                           
                                                                                                                                                                                                                             
                                                                                                                                                                                                                                 
    def __init__(self,file_config):                                                                                                                                                                                               
                                                                                                                                                                                                                         
        self.file_config = file_config                                                                                                                                                                                             
        self.config = ConfigParser.ConfigParser() #handle for parsing from ConfigParser class
        self.key = re.compile("BL.") #all config sections with BL info start with BL.                                                                                                                                     
                                                                                                                                                                                                                                                                                                                                                                                                                                                          
    def readSettings(self):                                                                                                                                                                                              
        """get all settings from config file"""                                                                                                                                                                                  
                                                                                                                                                                                                                                 
        local_settings = {}
        
        self.config.read(self.file_config)
        sections = self.config.sections()
        for section in sections:
            if self.key.match(section):
                name = section.split(".")[1]
                for option in self.config.options(section):                                                                                                                                                                              
                    local_settings[option] = self.config.get(section,option)
                if self.global_settings.has_key('bls'):                                                                                                                                                              
                    self.global_settings['bls'][name] = local_settings
                else:
                    self.global_settings['bls'] = {}
                    self.global_settings['bls'][name] = local_settings
            else:
                for option in self.config.options(section):                                                                                                                                                                              
                    local_settings[option] = self.config.get(section,option)                                                                                                                                                              
                self.global_settings[section] = local_settings
            local_settings = {}                                                                                                                                                                     
                                                                                                                                                                                                                                 
    def returnGlobalSettings(self):                                                                                                                                                                                              
        """return dictionary with all settings """                                                                                                                                                                               
                                                                                                                                                                                                                         
        return self.global_settings                                                                                                                                                                                               
                                                                                                                                                                                                                         
    def returnSectionSettings(self,section):                                                                                                                                                                                     
        """ return settings from given section """                                                                                                                                                                               
                                                                                                                                                                                                                          
        return self.global_settings[section]        


class Timer:
    """multiple classes wants to know current date and time..."""
    
    def __init__(self):
        """empty constructor"""
        
        pass
    
    def getToday(self):
        """return today's date in a proper format to be used for mysql table name"""
        
        return str(datetime.date.today())
    
    def getNow(self):
        """return current time, properly formatted"""
        
        return time.strftime('%H:%M:%S',time.localtime())
    
class UrlFetcher:
    """fetch file from url"""
    
    def __init__(self):
        """constructor"""
        
        self.timer = Timer()

    def get_url(self, url, path):
        """download file"""
        
        try:
            u = urllib2.urlopen(url)
        except HTTPError, e:
            print "[E] Error when trying to download file! %s : %s" % (HTTPError, e)
            return
        t_local = os.stat(path).st_mtime #local timestamp
        headers = u.info()
        t_server = headers.getheader("Last-Modified", 0) 
        if t_server != 0: #getheader should return 0 if header was missing
            try:
                t_server = time.mktime(time.strptime(t_server, "%a, %d %b %Y %H:%M:%S GMT"))
            except Exception, e:
                print "[E] %s %s Couldn't *read* timestamp for %s! Error was: %s %s" % ( self.timer.getToday(),
                                                                                  self.timer.getNow(),
                                                                                   url, Exception, e)
        else:
            print "[E] %s %s Couldn't *get* timestamp for %s! Header was missing? See below:" % ( self.timer.getToday(),
                                                                                  self.timer.getNow(), url)
            print headers
        
        if t_local != t_server: #newer file so let's get it!
            print "[+] %s %s File with a different or no timestamp found on the server, downloading %s..." % (self.timer.getToday(),
                                                                                                        self.timer.getNow(),
                                                                                                        url)
            local_file = open(path, 'w')
            local_file.write(u.read())
            local_file.close()
            
            if t_server != 0: #set the new timestamp to match the server
                os.utime(path, (t_server, t_server))
        else:
            print "[.] %s %s No new files were found at %s, moving on..." % (self.timer.getToday(),
                                                                             self.timer.getNow(),
                                                                             url)    


class BlacklistBase:
    """load blacklists as necessary"""

    def __init__(self, bl):
        """a constructor
           bl - blacklist
           type - url or file? """
        
        self.timer = Timer()
        self.bl = bl['filename']
        self.type = bl['type']
        try:
            self.url = bl['url']
        except:
            self.url = None
        try:
            self.update = bl['update']
        except:
            self.update = False
        self.url_fetcher = UrlFetcher()
    
    def load_blacklist(self):
        """load bl
        
        This assumes one domain per line. If the file is different format, you need to overload this method
        in the child class."""
        
        try:
            f = open(self.bl)
        except IOError, e:
            print "[!] %s %s Error opening %s! A blacklist could have not been loaded... %s: %s" % (self.timer.getToday(),
                                                                                                    self.timer.getNow(),
                                                                                                    self.bl, Exception, e)
            print "[+] %s %s Attempting to download the blacklist..." % (self.timer.getToday(), self.timer.getNow() )
            if self.url != None:
                self.fetch_blacklist_from_url()
            try: #let's try again shall we?
                f = open(self.bl)
            except IOError, e:
                print "[!] %s %s Still couldn't open %s! Check what's going on... %s: %s" % (self.timer.getToday(), 
                                                                                             self.timer.getNow(),
                                                                                             self.bl, Exception, e)
                sys.exit(1)            
        self.entries = f.readlines()
        f.close()
        self._parse_blacklist()
        print "[+] %s %s Loaded %s entries from %s" % (self.timer.getToday(), self.timer.getNow(), len(self.entries), self.bl)
        return self.entries, self.bl
        
    def _parse_blacklist(self):
        """do any magic that needs to be done to have a python list of domains...
        
        Normally this is a NOP, if parsing is needed, this should be overloaded in child class"""
        pass

    def fetch_blacklist_from_url(self):
        """update the blacklist"""
        
        #this below will write to a file so no need to return anything
        if self.url != None:
            self.url_fetcher.get_url(self.url, self.bl)
        
    def update_blacklist(self):
        """fetch new bl and reload it... """
        
        if self.update and self.url == None:
            #it's a file, so just reload it.
            return self.load_blacklist()
        elif self.update and self.url != None: #update only if the config file said so.
            self.url_fetcher.get_url(self.url, self.bl)
            del(self.entries)
            return self.load_blacklist()
        else: #in any other case, just return what you already have.
            return self.entries
        
    def get_blacklist(self):
        """return bl"""
        
        return self.entries
    
    def reload_blacklist(self):
        """reload blacklist from file"""
        
        del(self.entries)
        return self.load_blacklist()


class BL_custom(BlacklistBase):
    """custom blacklist, one domain per line. All lines starting with # and blank lines are stripped."""
    
    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)
        
    def _parse_blacklist(self):
        
        re_hash = re.compile('#')
        tmp = []
        for line in self.entries:
            #skip empty lines and these starting with #
            if not line == '' and not re_hash.match(line):
                tmp.append(line)
        
        #This is not very efficient, we probably should return the results instead
        del(self.entries)
        self.entries = tmp


class BL_malwaredomains(BlacklistBase):
    """load bl from malwaredomains.com.
    
        file - 
        type - file 
        file_url - http://mirror1.malwaredomains.com/files/justdomains
        
        This is simple file, one domain per line, no additional parsing is required."""

    def __init__(self, bl):
        """a constructor"""
        
        BlacklistBase.__init__(self, bl)
    

class BL_someonewhocares(BlacklistBase):
    """http://someonewhocares.org/hosts/"""
    
    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)
        
    def _parse_blacklist(self):
        
        re_loopback = re.compile('127.0.0.1')
        tmp = []
        for line in self.entries:
            if re_loopback.match(line):
                tmp.append( line.split()[1] )
        
        #This is not very efficient
        del(self.entries)
        self.entries = tmp
        

class BL_palevotracker(BlacklistBase):
    """https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist"""

    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)

    def _parse_blacklist(self):
        """it's one domain per line but we need to get rid of the first line which is a comment"""
        
        self.entries = self.entries[1:]
        

class BL_spyeyetracker(BlacklistBase):
    """ spyeyetracker.abuse.ch """

    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)

    def _parse_blacklist(self):
        """it's one domain per line but we need to get rid of the first line which is a comment"""
        
        self.entries = self.entries[6:]


class BL_zeustracker(BlacklistBase):
    """ spyeyetracker.abuse.ch """

    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)

    def _parse_blacklist(self):
        """it's one domain per line but we need to get rid of the first line which is a comment"""
        
        self.entries = self.entries[6:]
        
        
class BL_phishtank(BlacklistBase):
    """http://www.phishtank.com """

    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)
        filters = [r"http://", r"https://", r"\"http://", r"\"https://"]
        self.re_filters = []
        for i in filters:
            self.re_filters.append( re.compile(i) )        

    def _parse_blacklist(self):
        """we're loosing the urls here, which might or might not be relevant..."""
        
        # TODO - needs to filter generic ones, where domain doesn't make sense
        # like t.co or www.google.com
        
        tmp = []
        for entry in self.entries:
            str = ''
            url = entry.split(',')[1]
            if self.re_filters[0].match(url):
                url = url[7:]
            elif self.re_filters[1].match(url):
                url = url[8:]
            elif self.re_filters[2].match(url):
                url = url[8:]
            elif self.re_filters[3].match(url):
                url = url[9:]
            str = url.split('/')[0] # get rid of /whatever_the_url?some_params
            if str not in tmp:    
                tmp.append(str) 
        del(self.entries)
        self.entries = tmp
        

class BlacklistHandler:
    """deal with all bl related stuff, load, query, return, etc..."""
    
    def __init__(self,bls,smtp):
        """a constructor"""
        
        self.timer = Timer()
        self.bl_handlers = {} #handle to all BL_* objects
        self.bls = set() # THE BLACKLIST
        self.bls_full = {} # store additional info about the domains
        self.mailer = MailHandler(smtp)
        signal.signal(signal.SIGHUP, self.reload_blacklists)
        signal.signal(signal.SIGUSR1, self.update_blacklists)
        self.matched = {} #dictionary of all previously matched entries
        #initialize all available blacklist handlers
        for bl in bls.keys():
            try:
                self.bl_handlers[bl] = globals()["BL_"+bl]( bls[bl] )
            except:
                print "[E] %s %s Couldn't fine a handler for %s blacklist! " % (self.timer.getToday(), self.timer.getNow(), bl )
        self._load_bls()
        
    def _load_bls(self):
        """load all bls"""
    
        for bl in self.bl_handlers: #for each handler, call its 'load_blacklist()' method and...
            list, name = self.bl_handlers[bl].load_blacklist()
            self._update_bls_dict( list, bl ) #...feed into our bls dictionary
            
    def _update_bls_dict(self,list, bl_name):
        """take the 'list' and update our blacklist dictionary"""
        
        for i in list:
            item = i.strip()
            if item not in self.bls:
                self.bls.add(item)
                self.bls_full[item] = [bl_name]
            else:
                self.bls_full[item].append(bl_name)
        print "[.] %s %s Finished updating blacklist, now it has %d entries..." % (self.timer.getToday(),
                                                                                   self.timer.getNow(),
                                                                                   len(self.bls) )

    def _delete_data(self):
        """delete blacklist and create empty structures"""

        del(self.bls)
        del(self.bls_full)
        self.bls = set() # THE BLACKLIST
        self.bls_full = {} # store additional info about the domains
        
    def query_bls(self, entry):
        """check if given entry appears on any of our bls"""
        
        if entry['domain'] in self.bls:
            print "\n[!] %s %s Got match on %s! sources: %s" % (self.timer.getToday(), self.timer.getNow(), entry,
                                                              self.bls_full[ entry['domain'] ] )
            #self.seen_before(entry)
            self.mailer.send_notification(entry,self.bls_full[entry['domain']])
            
    def seen_before(self,entry):
        """check if we've got match on that domain before
        
            Stored in dict, domains as keys, with a list for each main on a given domain"""

            #if self.matched.has_key(entry['domain']): #we've already matched on this domain before
            #    if self.matched[entry['domain']]['date'] == entry['date'] and \
            #    self.matched[entry['domain']]['time'] == entry['time']:
            #        pass #we've seen that entry before!
            #    else:
        pass
                    
    def update_blacklists(self, signum = None, frame = None):
        """update all blacklists"""

        print "[!] %s %s Got signal (%s)! Updating blacklists..." % (self.timer.getToday(), 
                                                                                  self.timer.getNow(),
                                                                                  signum)
        self._delete_data()
        for bl in self.bl_handlers: #for each handler, call its 'load_blacklist()' method and...
            list, name = self.bl_handlers[bl].update_blacklist()
            self._update_bls_dict( list, bl ) #...feed into our bls dictionary        
            
    def reload_blacklists(self, signum, frame):
        """reload all blacklists"""
        
        print "[!] %s %s Got signal (%s)! Reloading blacklists..." % (self.timer.getToday(), 
                                                                                  self.timer.getNow(),
                                                                                  signum)
        self._delete_data()
        for bl in self.bl_handlers: #for each handler, call its 'load_blacklist()' method and...
            list, name = self.bl_handlers[bl].reload_blacklist()
            self._update_bls_dict( list, bl ) #...feed into our bls dictionary 
             

class Stats:
    """let's do some stats, shall we?"""
    
    def __init__(self):
        
        pass
    
    def do_stats(self):
        """call this method to get all stats done"""
        
        pass
    
class LogHandler:
    """parse old logs"""
    
    def __init__(self,path,logfile):
        """a constructor
        
            We expect the logs to be in query.log.[0-10] format"""
        
        self.path = path
        self.logfile = logfile
        
    def _list_logs_files(self):
        """get a list of old logs that we need to parse"""
        
        return glob.glob(self.path+'/'+self.logfile+'.*')
        
    def get_old_logs(self):
        """go through old logs"""
        
        logs = self._list_logs_files()
        return logs
                

class QueryFilter:
    """filter stuff we don't care about"""

    def __init__(self,f_filters):
        """a constructor"""

        #load list of filtered domains
        self.filters = open(f_filters).readlines()
        self.timer = Timer()
        self._compile_filters()

    def _compile_filters(self):
        """create a list of compiled RegExp filters to speed up matching"""
        
        self.re_filters = []
        for entry in self.filters:
            print "[+] %s %s Compiling filter for %s..." % (self.timer.getToday(), self.timer.getNow(), entry[:-1] )
            self.re_filters.append( re.compile(entry.strip() ) )    

    def filter_query(self, query):
        """do we need to filter the query?"""

        for re_entry in self.re_filters:
            try:
                if query["domain"] != None and re_entry.search(query["domain"]):
                    return None
            except:
                print "[E] %s %s error occured when filtering a line! See below..." % (self.timer.getToday(), self.timer.getNow())
                print query
                sys.exit(1)
        return query

class EntryHandler:
    """deals with new entry in the logs"""

    def __init__(self, opts):
        """a constructor"""

        self.log_path = opts['general']['log_path']
        self.log_file = opts['general']['log_file']
        self.bind = BindParser()
        self.filter = QueryFilter(opts['general']['f_filters'])
        self.bls = BlacklistHandler(opts['bls'],opts['smtp'])
        self.log = LogHandler(opts['general']['log_path'],opts['general']['log_file'])
        self.stats = Stats()
        self.stat_counter = 0
        self.stat_threshold = 100000 # after how many individual queries do we update our stats?
        self.update_frq = 86400 # how often do we check for updates of blacklists? (86400s = 24h)
        self.timer = Timer()
        self.start_time = time.time()
        signal.signal(signal.SIGUSR2, self.sigusr2_handler)
        
    def sigusr2_handler(self, num, frame):
        """handle sigusr2! :)"""
        
        print "[!] %s %s Got signal! (%s) Going through old logs..." % (self.timer.getToday(), self.timer.getNow(), num)
        self.handle_old_logs()
        
    def handle_old_logs(self):
        """go through old logs"""
        
        logs = self.log.get_old_logs()
        for log in logs:
            data = set( line.strip() for line in open(log) )
            q = len(data)
            i = 0
            print "[+] %s %s processing %s (%s entries)" % (self.timer.getToday(), self.timer.getNow(), log, q)
            for line in data:
                p = self.filter.filter_query( self.bind.parse_line(line) )
                if p:
                    self.bls.query_bls(p)
                i += 1
                #the below is nice but pollutes logs badly
                #sys.stdout.write("\r[.] processing...%.2f%% done" % float( int(i) / int(q) * 100 ) )
            print "[*] %s %s completed processing %s." % (self.timer.getToday(), self.timer.getNow(), log)
        del(data) #we no longer care about the old data

    def handler(self,filename, lines):
        """call me when new line(s) is available"""
        
        if filename == self.log_path+'/'+self.log_file:
            for line in lines:
                self.stat_counter +=1
                p = self.filter.filter_query( self.bind.parse_line(line) ) #filter out the internal stuff
                if p: #there is something to check
                    self.bls.query_bls(p) #query our blacklists
                if self.stat_counter == self.stat_threshold:
                    #print "[+] %s %s queries processed, time for some stats..." % (self.timer.getNow(), self.stat_threshold )
                    self.stats.do_stats()
                    self.stat_counter = 0
        elapsed = time.time() - self.start_time 
        if elapsed > self.update_frq:
            print "[+] %s %s It's been %s since the last update, updating blacklists..." % (self.timer.getToday(),
                                                                                            self.timer.getNow(), elapsed)
            self.bls.update_blacklists()
            self.start_time = time.time()

class Monitor:
    """main class"""

    def __init__(self, opts):
        """a constructor"""

        self.eh = EntryHandler(opts)
        self.log_path = opts['general']['log_path']
        self.watcher = LogWatcher.LogWatcher(opts['general']['log_path'], self.eh.handler)
        self.timer = Timer()
        self.old_logs = opts['general']['old_logs']
        
    def daemonise(self):
        """ daemonise itself - code taken from Luke """
        
    try:
        pid = os.fork()
    #exit parent of first fork
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write('[E] %s %s Failed to fork when daemonising myself: %d (%s)\n' % (self.timer.getToday(),
                                                                                          self.timer.getNow(),
                                                                                          e.errno, e.strerror))
        sys.exit(1)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        #exit parent of second fork
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write('[E] %s %s Failed to fork when daemonising myself: %d (%s)\n' % (self.timer.getToday(),
                                                                                          self.timer.getNow(),
                                                                                          e.errno, e.strerror))
        sys.exit(1)       

    def go(self):
        """main method
        
            1. Load blacklists
            2. Parse old files
            3. Add current log file for monitoring
            4. Loop 3."""
            
        if int(self.old_logs) == 1:
            print self.old_logs
            self.eh.handle_old_logs()
        self.daemonise()
        print "[+] %s %s ...moving onto monitoring live data..." % (self.timer.getToday(), self.timer.getNow() )
        #This is rather irrelevant now, as we daemonise itself by default.
        try:
            self.watcher.loop()
        except (KeyboardInterrupt, SystemExit): # CTRL + C
            print "[!] %s Ctrl + c pressed, finishing..." % self.timer.getNow(),
            print " shutdown completed!\n"
            sys.stdout.flush()
            sys.exit(0)        
        

class BindParser:
    """parse bind9 query logs, return a pair of (domain, ips) or (ip, domain)"""

    def __init__(self):
        """a constructor"""
        pass

    def parse_line(self,line):
        """parse a given line and returned a dict of stuff..."""

        dict = {}
        split = line.split()
        try:    
            dict["date"] = split[0]
        except:
            dict["date"] = None

        try:
            dict["time"] = split[1]
        except:
            dict["time"] = None

        try:
            dict["client"] = split[5].split("#")[0]
        except:
            dict["client"] = None

        try:
            dict["domain"] = split[9]
        except:
            dict["domain"] = None

        try:
            dict["type"] = split[11]
        except:
            dict["type"] = None

        return dict
 

if __name__ == "__main__":

    timer= Timer()
    #first let's drop privileges, shall we?
    if os.getuid() == 0:
        try:
            running_uid = pwd.getpwnam('named').pw_uid
            running_gid = grp.getgrnam('named').gr_gid
            os.setgroups([])
            os.setgid(running_gid)
            os.setuid(running_uid)
        except Exception, e:
            print "[!] %s %s Error dropping privileges! %s : %s" % (timer.getToday(),
                                                                    timer.getNow(),Exception, e)
    
    p = optparse.OptionParser(description='Monitor DNS server logs for queries to malicious domains.',
                                prog='dns_watch',
                                version='0.1',
                                usage= '%prog -c config_file [-v --verbose]')
    p.add_option('--verbose', '-v',  action="store_true", help="print extra info")
    p.add_option('--config', '-c',  action="store", default = None, help="use configuration file")
    
    options, arguments = p.parse_args()

    if options.config == None:
        print "[E] No config file provided! What am I supposed to do?!?"
        sys.exit(1)
    
    #print "[+] %s Parsing config file..." % timer.getNow()
    config = ConfigFileParser(options.config)
    config.readSettings()
    config_opts = config.returnGlobalSettings()

    if config_opts['general'].has_key('outfile'):
        try:
            sys.stdout = open(config_opts['general']['outfile'], 'a', 0)
            print "[+] %s %s Log opened, ready for some action..."  % (timer.getToday(), timer.getNow())
        except Exception, e:
            print "[E] %s Error opening the log file! %s : %s" % (timer.getNow(), Exception, e)
            sys.exit(1)
    else:
        print "[W] %s No logfile specified! ('outfile') Output will not be logged." % timer.getNow()
    print "[+] %s %s Starting monitoring..." % (timer.getToday(), timer.getNow() )
    
    if os.path.isfile(config_opts['general']['pid']):
        print 'PID file found! Are you sure that the process isn\'t running? Remove the pid file then...'
        sys.exit(1)
    else:
        f = open(config_opts['general']['pid'], 'w')
        f.write(str(os.getpid()))
        f.flush()
        f.close()        
    sys.stdout.flush()
    monitor = Monitor(config_opts)
    monitor.go()



