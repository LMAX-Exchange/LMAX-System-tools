dns-watch
=========

A tool written in python that continuously monitors DNS server logs, and sends out email alerts when a query to a known malicious domain is found. If you see a lot of such queries on your network, it's quite likely that something went terribly wrong... ;)

Maintainer
==========

[Radoslaw Madej](https://github.com/radegand)


Features
========

- supports BIND log format. Support for other log formats is planned in the future
- email notifications
- ability to ignore certain domains
- blacklists auto-updating
- custom file based list
- runs as a daemon by default
- at the moment, out of the box it can read and parse the following blacklists:
  * Malware Domains (http://malwaredomains.com)
  * Palevo Tracker (https://palevotracker.abuse.ch/)
  * SpyEye Tracker (https://spyeyetracker.abuse.ch/)
  * Zeus Tracker (https://zeustracker.abuse.ch/)
- easily expandable to support new blacklists
- sending commands via signals


License
=======

dns-watch is released under GPL 3.0.

Dependencies
============

- Python :) Tested with python 2.4 - 2.7
- LogWatch.py by Giampaolo Rodolà available at http://code.activestate.com/recipes/577968-log-watcher-tail-f-log/


Installation instructions
=========================

1. Check out the project.
2. Edit the dns_watch.conf file. All options should be fairly self-explanatory. Make sure that all the paths are correct, especially these pointing to your BIND logs. Set SMTP settings to receive email notifications.
3. The default blacklist URLs should work just fine. Check the term of use for each blacklist (ie,allowed frequency of updates, etc.) and if possible, consider a donation to support them.
4. If you have any specific domains you want to watch for, put them one domain per line in a file, and use the BL.custom section to make dns-watch use it.
5. Edit filters.txt - put there any domains you don't care about (quite possibly all your internal domains).
6. Run the script manually (it will daemonise itself to run in the background automatically) or better, use the init script provided in ./scripts.

Running it manually:
<pre>
python dns_watch.py -c dns_watch.conf
</pre>

Or copy the dns_watch script to /etc/init.d and simply run:
<pre>
/etc/init.d/dns_watch restart
</pre>
7. Done! Now wait for email notifications... :) You can check the log file to see that it actually is doing something:
<pre>
[+] 2013-04-10 10:17:42 Log opened, ready for some action...
[+] 2013-04-10 10:17:42 Starting monitoring...
[+] 2013-04-10 10:17:42 Compiling filter for internal1.domain...
[+] 2013-04-10 10:17:42 Compiling filter for internal2.domain...
[+] 2013-04-10 10:17:42 Loaded 13897 entries from /opt/dns_watch/etc/bls/malwaredomains.com
[.] 2013-04-10 10:17:42 Finished updating blacklist, now it has 13897 entries...
[+] 2013-04-10 10:17:42 Loaded 716 entries from /opt/dns_watch/etc/bls/zeustracker.abuse.ch
[.] 2013-04-10 10:17:42 Finished updating blacklist, now it has 14328 entries...
[+] 2013-04-10 10:17:42 Loaded 54 entries from /opt/dns_watch/etc/bls/palevotracker.abuse.ch
[.] 2013-04-10 10:17:42 Finished updating blacklist, now it has 14382 entries...
[+] 2013-04-10 10:17:42 Loaded 145 entries from /opt/dns_watch/etc/bls/spyeyetracker.abuse.ch
[.] 2013-04-10 10:17:42 Finished updating blacklist, now it has 14447 entries...
[+] 2013-04-10 10:17:42 Loaded 2078 entries from /opt/dns_watch/etc/bls/lmax
[.] 2013-04-10 10:17:42 Finished updating blacklist, now it has 16424 entries...
watching logfile /var/named/chroot/var/log/query.log
watching logfile /var/named/chroot/var/log/named.log
[+] 2013-04-10 10:17:42 ...moving onto monitoring live data...
</pre>

Example when a match is found: (will also be sent as an email)
<code>
[!] 2013-04-09 13:39:10 Got match on {'date': '09-Apr-2013', 'domain': 'verymaliciousdomain.blah', 'client': '192.168.1.1', 'type': 'NS', 'time': '
13:39:09.968'}! sources: ['malwaredomains']
</code>

Currently dns-watch accepts three signals, which can be use to send different commands:

- HUP - reload blacklists
- USR1 - update blacklists
- USR2 - parse old logs

Reload blacklists
-----------------
Scenario - you have updated your file containing customised domains your are interested in monitoring and you want the script to use the new data. Simply send it the HUP signal, and it will reload *all* of its configured blacklists files.
<pre>
kill -HUP <dns_watch_PID>
</pre>
In the logs you should see:
<pre>
[!] 2013-04-10 12:48:36 Got signal (1)! Reloading blacklists...
[+] 2013-04-10 12:48:36 Loaded 17484 entries from /opt/dns_watch/etc/bls/malwaredomains.com
[.] 2013-04-10 12:48:37 Finished updating blacklist, now it has 17484 entries...
[+] 2013-04-10 12:48:37 Loaded 746 entries from /opt/dns_watch/etc/bls/zeustracker.abuse.ch
[.] 2013-04-10 12:48:37 Finished updating blacklist, now it has 17948 entries...
[+] 2013-04-10 12:48:37 Loaded 51 entries from /opt/dns_watch/etc/bls/palevotracker.abuse.ch
[.] 2013-04-10 12:48:37 Finished updating blacklist, now it has 17999 entries...
[+] 2013-04-10 12:48:37 Loaded 143 entries from /opt/dns_watch/etc/bls/spyeyetracker.abuse.ch
[.] 2013-04-10 12:48:37 Finished updating blacklist, now it has 18063 entries...
[+] 2013-04-10 12:48:37 Loaded 2078 entries from /opt/dns_watch/etc/bls/lmax
[.] 2013-04-10 12:48:37 Finished updating blacklist, now it has 20040 entries...
</pre>

Update blacklists
-----------------
By default, if a blacklist is set to auto-update, the tool will connect every 24 hours to a server, and based on the 'Last-Modified' headers (or lack of them), it will download and reload the newest version of the blacklists.

If for whatever reason, you want the trigger the update manually, just send the USR1 signal:
<pre>
kill -USR1 <dns_watch_PID>
</pre>
In the logs you should see something like this:
<pre>
[!] 2013-04-10 12:56:37 Got signal (10) frame: <frame object at 0x9a85e0c>! Updating blacklists...
[.] 2013-04-10 12:56:38 No new files were found at http://mirror1.malwaredomains.com/files/justdomains, moving on...
[+] 2013-04-10 12:56:38 Loaded 17484 entries from /opt/dns_watch/etc/bls/malwaredomains.com
[.] 2013-04-10 12:56:38 Finished updating blacklist, now it has 17484 entries...
[.] 2013-04-10 12:56:39 No new files were found at http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist, moving on...
[+] 2013-04-10 12:56:39 Loaded 746 entries from /opt/dns_watch/etc/bls/zeustracker.abuse.ch
[.] 2013-04-10 12:56:39 Finished updating blacklist, now it has 17948 entries...
[E] 2013-04-10 12:56:39 Couldn't *get* timestamp for https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist! Header was missing? See below:
Date: Wed, 10 Apr 2013 12:56:39 GMT
Server: Apache/2
X-Powered-By: PHP/5.3.3-7+squeeze15
Content-Disposition: filename=palevoblocklist.txt
Connection: close
Transfer-Encoding: chunked
Content-Type: text/plain

[+] 2013-04-10 12:56:39 File with a different or no timestamp found on the server, downloading https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist...
[+] 2013-04-10 12:56:39 Loaded 51 entries from /opt/dns_watch/etc/bls/palevotracker.abuse.ch
[.] 2013-04-10 12:56:39 Finished updating blacklist, now it has 17999 entries...
[.] 2013-04-10 12:56:41 No new files were found at https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist, moving on...
[+] 2013-04-10 12:56:41 Loaded 143 entries from /opt/dns_watch/etc/bls/spyeyetracker.abuse.ch
[.] 2013-04-10 12:56:41 Finished updating blacklist, now it has 18063 entries...
[+] 2013-04-10 12:56:41 Loaded 2078 entries from /opt/dns_watch/etc/bls/lmax
[.] 2013-04-10 12:56:41 Finished updating blacklist, now it has 20040 entries...
</pre>
You don't need to reload blacklists once they were updated. This is done automatically.

Parse old logs
--------------
By default dns-watch monitors only the current log file (for instance 'query.log'), but you can also make it parse all old files during startup by setting the 'old_logs' options to 1. But what if you've just updated your blacklists and you want to check if none of the newly added domains appear in your old logs? This is exactly what signal USR2 is for - when send to the program, it will cause it to read all log files (query.log.*) and report on any matches with its current set of blacklists:
<pre>
kill -USR1 <dns_watch_PID>
</pre>
In the logs you should see:
<pre>
[!] 2013-04-10 12:32:39 Got signal! (12) Going through old logs...
</pre>


Using additional blacklists
===========================

If you only have a handful of additional domains that you want to monitor, and that list is rather static, you can simply put all of them in a file and use the BL.custom option to use it.

If you want to use another blacklists available online, you need to create another entry in the config file, for instance:
<pre>
[BL.myonlineblacklist]
filename=/opt/dns_watch/etc/bls/myblacklist.txt
type=file
url=https://somedomain.com/mybls.txt
update=1
</pre>
The section name must start with 'BL.'. The only type currently supported is 'file'.

If your blacklists contains only a list of domains, one domain per line, and no other data such as comments, etc., you don't need to do anything else. Just restart the script, and it will automatically read and load your new BL. entry.

If however the blacklist contains any additional data, you need to write a parsing method that will return a list of domains. Here's how to do it:

1. Create new class that inherits from BlacklistBase called BL_myonlineblacklist (name must start with BL_ and the name should match the name you've given it in the config file).
2. Create a constructor that will call the parent class constructor.
3. Implement a self._parse_blacklist() method. This method doesn't take any arguments, your raw data is available in self.entries list which is also where your parser needs to store the cleared domain list. Don't return anything.

For example, look at the BL_zeustracker class:
<pre>
class BL_zeustracker(BlacklistBase):
    """ spyeyetracker.abuse.ch """

    def __init__(self, bl):
        
        BlacklistBase.__init__(self, bl)

    def _parse_blacklist(self):
        """it's one domain per line but we need to get rid of the first line which is a comment"""
        
        self.entries = self.entries[6:]
</pre>

If you need to do any additional parsing or stripping, just work directly on and modify the self.entries list.

Contact information
===================

Feel free to contact me at radegand _at_ o2 dot pl

Feedback, comments, suggestions appreciated!

Credits
=======

It uses a 'Log watcher' recipe written by Giampaolo Rodolà and available at: http://code.activestate.com/recipes/577968-log-watcher-tail-f-log/
