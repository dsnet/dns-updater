#!/usr/bin/env python

# Written in 2014 by Joe Tsai <joetsai@digital-static.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain. To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

import re
import os
import sys
import json
import signal
import urllib2
import optparse
import datetime
import traceback
import threading
import paramiko
import pyrax


################################################################################
############################### Global variables ###############################
################################################################################

# Regex patterns
REGEX_ADDR = r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

log_file = None
domains = None
sleep_event = threading.Event()
terminate = False


################################################################################
############################### Helper functions ###############################
################################################################################

def write_log(text):
    """Write text to log file"""
    timestamp = str(datetime.datetime.now())
    for line in text.split('\n'):
        log_file.write("%s  %s\n" % (timestamp, line))
    log_file.flush()


def interrupt_handler(sig_num, frame):
    """Handle system signal interrupts"""
    global terminate
    terminate = True
    sleep_event.set()


def addr_from_router(iface, user, host, passwd = None, key_file = None):
    """Get IP address via SSH on router"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            host, username = user, password = passwd, key_filename = key_file
        )
        stdin, stdout, stderr = ssh.exec_command("ifconfig %s" % iface)
        stdin.close()
        res = re.search("inet addr:(%s)" % REGEX_ADDR, stdout.read())
        return res.groups()[0]
    finally:
        ssh.close()

def addr_from_http(url):
    """Get IP address from external HTTP source"""
    addr = urllib2.urlopen(url).read().strip()
    if not re.match('^%s$' % REGEX_ADDR, addr):
        raise Exception("Did not get IP address back from source!")
    return addr


def upsert_domain(domain, addr):
    """Upsert the IP address for the given domain"""
    dns = pyrax.cloud_dns
    domain, full_domain = '.'.join(domain.split('.')[-2:]), domain
    try:
        rec = dns.find_record(domain, 'A', name = full_domain)
        if rec.data != addr:
            rec.update(data = addr)
            write_log("Update record: %s -> %s" % (full_domain, addr))
    except pyrax.exceptions.DomainRecordNotFound:
        dns.add_record(domain, {'type': 'A', 'name': full_domain, 'data': addr})
        write_log("Insert record: %s -> %s" % (full_domain, addr))


################################################################################
################################# Script start #################################
################################################################################

if __name__ == "__main__":
    # Parse cmdline arguments
    opts_parser = optparse.OptionParser()
    opts_parser.add_option(
        '-l', '--log', default = '-',
        help = "where to write the daemon log file",
    )
    (opts, args) = opts_parser.parse_args()

    # Start log file
    log_file = sys.stdout if opts.log == '-' else open(opts.log, 'a')
    write_log("Start daemon")

    try:
        # Load the configuration file
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        with open('dns_updater.json') as conf_file:
            configs = json.loads(conf_file.read())
        domains = configs['domains']
        poll_delay = configs['poll_delay']

        # Load up pyrax
        pyrax_class = 'pyrax.identity.rax_identity.RaxIdentity'
        cls = pyrax.utils.import_class(pyrax_class)
        pyrax.identity = cls()
        pyrax.set_credentials(configs['api_user'], configs['api_key'])

        # Make address lookup callback
        src_conf = configs['addr_src']
        src_type = src_conf['type']
        if src_type == 'http':
            get_addr = lambda: addr_from_http(src_conf['url'])
        elif src_type == 'ssh-router':
            get_addr = lambda: addr_from_router(
                src_conf['iface'],
                src_conf['user'],
                src_conf['host'],
                passwd = src_conf.get('pass'),
                key_file = src_conf.get('key_file'),
            )
        else:
            raise Exception("Invalid IP address source")
    except:
        write_log(traceback.format_exc().strip())
        write_log("Stop daemon")
        sys.exit(1)

    # Handle signals
    signal.signal(signal.SIGINT, interrupt_handler)
    signal.signal(signal.SIGTERM, interrupt_handler)

    # Main event loop
    while not terminate:
        try:
            addr = get_addr()
            for dom in domains:
                upsert_domain(dom, addr)
        except:
            write_log(traceback.format_exc().strip())

        # Sleep rotation delay
        sleep_event.wait(poll_delay)
        sleep_event.clear()
    write_log("Stop daemon")
