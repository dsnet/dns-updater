# Rackspace Dynamic DNS Updater #

## Introduction ##

Simple dynamic IP address updater for Rackspace DNS. This implementation allows
for the external address to be acquired from either asking a third-party server
or by querying the local router directly. It was deemed slightly more secure to
query a local router because a third-party server could be un-truthful or the
HTTP message could be intercepted and altered.


## Configuration ##

The JSON file contains the configuration parameters for the daemon. Most of the
entries are fairly self-explanatory. In specific, the 'domains' field is a list
of A records for domains and sub-domains to update.

This updater daemon can acquire the external IP address through two ways. The
simplest way is to acquire the IP address by asking an external server via HTTP.
The requirements are that the server replies back with just the address as the
body contents. This acquisition method can be set by the following:
```python
"addr_src": {
    "type": "http",
    "url": "http://ipv4.dndy.me"
}
```

Alternatively, the daemon can acquire the address by SSH-ing into the local
router and then running ```ifconfig $IFACE``` to acquire the external address
directly. This method can be used set by the following:
```python
"addr_src": {
    "type": "ssh-router",
    "iface": "vlan2",
    "user": "root",
    "host": "dd-wrt",
    "pass": "password",
    "key_file": "id_rsa"
}
```

The 'iface' parameter is the interface that the router uses to acquire its
external IP address. In my case, this was 'vlan2'. The 'user' and 'host' fields
are as one would expect for SSH. In order for SSH to work, either 'pass' or
'key_file' must be supplied. If a key file is specified, the path must be
relative to the location of daemon source directory.


## Files ##

* **dns_updater.py**: DNS update daemon
* **dns_updater.json**: Configuration settings for dns_updater
* **dns_updater**: Init.d script to start the dns_updater daemon


## Installation ##

```bash
# Be root to install
su

# Download the archive
SRC_VERSION=tip
curl http://code.digital-static.net/dns-updater/get/$SRC_VERSION.tar.gz | tar -zxv

# Move local copy
SRC_ROOT=/usr/local/dns_updater
mv *-dns-updater-* $SRC_ROOT

# Update configuration file
nano $SRC_ROOT/dns_updater.json
chown root:root $SRC_ROOT/dns_updater.json
chmod go-rwx $SRC_ROOT/dns_updater.json

# Setup the daemon service
ln -s $SRC_ROOT/dns_updater /etc/init.d/dns-updater
update-rc.d dns-updater defaults
service dns-updater start
```