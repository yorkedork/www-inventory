# www-inventory

This program scans an IP range looking for machines that respond on port 80. It then copies all the files from that machine's /etc/httpd/vhost.d and parses out useful information. It outputs a pretty HTML page.

It is assumed you can use SSH keys to access each box.

# Install

make install

# Run

make
