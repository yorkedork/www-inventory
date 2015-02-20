#!/usr/bin/env python3
import json
import re
import os
import stat
import subprocess
import tempfile
import getpass
import xml.etree.ElementTree as ET
import socket
from collections import defaultdict
from multiprocessing import Pool
from jinja2 import Template


def download_vhosts(ip, vhost_dir, user):
    """
    Create a directory in `vhost_dir`, with a name corresponding to the `IP` we're
    looking at. rsync into the box, and download all the files in
    /etc/httpd/vhost.d
    """
    sub_dir = os.path.join(vhost_dir, ip)
    os.mkdir(sub_dir)
    subprocess.call([
        "rsync",
        "--recursive",
        "--rsh", "ssh -o stricthostkeychecking=no -o userknownhostsfile=/dev/null -o batchmode=yes -o passwordauthentication=no", 
        "--timeout=3",
        user + "@" + ip + ":/etc/httpd/vhost.d/*",
        sub_dir
    ])


def is_matching_server_name(name, ip):
    """
    Return True if the domain name `name` resolves to the `ip`
    """
    # replace *.example.com with foo.example.com since *.example.com is not
    # something you can get a hostname for
    if name.startswith("*"):
        name = "foo" + name[1:]

    try:
        return socket.gethostbyname(name) == ip
    except socket.gaierror:
        return False


def no_other_permissions(dir):
    """
    Returns true if dir has no permissions for other
    """
    # for whatever reason, the correct permissions aren't returned unless there
    # is a slash at the end of the name. This is an issue because of NFS. 
    if not dir.endswith("/"):
        dir += "/"
    try:
        stat_info = os.stat(dir)
        return (stat_info.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)) == 0
    except OSError:
        return False


def is_on_safe_vm(ip):
    """
    inert.rc.pdx.edu is a VM with no scripting or .htaccess enabled so sites
    here should be safe even if their /vol/www/<dir> is readable by others
    """
    return ip == "131.252.43.92"


def has_no_other_writable_files_or_dirs(dir):
    """
    Check to see if dir has any files or dirs writable by others
    """
    stdout = tempfile.TemporaryFile()
    subprocess.call([
    "find", 
    dir,
    "-perm", "/o+w",
    "-and",
    "-type", "f", 
    "-or",
    "-perm", "/o+w",
    "-and",
    "-type", "d",
    "-print", 
    "-quit"], stdout=stdout)
    stdout.seek(0)
    return len(stdout.read().strip()) == 0


if __name__ == "__main__":
    stdout = tempfile.TemporaryFile()
    # use nmap to scan all the boxes that respond on port 80
    subprocess.call(['nmap', '-PS', '-p80', '-oX', '-', '131.252.43,42,110.1-255'], stdout=stdout)
    stdout.seek(0)
    # using the XML output of nmap, create a dict where the key is an IP, and the value is the name from the PTR record
    xml_tree = ET.fromstring(stdout.read())
    ips = dict((host.find("address").attrib['addr'], (getattr(host.find("./hostnames/hostname[@type='PTR']"), 'attrib', {'name': None})['name']))  for host in xml_tree.findall("./host"))

    # the temp dir to write vhost files to
    vhost_dir = tempfile.mkdtemp()
    # the user to SSH into other boxes as
    user = getpass.getuser()
    # download all the vhosts in parallel, since it's really slow otherwise
    pool = Pool(16)
    args = [(ip, vhost_dir, user) for ip in ips.keys()]
    pool.starmap(download_vhosts, args)

    # just a helper to build a path relative to vhost_dir
    build_full_path = lambda *args: os.path.normpath(os.path.join(vhost_dir, *args))
    # we save all the information into a big old complicated deeply nested dict
    all_data = {}
    # keep track of all the /vol/www/ directories we see so we can figure out
    # which ones are used
    all_dirs = set()
    # for each IP address we found, we store the reverse (i.e. the PTR
    # record), and a list of vhosts files that are located on that machine
    for ip in os.listdir(vhost_dir):
        all_data[ip] = {}
        all_data[ip]['reverse'] = ips[ip]
        all_data[ip]["vhosts"] = []

        # for each vhost file that was downloaded...
        for vhost_file in os.listdir(build_full_path(ip)):
            # we don't care about non-.conf files
            if not vhost_file.endswith(".conf"):
                continue

            data = {}
            data['name'] = vhost_file

            contents = open(build_full_path(ip, vhost_file)).read()
            # find all the ServerName and ServerAlias
            names = set(match[1] for match in re.findall(r"(servername|serveralias)\s+(?P<name>.*)", contents, re.I))
            data['names'] = []
            for name in names:
                data['names'].append({
                    "value": name,
                    "is_valid": is_matching_server_name(name, ip)
                })

            # find all the references to /vol/www/<something>/
            dirs = set(match for match in re.findall(r"(/vol/www/.+?)(?:/|\s+)", contents, re.I))
            data['dirs'] = []
            for dir in dirs:
                all_dirs.add(dir)
                data['dirs'].append({
                    "value": dir, 
                    "good_permissions": no_other_permissions(dir) or (is_on_safe_vm(ip) and has_no_other_writable_files_or_dirs(dir))
                })

            if "WSGIScriptAlias" in contents:
                data['wsgi'] = True

            all_data[ip]['vhosts'].append(data)

    #print(json.dumps(all_data))
    # generate our fancy HTML report
    t = Template(open("template.html").read())
    # find all dirs that aren't being used
    dirs = set("/vol/www/" + dir for dir in os.listdir("/vol/www") if not dir.startswith("."))
    unused_dirs = dirs - all_dirs
    print(t.render(data=all_data, unused_dirs=unused_dirs))
