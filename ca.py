#!/usr/bin/env python
#
# CA.py - wrapper around ca to make it easier to use ... basically ca requires
#      some setup stuff to be done before you can use it and this makes
#      things easier between now and when Eric is convinced to fix it :-)
#
# CA.py -newca ... will setup the right stuff
# CA.py -newreq[-nodes] ... will generate a certificate request
# CA.py -sign ... will sign the generated request and output
#
# At the end of that grab newreq.pem and newcert.pem (one has the key
# and the other the certificate) and cat them together and that is what
# you want/need ... I'll make even this a little cleaner later.
#
#
# 27-Dec-2016 jhlee    Original hacking(From CA.pl)
#
# Ji-Ho Lee
# search5@gmail.com
#

# default openssl.cnf file has setup as per the following
# demoCA ... where everything is stored
from optparse import OptionParser, Option
import sys
import os
import re
import subprocess
import shlex

openssl_cmd = "openssl"
if "OPENSSL" in os.environ:
    openssl_cmd = "openssl"
else:
    os.environ["OPENSSL"] = openssl_cmd

SSLEAY_CONFIG = os.environ.get("SSLEAY_CONFIG", "")

# 5 year
DAYS = "-days 1825"
# 10 years
CADAYS = "-days 3650"
REQ = "%s req %s" % (openssl_cmd, SSLEAY_CONFIG)
CA = "%s ca %s" % (openssl_cmd, SSLEAY_CONFIG)
VERIFY = "%s verify" % openssl_cmd
X509 = "%s x509" % openssl_cmd
PKCS12 = "%s pkcs12" % openssl_cmd

CATOP = "/etc/ssl/ca"
CAKEY = "cakey.pem"
CAREQ = "careq.pem"
CACERT = "cacert.pem"


def ca_helper():
    help_usage = "usage: %prog --signcert certfile keyfile|--newcert|--newreq|--newreq-nodes|--newca|--sign|--verify"

    parser = OptionParser(usage=help_usage)
    parser.add_option("--signcert", type="string", nargs=2, dest="signcert",
                      help="Certification Sign", action="callback", callback=signcert, metavar="certfile keyfile")
    parser.add_option("--newcert", help="New Certification", action="callback", callback=newcert)
    parser.add_option("--newreq", help="New Certification CSR", action="callback", callback=newreq)
    parser.add_option("--newreq-nodes", help="New Certification Nodes", action="callback", callback=newreq_nodes)
    parser.add_option("--pkcs12", help="PKCS12", type="string", nargs=1, metavar="Certification Name",
                      action="callback", callback=pkcs12)
    parser.add_option("--xsign", help="Certification xsign", action="callback", callback=xsign)
    parser.add_option("--sign", "--signreq", help="Certification sign", action="callback", callback=sign)
    parser.add_option("--signCA", help="CA sign", action="callback", callback=signCA)
    parser.add_option("--verify", help="Certification Verify", action="callback", callback=verify, type="string")

    (options, args) = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(2)

    return


def newca(option, opt_str, value, parser, *args, **kwargs):
    # if explicitly asked for or it doesn't exist then setup the
    # directory structure that Eric likes to manage things

    NEW = "1"
    if NEW or (not os.path.exists(os.path.join(CATOP, "serial"))):
        # create the directory hierarchy
        os.mkdir(CATOP)
        print(CATOP)
        os.mkdir(os.path.join(CATOP, "certs"))
        os.mkdir(os.path.join(CATOP, "crl"))
        os.mkdir(os.path.join(CATOP, "newcerts"))
        os.mkdir(os.path.join(CATOP, "private"))

        open(os.path.join(CATOP, "index.txt"), "w").write("")
        open(os.path.join(CATOP, "crlnumber"), "w").write("01\n")

    if not os.path.join(CATOP, "private", CAKEY):
        tmp_file = input("CA certificate filename (or enter to create) ")
        tmp_file = tmp_file.rstrip()

        # ask user for existing CA certificate
        if os.path.join(tmp_file):
            cp_pem(tmp_file, os.path.join(CATOP, CACERT), "CERTIFICATE")
            cp_pem(tmp_file, os.path.join(CATOP, "private", CAKEY), "PRIVATE")
        else:
            print("Making CA certificate ...")
            keyout_path = os.path.join(CATOP, "private", CAKEY)
            out_path = os.path.join(CATOP, CAREQ)

            key_create_cmd = "{0} -newkey rsa:2048 -keyout {1} -out {2}".format(REQ, keyout_path, out_path)

            subprocess.Popen(shlex.split(key_create_cmd), stdout=subprocess.PIPE)

            out_path = os.path.join(CATOP, CACERT)
            keyfile_path = os.path.join(CATOP, "private", CAKEY)
            infile_path = os.path.join(CATOP, CAREQ)

            serial_create_cmd = "{0} -create_serial -out {1} {2} -batch " \
                                "-keyfile {3} -selfsign " \
                                "-extensions v3_ca -infiles {4}".format(CA, out_path, CADAYS, keyfile_path, infile_path)

            subprocess.Popen(shlex.split(serial_create_cmd), stdout=subprocess.PIPE)


def newcert(option, opt_str, value, parser, *args, **kwargs):
    # create a certificate
    cmd = "{0} -new -x509 -keyout newkey.pem -out newcert.pem {1}".format(REQ, DAYS)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Certificate is in newcert.pem, private key is in newkey.pem")


def newreq(option, opt_str, value, parser, *args, **kwargs):
    # create a certificate request
    cmd = "{0} -new -keyout newkey.pem -out newreq.pem {1}".format(REQ, DAYS)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Request is in newreq.pem, private key is in newkey.pem")


def newreq_nodes(option, opt_str, value, parser, *args, **kwargs):
    # create a certificate request
    cmd = "{0} -new -nodes -keyout newkey.pem -out newreq.pem {1}".format(REQ, DAYS)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Request is in newreq.pem, private key is in newkey.pem")


def pkcs12(option, opt_str, value, parser, *args, **kwargs):
    cname = "My Certificate" if not value else value
    certfile_path = os.path.join(CATOP, CACERT)
    cmd = "{0} -in newcert.pem -inkey newkey.pem " \
          "-certfile ${1} -out newcert.p12 " \
          "-export -name {2}".format(PKCS12, certfile_path, cname)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("PKCS #12 file is in newcert.p12")
    sys.exit(1)


def xsign(option, opt_str, value, parser, *args, **kwargs):
    cmd = "{0} -policy policy_anything -infiles newreq.pem".format(CA)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)


def sign(option, opt_str, value, parser, *args, **kwargs):
    cmd = "{0} -policy policy_anything -out newcert.pem -infiles newreq.pem".format(CA)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Signed certificate is in newcert.pem")


def signCA(option, opt_str, value, parser, *args, **kwargs):
    cmd = "{0} -policy policy_anything -out newcert.pem -extensions v3_ca -infiles newreq.pem".format(CA)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Signed CA certificate is in newcert.pem")


def signcert(option, opt_str, value, parser, *args, **kwargs):
    certfile, keyfile = value
    cmd = "{0} -x509toreq -in newreq.pem -signkey newreq.pem -out tmp.pem".format(X509)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    cmd = "{0} -policy policy_anything -out newcert.pem -infiles tmp.pem".format(CA)
    subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Signed certificate is in newcert.pem")


def verify(option, opt_str, value, parser, *args, **kwargs):
    print(value)
    """
    if (shift) {
        foreach $j (@ARGV) {
            system ("$VERIFY -CAfile $CATOP/$CACERT $j");
            $RET=$? if ($? != 0);
        }
        exit $RET;
    } else {
        system ("$VERIFY -CAfile $CATOP/$CACERT newcert.pem");
        $RET=$?;
        exit 0;
    }
    """
    pass


def cp_pem(*args):
    infile, outfile, bound = args

    infile_obj = open(infile, "r")
    outfile_obj = open(outfile, "w")

    for line in infile_obj.readline():
        flag = 1 if re.search("^-----BEGIN.*{0}".format(bound), line) else 0
        outfile_obj.write(line)

        if flag:
            outfile_obj.write(line)
            if re.search("^-----END.*{0}".format(bound), line):
                break

    infile_obj.close()
    outfile_obj.close()

    return 1

if __name__ == "__main__":
    ca_helper()
