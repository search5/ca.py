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
import getopt
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

RET = 0


def ca_helper():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "?h", ["help, newca"])
    except getopt.GetoptError as err:
        print(str(err))
        help()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ("-?", "-h", "--help"):
            help()
        elif opt == "--newca":
            newca()

    print(RET)

    if len(sys.argv[1:]) == 0:
        help()

    return


def newca():
    global RET

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

        open(os.path.join(CATOP, "index.txt",), "w").write("")
        open(os.path.join(CATOP, "v", ), "w").write("01\n")

    if not os.path.join(CATOP, "private", CAKEY):
        tmp_file = input("CA certificate filename (or enter to create) ")
        tmp_file = tmp_file.rstrip()

        # ask user for existing CA certificate
        if os.path.join(tmp_file):
            func_ret = cp_pem(tmp_file, os.path.join(CATOP, "private", CAKEY), "PRIVATE")
            func_ret = cp_pem(tmp_file, os.path.join(CATOP, CACERT), "CERTIFICATE")
        else:
            print("Making CA certificate ...")
            keyout_path = os.path.join(CATOP, "private", CAKEY)
            out_path = os.path.join(CATOP, CAREQ)

            key_create_cmd = "{0} -newkey rsa:2048 -keyout {1} -out {2}".format(REQ, keyout_path, out_path)

            func_ret = subprocess.run(shlex.split(key_create_cmd), stdout=subprocess.PIPE)

            out_path = os.path.join(CATOP, CACERT)
            keyfile_path = os.path.join(CATOP, "private", CAKEY)
            infile_path = os.path.join(CATOP, CAREQ)

            serial_create_cmd = "{0} -create_serial -out {1} {2} -batch " \
                                "-keyfile {3} -selfsign " \
                                "-extensions v3_ca -infiles {4}".format(CA, out_path, CADAYS, keyfile_path, infile_path)

            func_ret = subprocess.run(shlex.split(serial_create_cmd), stdout=subprocess.PIPE)

            RET = func_ret.stdout.read()


def newcert():
    # create a certificate
    """
    system ("$REQ -new -x509 -keyout newkey.pem -out newcert.pem $DAYS");
    $RET=$?;
    """
    print("Certificate is in newcert.pem, private key is in newkey.pem")


def newreq():
    # create a certificate request
    """
    system ("$REQ -new -keyout newkey.pem -out newreq.pem $DAYS");
    $RET=$?;
    """
    print("Request is in newreq.pem, private key is in newkey.pem")


def newreq_nodes():
    # create a certificate request
    """
    system ("$REQ -new -nodes -keyout newkey.pem -out newreq.pem $DAYS");
    $RET=$?;
    """
    print("Request is in newreq.pem, private key is in newkey.pem")


def pkcs12(cname):
    cname = "My Certificate" if not cname else cname

    """
    system ("$PKCS12 -in newcert.pem -inkey newkey.pem " .
        "-certfile ${CATOP}/$CACERT -out newcert.p12 " .
        "-export -name \"$cname\"");
    $RET=$?;
    """
    print("PKCS #12 file is in newcert.p12")
    sys.exit(1)


def xsign():
    """
    system ("$CA -policy policy_anything -infiles newreq.pem");
            $RET=$?;
    """
    pass


def sign():
    """
    system ("$CA -policy policy_anything -out newcert.pem " .
                                "-infiles newreq.pem");
            $RET=$?;
    """
    print("Signed certificate is in newcert.pem")


def signCA():
    """
    system ("$CA -policy policy_anything -out newcert.pem " .
                        "-extensions v3_ca -infiles newreq.pem");
            $RET=$?;
    """
    print("Signed CA certificate is in newcert.pem")


def signcert():
    """
    system ("$X509 -x509toreq -in newreq.pem -signkey newreq.pem " .
                                    "-out tmp.pem");
            system ("$CA -policy policy_anything -out newcert.pem " .
                                "-infiles tmp.pem");
            $RET = $?;
    """
    print("Signed certificate is in newcert.pem")


def verify(*args):
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

    flag = 0

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


def help():
    help_usage = "$ Usage: ca.py --newcert|--newreq|--newreq-nodes|--newca|--sign|--verify"

    print(help_usage)

if __name__ == "__main__":
    ca_helper()
