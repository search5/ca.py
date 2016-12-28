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
import configparser
import os
import re
import shlex
import subprocess
import sys
from argparse import ArgumentParser
from ca_py import openssl_util

openssl_cmd = "openssl"
if "OPENSSL" in os.environ:
    openssl_cmd = "openssl"
else:
    os.environ["OPENSSL"] = openssl_cmd

SSLEAY_CONFIG = os.environ.get("SSLEAY_CONFIG", "")

# 5 year
DAYS = "1825"
# 10 years
CADAYS = "3650"
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
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--newca", help="New Certificate Authority", action="store_true")
    group.add_argument("--newcert", help="New Certification", action="store_true")
    group.add_argument("--newreq", help="New Certification CSR", action="store_true")
    group.add_argument("--newreq-nodes", help="New Certification Nodes", action="store_true")
    group.add_argument("--pkcs12", help="PKCS12", type=str, nargs=1, metavar=("Certification Name",), action="store")
    group.add_argument("--xsign", help="Certification xsign", action="store_true")
    group.add_argument("--sign", "--signreq", help="Certification sign", action="store_true")
    group.add_argument("--signcert", type=str, nargs=2, dest="signcert",
                        help="Certification Sign", action="store", metavar=("certfile", "keyfile"))
    group.add_argument("--signCA", help="CA sign", action="store_true")
    group.add_argument("--verify", help="Certification Verify", action="store", type=str,
                       nargs='*', metavar="cert.pem")

    parser.add_argument("-i", "--config", help="Location of the CA.ini file to be used for issuing certificates",
                        action="store", type=str, nargs=1, metavar=("filename",))

    parser.add_argument("-d", "--days", help="Client Certificate Validity Period", action="store",
                        type=str, metavar=("days"))
    parser.add_argument("--cadays", help="Root Certification Authority Certificate Validity Period",
                        action="store", type=str, metavar=("days"))
    parser.add_argument("--catop", help="Certification Authority Directory", action="store", type=str,
                        metavar=("ca_top_directory"))
    parser.add_argument("--cakey", help="Certificate authority secret key filename", action="store", type=str,
                        metavar=("ca_key_filename"))
    parser.add_argument("--careq", help="Certificate authority authentication request key filename", action="store",
                        type=str, metavar=("ca_request_filename"))
    parser.add_argument("--cacert", help="Certificate Authority Key File Name", action="store", type=str,
                        metavar=("ca_certficate_filename"))

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(2)

    args = parser.parse_args()

    # 설정 파일과 개별 설정 옵션은 겹쳐서 사용할 수 없습니다.
    if args.config and (args.days or args.cadays or args.catop or args.cakey or args.careq or args.cacert):
        print("The ca.ini file and the individual setup options are mutually exclusive.")
        sys.exit(1)

    # 인증서 유효기간, 루트인증서 유효기간, 인증서 최상위 디렉터리 설정
    if args.config:
        config(args.config)
    if args.days:
        ca_entry(args.days, "days")
    if args.cadays:
        ca_entry(args.cadays, "cadays")

    # 인증서 생성에 사용되는 기본값 지정
    if args.catop:
        ca_entry(args.catop, "catop")
    if args.cakey:
        ca_entry(args.cakey, "cakey")
    if args.careq:
        ca_entry(args.careq, "careq")
    if args.cacert:
        ca_entry(args.cacert, "cacert")

    # 실행시 한번, openssl.cnf 파일 점검해서 만들어둠
    openssl_util.make_openssl_cnf(CATOP, DAYS)

    if args.newca:
        newca()
    elif args.newcert:
        newcert()
    elif args.newreq:
        newreq()
    elif args.newreq_nodes:
        newreq_nodes()
    elif args.pkcs12:
        pkcs12(args.pkcs12)
    elif args.xsign:
        xsign()
    elif args.sign:
        sign()
    elif args.signcert:
        signcert(args.signcert)
    elif args.signCA:
        signCA()
    elif args.verify:
        verify(args.verify)

    return


def newca():
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

            subprocess.call(shlex.split(key_create_cmd), stdout=subprocess.PIPE)

            out_path = os.path.join(CATOP, CACERT)
            keyfile_path = os.path.join(CATOP, "private", CAKEY)
            infile_path = os.path.join(CATOP, CAREQ)

            serial_create_cmd = "{0} -create_serial -out {1} -days {2} -batch " \
                                "-keyfile {3} -selfsign " \
                                "-extensions v3_ca -infiles {4}".format(CA, out_path, CADAYS, keyfile_path, infile_path)

            subprocess.call(shlex.split(serial_create_cmd), stdout=subprocess.PIPE)


def newcert():
    # create a certificate
    cmd = "{0} -new -x509 -keyout newkey.pem -out newcert.pem -days {1}".format(REQ, DAYS)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Certificate is in newcert.pem, private key is in newkey.pem")


def newreq():
    # create a certificate request
    cmd = "{0} -new -keyout newkey.pem -out newreq.pem -days {1}".format(REQ, DAYS)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Request is in newreq.pem, private key is in newkey.pem")


def newreq_nodes():
    # create a certificate request
    cmd = "{0} -new -nodes -keyout newkey.pem -out newreq.pem -days {1}".format(REQ, DAYS)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Request is in newreq.pem, private key is in newkey.pem")


def pkcs12(values):
    cname = "My Certificate" if not values[0] else values[0]
    certfile_path = os.path.join(CATOP, CACERT)
    cmd = "{0} -in newcert.pem -inkey newkey.pem " \
          "-certfile ${1} -out newcert.p12 " \
          "-export -name {2}".format(PKCS12, certfile_path, cname)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("PKCS #12 file is in newcert.p12")


def xsign():
    cmd = "{0} -policy policy_anything -infiles newreq.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)


def sign():
    cmd = "{0} -policy policy_anything -out newcert.pem -infiles newreq.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Signed certificate is in newcert.pem")


def signCA():
    cmd = "{0} -policy policy_anything -out newcert.pem -extensions v3_ca -infiles newreq.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Signed CA certificate is in newcert.pem")


def signcert(values):
    certfile, keyfile = values
    cmd = "{0} -x509toreq {1} -in {2} -signkey {3} -out tmp.pem".format(X509, DAYS, certfile, keyfile)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    cmd = "{0} -policy policy_anything -out newcert.pem -infiles tmp.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    print("Signed certificate is in newcert.pem")


def verify(values):
    if len(values) > 1:
        for cert_file in values:
            cafile_path = os.path.join(CATOP, CACERT)
            cmd = "{0} -CAfile {1} {2}".format(VERIFY, cafile_path, cert_file)
            subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    else:
        cafile_path = os.path.join(CATOP, CACERT)
        cmd = "{0} -CAfile {1} newcert.pem".format(VERIFY, cafile_path)
        subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)


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


def config(config_file_loc):
    global CATOP, CAKEY, CAREQ, CACERT, DAYS, CADAYS

    if not os.path.exists(config_file_loc[0]):
        print("The configuration file you specified does not exist. Use the default value.")
        print("CATOP: %s\nCAKEY: %s\nCAREQ: %s\nCACERT: %s\nDAYS: %s\nCADAYS: %s" % (
            CATOP, CAKEY, CAREQ, CACERT, DAYS, CADAYS ))
        sys.exit(1)

    ca_ini = configparser.ConfigParser()
    ca_ini.read(config_file_loc[0])

    if 'CA' not in ca_ini.sections():
        print("Invalid configuration file. The CA section must be present.")
        sys.exit(1)

    if "CATOP" in ca_ini['CA']:
        CATOP = ca_ini['CA']['CATOP']
    else:
        ca_ini['CA']['CATOP'] = CATOP

    if "CAKEY" in ca_ini['CA']:
        CAKEY = ca_ini['CA']['CAKEY']
    else:
        ca_ini['CA']['CAKEY'] = CAKEY

    if "CAREQ" in ca_ini['CA']:
        CAREQ = ca_ini['CA']['CAREQ']
    else:
        ca_ini['CA']['CAREQ'] = CAREQ

    if "CACERT" in ca_ini['CA']:
        CACERT = ca_ini['CA']['CACERT']
    else:
        ca_ini['CA']['CACERT'] = CACERT

    if "DAYS" in ca_ini['CA']:
        DAYS = ca_ini['CA']['DAYS']
    else:
        ca_ini['CA']['DAYS'] = DAYS

    if "CADAYS" in ca_ini['CA']:
        CADAYS = ca_ini['CA']['CADAYS']
    else:
        ca_ini['CA']['CADAYS'] = CADAYS

    ca_ini.write(open(config_file_loc[0], "w"))

    print("The final settings are as follows.")
    for ca_entry in ("CATOP", "CAKEY", "CAREQ", "CACERT", "DAYS", "CADAYS"):
        print("%s: %s" % (ca_entry, ca_ini['CA'].get(ca_entry, '')))


def ca_entry(values, field):
    global CATOP, CAKEY, CAREQ, CACERT, DAYS, CADAYS

    if field == "days":
        DAYS = values[0]
    elif field == "cadays":
        CADAYS = values[0]
    elif field == "catop":
        CATOP = values[0]
    elif field == "cakey":
        CAKEY = values[0]
    elif field == "careq":
        CAREQ = values[0]
    elif field == "cacert":
        CACERT = values[0]

if __name__ == "__main__":
    ca_helper()
