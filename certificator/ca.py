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
import shutil
import subprocess
import click
from pathlib import Path
from certificator import openssl_util

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


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        if cmd_name in ('sign', 'signreq'):
            return super().get_command(ctx, 'sign')
        return super().get_command(ctx, cmd_name)


def file_exists(ctx, param, value):
    checker = lambda x: os.path.exists(x)

    if isinstance(value, tuple):
        ret_value = []
        for item in value:
            if not checker(item):
                raise click.FileError(item, hint="{0} 파일이 존재하지 않습니다. 다시 확인하여 주세요".format(item))
            else:
                ret_value.append(item)
        return tuple(ret_value)

    if os.path.exists(value):
        return value
    raise click.FileError(value, hint="{0} 파일이 존재하지 않습니다. 다시 확인하여 주세요".format(value))


@click.group(cls=AliasedGroup)
@click.option('--debug/--no-debug', default=False)
@click.option("-i", "--config", help="Location of the CA.ini file to be used for issuing certificates")
@click.option("-d", "--days", help="Client Certificate Validity Period")
@click.option("--cadays", help="Root Certification Authority Certificate Validity Period")
@click.option("--catop", help="Certification Authority Directory")
@click.option("--cakey", help="Certificate authority secret key filename")
@click.option("--careq", help="Certificate authority authentication request key filename")
@click.option("--cacert", help="Certificate Authority Key File Name")
@click.option("--key-length", help="")
@click.pass_context
def cli(ctx, debug, config, days, cadays, catop, cakey, careq, cacert, key_length):
    # ensure that ctx.obj exists and is a dict (in case `cli()` is called
    # by means other than the `if` block below
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug

    key_length = int(key_length or "2048")
    ctx.obj['key_length'] = key_length
    if key_length < 2048:
        raise click.ClickException("Key length must be at least 2048.")

    if config:
        ctx.obj['config'] = config_read(config, ctx)
    else:
        ctx.obj['days'] = days or DAYS
        ctx.obj['cadays'] = cadays or CADAYS
        ctx.obj['catop'] = catop or CATOP
        ctx.obj['cakey'] = cakey or CAKEY
        ctx.obj['careq'] = careq or CAREQ
        ctx.obj['cacert'] = cacert or CACERT

    if config and (days or cadays or catop or cakey or careq or cacert):
        raise click.UsageError("The ca.ini file and the individual setup options are mutually exclusive.", ctx)

    openssl_util.make_openssl_cnf(ctx.obj['catop'], DAYS)


@cli.command(help="New Certificate Authority")
@click.pass_context
def newca(ctx):
    # if explicitly asked for or it doesn't exist then setup the
    # directory structure that Eric likes to manage things

    NEW = "1"
    if NEW or (not Path(ctx.obj['catop'], "serial").exists()):
        # create the directory hierarchy
        for item in ("certs", "crl", "newcerts", "private"):
            Path(ctx.obj['catop'], item).mkdir(parents=True, exist_ok=True)

        Path(ctx.obj['catop'], "index.txt").write_text("")
        Path(ctx.obj['catop'], "crlnumber").write_text("01\n")

    if not Path(ctx.obj['catop'], "private", ctx.obj['cakey']).exists():
        tmp_file = input("CA certificate filename (or enter to create) ")
        tmp_file = tmp_file.rstrip()

        # ask user for existing CA certificate
        if os.path.join(tmp_file):
            cp_pem(tmp_file, os.path.join(ctx.obj['catop'], ctx.obj['cacert']), "CERTIFICATE")
            cp_pem(tmp_file, os.path.join(ctx.obj['catop'], "private", ctx.obj['cakey']), "PRIVATE")
        else:
            click.echo("Making CA certificate ...")
            keyout_path = os.path.join(ctx.obj['catop'], "private", ctx.obj['cakey'])
            out_path = os.path.join(ctx.obj['catop'], ctx.obj['careq'])

            key_create_cmd = "{0} -newkey rsa:{1} -keyout {2} -out {3}".format(REQ, ctx.obj['key_length'], keyout_path, out_path)

            subprocess.call(shlex.split(key_create_cmd), stdout=subprocess.PIPE)

            out_path = os.path.join(ctx.obj['catop'], ctx.obj['cacert'])
            keyfile_path = os.path.join(ctx.obj['catop'], "private", ctx.obj['cakey'])
            infile_path = os.path.join(ctx.obj['catop'], ctx.obj['careq'])

            serial_create_cmd = "{0} -create_serial -out {1} -days {2} -batch " \
                                "-keyfile {3} -selfsign " \
                                "-extensions v3_ca -infiles {4}".format(CA, out_path, ctx.obj['cadays'], keyfile_path,
                                                                        infile_path)

            subprocess.call(shlex.split(serial_create_cmd), stdout=subprocess.PIPE)


@cli.command(help="New Certification")
@click.pass_context
def newcert(ctx):
    # create a certificate
    cmd = "{0} -new -x509 -keyout newkey.pem -out newcert.pem -days {1}".format(REQ, DAYS)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("Certificate is in newcert.pem, private key is in newkey.pem")


@cli.command(help="New Certification CSR")
@click.pass_context
def newreq(ctx):
    # create a certificate request
    cmd = "{0} -new -keyout newkey.pem -out newreq.pem -days {1}".format(REQ, DAYS)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("Request is in newreq.pem, private key is in newkey.pem")


@cli.command(name='newreq-nodes', help="New Certification Nodes")
@click.pass_context
def newreq_nodes(ctx):
    # create a certificate request
    cmd = "{0} -new -nodes -keyout newkey.pem -out newreq.pem -days {1}".format(REQ, DAYS)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("Request is in newreq.pem, private key is in newkey.pem")


@cli.command(help="PKCS12")
@click.argument('certification_name', metavar='Certification Name', required=True)
@click.pass_context
def pkcs12(ctx, certification_name):
    cname = certification_name or "My Certificate"
    certfile_path = os.path.join(ctx.obj['catop'], ctx.obj['cacert'])
    cmd = "{0} -in newcert.pem -inkey newkey.pem " \
          "-certfile ${1} -out newcert.p12 " \
          "-export -name {2}".format(PKCS12, certfile_path, cname)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("PKCS #12 file is in newcert.p12")


@cli.command(help="Certification xsign")
@click.pass_context
def xsign(ctx):
    cmd = "{0} -policy policy_anything -infiles newreq.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)


@cli.command(help="Certification sign(or equal command signreq)")
@click.pass_context
def sign(ctx):
    cmd = "{0} -policy policy_anything -out newcert.pem -infiles newreq.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("Signed certificate is in newcert.pem")


@cli.command(help="Certification Sign")
@click.argument('certfile', callback=file_exists, required=True)
@click.argument('keyfile', callback=file_exists, required=True)
@click.pass_context
def signcert(ctx, certfile, keyfile):
    cmd = "{0} -x509toreq {1} -in {2} -signkey {3} -out tmp.pem".format(X509, DAYS, certfile, keyfile)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    cmd = "{0} -policy policy_anything -out newcert.pem -infiles tmp.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("Signed certificate is in newcert.pem")


@cli.command(help="CA sign")
@click.pass_context
def signCA(ctx):
    cmd = "{0} -policy policy_anything -out newcert.pem -extensions v3_ca -infiles newreq.pem".format(CA)
    subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    click.echo("Signed CA certificate is in newcert.pem")


@cli.command(help="Certification Verify")
@click.argument('cert_pem', callback=file_exists, nargs=-1, required=True)
@click.pass_context
def verify(ctx, cert_pem):
    if len(cert_pem) > 1:
        for cert_file in cert_pem:
            cafile_path = os.path.join(ctx.obj['catop'], ctx.obj['cacert'])
            cmd = "{0} -CAfile {1} {2}".format(VERIFY, cafile_path, cert_file)
            subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)
    else:
        cafile_path = os.path.join(ctx.obj['catop'], ctx.obj['cacert'])
        cmd = "{0} -CAfile {1} newcert.pem".format(VERIFY, cafile_path)
        subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE)


def cp_pem(*args):
    infile, outfile, bound = args

    shutil.copyfile(infile, outfile)

    return 1


def config_read(config_file_loc, ctx):
    if not os.path.exists(config_file_loc[0]):
        raise click.UsageError("The configuration file you specified does not exist. Use the default value."
                               "ctx.obj['catop']: %s\nctx.obj['cakey']: %s\nctx.obj['careq']: %s\nctx.obj['cacert']: %s\nDAYS: %s\nCADAYS: %s" % (
                               ctx.obj['catop'], ctx.obj['cakey'], ctx.obj['careq'], ctx.obj['cacert'], DAYS, CADAYS))

    ca_ini = configparser.ConfigParser()
    ca_ini.read(config_file_loc[0])

    if 'CA' not in ca_ini.sections():
        raise click.ClickException("Invalid configuration file. The CA section must be present.")

    ctx.obj['days'] = ca_ini['CA'].get('DAYS', '')
    ctx.obj['cadays'] = ca_ini['CA'].get('CADAYS', '')
    ctx.obj['catop'] = ca_ini['CA'].get('CATOP', '')
    ctx.obj['cakey'] = ca_ini['CA'].get('CAKEY', '')
    ctx.obj['careq'] = ca_ini['CA'].get('CAREQ', '')
    ctx.obj['cacert'] = ca_ini['CA'].get('CACERT', '')

    click.echo("The final settings are as follows.")

    for ca_entry in ("ctx.obj['catop']", "ctx.obj['cakey']", "ctx.obj['careq']", "ctx.obj['cacert']", "DAYS", "CADAYS"):
        click.echo("%s: %s" % (ca_entry, ca_ini['CA'].get(ca_entry, '')))


if __name__ == "__main__":
    cli(obj={})
