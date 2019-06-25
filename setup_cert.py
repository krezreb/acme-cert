#!/usr/bin/env python

import os
from subprocess import Popen, PIPE
from OpenSSL import crypto
import datetime
import argparse

ACME_CERT_PORT=os.environ.get('ACME_CERT_PORT', '80')
SSL_CERT_EMAIL=os.environ.get('SSL_CERT_EMAIL', None)
SSL_CERT_FQDN=os.environ.get('SSL_CERT_FQDN', None)
SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', '/var/ssl/domain')
SSL_CERT_SELF_SIGNED = os.environ.get('SSL_CERT_SELF_SIGNED', 'false').lower() in ["true", "on", "1", "yes"]
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))

parser = argparse.ArgumentParser()
parser.add_argument('--port', default=ACME_CERT_PORT, help='What port to use to issue certs')
args = parser.parse_args()
        
def run(cmd, splitlines=False):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen([cmd], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    out, err = proc.communicate()
    if splitlines:
        out_split = []
        for line in out.split("\n"):
            line = line.strip()
            if line != '':
                out_split.append(line)
        out = out_split

    exitcode = int(proc.returncode)

    return (out, err, exitcode)

def log(s):
    print(s)

def get_le_cert(cert_file, fqdn, cert_email=None, expire_cutoff_days=31, acme_cert_http_port=80):
    change = False
    fail = False
    
    log('get_le_cert()')
    
    if os.path.isfile(cert_file):
        log('cert_file {} found'.format(cert_file))
        
        # cert already exists
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
        exp = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
        
        expires_in = exp - datetime.datetime.utcnow()
        
        if expires_in.days <= 0:
            log("Found cert {} EXPIRED".format(fqdn))
        else:
            log("Found cert {}, expires in {} days".format(fqdn, expires_in.days))
    
        if expires_in.days < expire_cutoff_days:
            log("Trying to renew cert {}".format(fqdn))
            # even though we're renewing we still use the --issue flag because of the
            # internals of how acme.sh works
            cmd = "acme.sh --issue --standalone --httpport {} -d {}".format(acme_cert_http_port, fqdn)

            (out, err, exitcode) = run(cmd)
            
            if exitcode == 0:
                log("RENEW SUCCESS: Certificate {} successfully renewed".format(fqdn))
                change = True
    
            else:
                log("RENEW FAIL: ERROR renewing certificate {}".format(fqdn))
                log(out)
                log(err)
                fail = True
    else :
        log('cert_file {} not found'.format(cert_file))
        cmd = "acme.sh --issue --standalone --httpport {} -d {}".format(acme_cert_http_port, fqdn)
        
        if cert_email != None:
            cmd += ' --accountemail {} '.format(cert_email)
            
        (out, err, exitcode) = run(cmd)
        
        if exitcode != 0:
            log("Requesting cert for {}: FAILED".format(fqdn))
            log(cmd)
            log(err)
            fail = True

        else:
            log("Requesting cert for {}: SUCCESS".format(fqdn))
            change = True
    
    return (change, fail)


cert_file=SSL_CERT_PATH+'/cert.pem'

if SSL_CERT_FQDN != None:
    (change, fail) = get_le_cert(cert_file, fqdn=SSL_CERT_FQDN, cert_email=SSL_CERT_EMAIL, expire_cutoff_days=CERT_EXPIRE_CUTOFF_DAYS, acme_cert_http_port=args.port)
                
    if change:
        log("Reloading nginx")
        run("nginx -s reload")
        
elif not os.path.isfile(cert_file) and SSL_CERT_SELF_SIGNED:
    if not os.path.isdir(SSL_CERT_PATH):
        os.makedirs(SSL_CERT_PATH)
    
    log('INFO: Generating self-signed ssl certificate')
    cmd = "openssl req -nodes -new -x509 -keyout {}/privkey.pem -out {}/cert.pem".format(SSL_CERT_PATH, SSL_CERT_PATH)
    cmd += " -subj '/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com' "
    run(cmd)
                
