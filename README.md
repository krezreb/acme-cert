# acme-cert, a set and forget ssl certification and renew script

My motivation is to have an easy to automate script that does the following.

- Issue letsencrypt certificates
- Renew them 31 days before their expiry 
- Deterministic filenames for the certificates.  No archives or cert2.pem when what I want is cert.pem
- Uses acme.sh because certbot doesn't have the above flexibility
- Be docker compose friendly, i.e. not rely on the apache or nginx plugins being running in the same container as the expiration process

# Examples to come