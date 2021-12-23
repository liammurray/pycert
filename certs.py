#!/usr/bin/env python3
# -*- mode: python3 -*-

import click
import datetime
import os
import shutil
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from collections import namedtuple


def gen_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

def key_pem(key):
  return key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

def pem(cert):
  return cert.public_bytes(
    encoding=serialization.Encoding.PEM
  )

#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#module-cryptography.hazmat.primitives.asymmetric.rsa)
def writef(out_file, *chunks):
    print(out_file)
    with open(out_file, "wb") as f:
      for chunk in chunks:
        f.write(chunk)

def gen_name(common_name, org=u"Acme"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Washington"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Seattle"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

def gen_root_cert(name, days=3650, path_length=None):
  """
    Generates a root certificate
  """
  key = gen_key()
  subject = issuer = gen_name(name)

  subject_keyid=x509.SubjectKeyIdentifier.from_public_key(key.public_key())
  auth_keyid=x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
 
  cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer
    ).public_key(key.public_key()
    ).serial_number(x509.random_serial_number()
    ).not_valid_before(datetime.datetime.utcnow()
    ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days)
    ).add_extension(subject_keyid, critical=False
    ).add_extension(auth_keyid, critical=False
    ).add_extension(
      x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, 
      data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=True, crl_sign=True), critical=True
    ).add_extension(
      x509.BasicConstraints(ca=True, path_length=path_length), critical=True
    ).sign(key, hashes.SHA256(), default_backend())

  return (key, cert)


def gen_user_cert(issuer_cert, issuer_key, dns_name, days=3650):
  """
    Generates a user certificate
  """
  key = gen_key()
  subject = gen_name(dns_name)
 
  ski_ext = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
  subject_keyid=x509.SubjectKeyIdentifier.from_public_key(key.public_key())
  auth_keyid=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value)
  alt_name=x509.SubjectAlternativeName([x509.DNSName(dns_name)])

  cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_cert.issuer
    ).public_key(key.public_key()
    ).serial_number(x509.random_serial_number()
    ).not_valid_before(datetime.datetime.utcnow()
    ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days)
    ).add_extension(alt_name, critical=False
    ).add_extension(subject_keyid, critical=False
    ).add_extension(auth_keyid, critical=False
    ).add_extension(
      x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, 
      data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False), critical=True
    ).sign(issuer_key, hashes.SHA256(), default_backend())

  return (key, cert)

def gen_csr(dns_name):
  """
    Generates a certificate signing request
  """
  key = gen_key()
  subject = gen_name(dns_name)
  dns_names = [dns_name]
  dns_names = [x509.DNSName(d) for d in dns_names]
  alt_name=x509.SubjectAlternativeName(dns_names)
  basic_constraints=x509.BasicConstraints(ca=False, path_length=None)
  csr = x509.CertificateSigningRequestBuilder().subject_name(subject
    ).add_extension(alt_name, critical=False
    ).add_extension(basic_constraints, critical=False
    ).add_extension(
      x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, 
      data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False), critical=True
    ).sign(key, hashes.SHA256())

  return (key, csr)

CertInfo = namedtuple("CertInfo", ["key", "cert", "key_file", "pem_file"])

class Certs(object):
  """
    For creating, loading certs
  """

  def __init__(self, certs_root, ssm_root, force):
    self.certs_root=certs_root
    self.ssm_root=ssm_root
    self.force=force
    self.certs={}

  def root(self, cert_key, name):

    cert_name=f"{cert_key}-ca"
    out_path=os.path.join(self.certs_root, 'ca')
    os.makedirs(out_path, exist_ok=True)

    print(f"Root CA: {cert_name}")
    (key, cert)=gen_root_cert(name)
    
    pem_file=os.path.join(out_path, f"{cert_name}.pem")
    key_file=os.path.join(out_path, f"{cert_name}.key")
 
    writef(key_file, key_pem(key))
    writef(pem_file, pem(cert))

    self.certs[cert_name]=CertInfo(key, cert, key_file, pem_file)

  def user(self, issuer_cert_key, cert_name, dns_name):

    issuer_cert_name=f"{issuer_cert_key}-ca"
    out_path=os.path.join(self.certs_root, issuer_cert_key)
    os.makedirs(out_path, exist_ok=True)

    print(f"End user cert: {cert_name} <== {issuer_cert_name} {dns_name}")
    issuer = self.certs[issuer_cert_name]

    (key, cert)=gen_user_cert(issuer.cert, issuer.key, dns_name)
    pem_file=os.path.join(out_path, f"{cert_name}.pem")
    pem_chain_file=os.path.join(out_path, f"{cert_name}-chain.pem")
    key_file=os.path.join(out_path, f"{cert_name}.key")
 
    pem_bytes = pem(cert)
    writef(key_file, key_pem(key))
    writef(pem_file, pem_bytes)
    # Order matters. See https://www.rfc-editor.org/rfc/rfc4346#section-7.4.2 (certificate list)
    writef(pem_chain_file, pem_bytes, pem(issuer.cert))

    self.certs[cert_name]=CertInfo(key, cert, key_file, pem_file)


@ click.group()
def certs():
    '''
      X.509 cert tool
    '''
    pass


@ click.command()
@ click.option('-p', '--prompt/--no-prompt', default=True, help='enable prompts')
@ click.option('-f', '--force/--no-force', default=True, help='force update certs')
@ click.option('-c', '--certs-root', default='./certificates/dev', help='certificate base path')
@ click.option('-s', '--ssm-root', default='/temporal/dev/certs', help='ssm parameter base path')
def gen(certs_root, ssm_root, force, prompt):
    """
      Generates certs in certs_root

      Examples:

       ./certs.py gen

       ./certs.py gen -c ./testing

      Verification:

       openssl verify -verbose -CAfile ca.pem user.pem

       openssl x509 -text -in -noout -in some.pem

    """
    if force and os.path.exists(certs_root):
      if prompt:
        print(f"This will remove and re-create: {certs_root}")
        if not click.confirm('\nContinue?', default=False):
          return
      shutil.rmtree(certs_root)
   
    certs = Certs(certs_root=certs_root, ssm_root=ssm_root, force=force)
    certs.root('client', 'client.acme.io')
    certs.root('cluster', 'cluster.acme.io')

    certs.user('client', 'developer', 'developer.engineering.acme.io')
    certs.user('cluster', 'frontend', 'temporal-frontend.dev.acme.io')
    certs.user('cluster', 'internode', 'temporal-internode.dev.acme.io')


certs.add_command(gen)

if __name__ == "__main__":
    certs()  # pylint: disable=no-value-for-parameter
