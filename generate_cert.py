import OpenSSL
from OpenSSL import crypto
import os

def generate_cert():
    # Generate a 2048-bit RSA key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed X509 certificate
    cert = crypto.X509()

    # Set subject CN to 'localhost'
    cert.get_subject().CN = 'localhost'

    # Set serial number
    cert.set_serial_number(1000)

    # Set validity period (valid from now for 365 days)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    # Set issuer to self (self-signed)
    cert.set_issuer(cert.get_subject())

    # Set public key
    cert.set_pubkey(key)

    # Sign the certificate with the private key
    cert.sign(key, 'sha256')

    # Save cert.pem
    with open('cert.pem', 'wb') as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    # Save key.pem
    with open('key.pem', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    print("Self-signed certificate and key have been generated successfully.")
    print("Certificate saved to: cert.pem")
    print("Private key saved to: key.pem")

if __name__ == '__main__':
    generate_cert()