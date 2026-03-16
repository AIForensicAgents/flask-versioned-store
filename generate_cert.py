import subprocess
import os


def generate_cert(cert_file="cert.pem", key_file="key.pem", days=365, common_name="localhost"):
    """Generate a self-signed SSL certificate using OpenSSL."""
    cmd = [
        "openssl", "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", key_file,
        "-out", cert_file,
        "-days", str(days),
        "-nodes",
        "-subj", f"/CN={common_name}"
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"Certificate generated successfully:")
        print(f"  Certificate: {cert_file}")
        print(f"  Private Key: {key_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating certificate: {e.stderr}")
        raise
    except FileNotFoundError:
        print("OpenSSL is not installed or not found in PATH.")
        raise


if __name__ == "__main__":
    generate_cert()