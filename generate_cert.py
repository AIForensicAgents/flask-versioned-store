"""Generate a self-signed SSL certificate for local development."""

import subprocess


def generate_cert(
    cert_file: str = "cert.pem",
    key_file: str = "key.pem",
    days: int = 365,
    common_name: str = "localhost",
) -> None:
    """Generate a self-signed SSL certificate using OpenSSL."""
    cmd = [
        "openssl", "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", key_file,
        "-out", cert_file,
        "-days", str(days),
        "-nodes",
        "-subj", f"/CN={common_name}",
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
