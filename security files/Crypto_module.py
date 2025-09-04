from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Generate or Load keys
def generate_fernet_key():
    return Fernet.generate_key()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_log(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted)
    return file_path + '.enc'

def sign_report(report_data, private_key):
    signature = private_key.sign(
        report_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Main function (example usage)
def run_crypto(log_path, report_data):
    fernet_key = generate_fernet_key()
    private_key, public_key = generate_rsa_keys()

    # Encrypt the log file
    encrypted_file = encrypt_log(log_path, fernet_key)
    print(f"Encrypted log saved to: {encrypted_file}")

    # Sign the report data
    signature = sign_report(report_data, private_key)
    print(f"Generated signature: {signature.hex()}")

    return fernet_key, private_key, public_key, signature

if __name__ == "__main__":
    # Example usage
    log_file = "Sample.evtx"
    report = "This is a sample report."

    try:
        fernet_key, private_key, public_key, signature = run_crypto(log_file, report)
        print(f"Fernet Key: {fernet_key.decode()}")
        print(f"Private Key (PEM): {private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()}")
        print(f"Public Key (PEM): {public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()}")
        print(f"Signature: {signature.hex()}")
    except Exception as e:
        print(f"Error: {e}")