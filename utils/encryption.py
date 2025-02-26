from cryptography.fernet import Fernet

def encrypt_file(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data)


def decrypt_file(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)
