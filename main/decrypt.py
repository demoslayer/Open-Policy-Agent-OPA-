from cryptography.fernet import Fernet

def decrypt_json_data(data, key):
    f = Fernet(key)

    def decrypt_value(value):
        try:
            return f.decrypt(value.encode()).decode()
        except Exception:
            return value  # Leave it unchanged if it's not decryptable

    def recurse(obj):
        if isinstance(obj, dict):
            return {k: recurse(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [recurse(elem) for elem in obj]
        elif isinstance(obj, str):
            return decrypt_value(obj)
        else:
            return obj

    return recurse(data)
