from cryptography.fernet import Fernet

def pseudonymize_json(data, key):
    f = Fernet(key)

    def encrypt_value(value):
        return f.encrypt(value.encode()).decode()

    def recurse(obj):
        if isinstance(obj, dict):
            return {k: recurse(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [recurse(elem) for elem in obj]
        elif isinstance(obj, str):
            return encrypt_value(obj)
        else:
            return obj

    return recurse(data)
