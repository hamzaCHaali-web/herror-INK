import secrets
import hashlib

class Security:
    @staticmethod
    def generate_pin():
        pin = secrets.randbelow(10000)
        return f"{pin:04d}"
    
    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_token(token):
        if token is None:
            return None
        return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    @staticmethod
    def hash_pin(pin):
        if pin is None:
            return None
        return hashlib.sha256(pin.encode('utf-8')).hexdigest()
