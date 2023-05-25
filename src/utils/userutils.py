import base64
import secrets
import json
import os

from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


class DecryptionError(Exception):
    def __init__(self, msg: str = 'Data could not be decrypted'):
        super().__init__(msg)


class User:
    def __init__(self, password: str):
        # get local encryption key
        key_dat, key_salt = parse_pem(os.path.join('keys', 'symetric.pem'), True)
        key_pw = SHA256.new(password.encode()+base64.b64decode(key_salt)).digest()
        self.aes_key = read_secure_data(key_dat, key_pw)
        # decrypt user information:
        with open(os.path.join('data', 'info.usr'), 'rb') as i:
            user_dat = self.decrypt_aes(i.read()).decode()
            self.u_id = user_dat[:44]
            rsa_pw = user_dat[44:60]
            has_proxy = user_dat[60] 
            self.name = user_dat[61:]
        # convert "has_proxy" to a boolean
        if has_proxy == 'Y':
            self.proxy = True
        else:
            self.proxy = False
        with open(os.path.join('keys', 'public.pem'), 'rb') as pub, open(os.path.join('keys', 'private.pem'), 'rb') as prv:
            self.rsa_pub = RSA.import_key(pub.read())
            self.rsa_prv = RSA.import_key(prv.read(), rsa_pw)
        # load user preferences
        with open(os.path.join('data', 'prefs.json')) as p:
            self.prefs = json.load(p)
        # decrypts and load user's contacts
        with open(os.path.join('data', 'contacts.txt'), 'rb') as c:
            contacts = c.read()
            if len(contacts) > 24:
                self.contacts = json.loads(self.decrypt_aes(contacts).decode())
            else:
                self.contacts = {}
        if self.contacts == {}:
            write_secure_data(json.dumps({self.name: {'addr': '127.0.0.1', 'id': self.u_id}}).encode(), self.aes_key)
        # load proxy details if provided
        if self.proxy:
            with open(os.path.join('data', 'proxy', 'prox_config.dat'), 'rb') as conf:
                self.prox_conf = json.loads(self.decrypt_aes(conf.read()).decode())
        # load node details if provided
        if os.path.exists(os.path.join('data', 'nodes.dat')):
            with open(os.path.join('data', 'nodes.dat'), 'rb') as nod:
                self.nodes = json.loads(self.decrypt_aes(nod.read()).decode())
        # keep track of ports the user is actively listening on
        self.active_ports = []
        # keep track of who the user is currently chatting with
        self.active_partners = []

    # allows the "write_secure_data" function to be called directly from the user object using the user's key
    def encrypt_aes(self, plaintext: bytes):
        return write_secure_data(plaintext, self.aes_key)
    
    # allows the "read_secure_data" function to be called directly from the user object using the user's key
    def decrypt_aes(self, ciphertext: bytes):
        return read_secure_data(ciphertext, self.aes_key)

    # decrypt a message with the user's rsa private key
    def decrypt_rsa(self, ciphertext: bytes):
        sentinel = b'ERROR'
        cipher = PKCS1_v1_5.new(self.rsa_prv)
        return cipher.decrypt(ciphertext, sentinel)

    # creates a digital signature of hashed message
    def sign_msg(self, msg_hash: SHA256.SHA256Hash):
        signer = pkcs1_15.new(self.rsa_prv)
        return signer.sign(msg_hash) 

    # adds or removes contacts from the user's list
    def modify_contacts(self, operation: str, contact_id: str, contact_name: str = None,  contact_addr: str = None):
        match operation:
            case 'add':
                # save contacts username and ip address (if provided)
                contact_info = {'Username': contact_name}
                if contact_addr:
                    contact_info['Address'] = contact_addr
                self.contacts[contact_id] = contact_info
            case 'del':
                del self.contacts[contact_id]
            case _:
                raise ValueError('Invalid Opperation')
        # overwrite current contacts with the updated list
        with open(os.path.join('data', 'contacts.txt'), 'wb') as c:
            c.write(self.encrypt_aes(json.dumps(self.contacts).encode()))
    
    def update_prefs(self, theme: str, notification: str, msg_font: str, date_format: str, erase_limit: int):
        self.prefs = {'theme': theme, 'notification': notification, 'msg-font': msg_font, 'date-format': date_format, 'erase-limit': erase_limit}
        with open(os.path.join('data', 'prefs.json'), 'w') as p:
            json.dump(self.prefs, p)

    # encrypts and stores all the messages sent in a given conversation
    def encrypt_archives(self, tunnel):
        archive_path = os.path.join('data', 'archives', tunnel.peer_name)
        # ensure an archive file exists for a given peer
        if not os.path.exists(archive_path):
            os.mkdir(archive_path)
        # convert message logs to string
        archive = '\n'.join(tunnel.history).encode()
        # encrypt and store message logs
        with open(os.path.join(archive_path, datetime.now().strftime("%d-%m-%y-%H%M.txt")), 'w') as f:
            f.write(break_lines(self.encrypt_aes(archive).decode()))          
    
    # decrypts archives and returns the plaintext
    def decrypt_archives(self, peer:str, date: str) -> str:
        archive_name = date.replace(':', '').replace(' ', '-')
        with open(os.path.join('data', 'archives', peer, f'{archive_name}.txt')) as a:
            return self.decrypt_aes(a.read().replace('\n', '').encode()).decode()

    # encrypts a log file after it's created
    def encrypt_logs(self, date: str=None):
        if not date:
            file_name = os.path.join('logs', f'{datetime.now().strftime("%d-%m-%y")}.log')
        else:
            file_name = os.path.join('logs', f'{date}.log')
        # get currently existing log entries
        with open(file_name) as log:
            log_dat = log.read()
            # check if there are any encrypted entries, and if so decrypt them
            if log_dat[0] == '{':
               encrypted, decrypted = log_dat[1:].split('}')
               to_encrypt = self.decrypt_aes(encrypted.encode()).decode()+decrypted
            else:
                to_encrypt = log_dat
        # overwrite log file with completely encrypted data
        with open(file_name, 'w') as log:
            log.write('{'+break_lines(self.encrypt_aes(to_encrypt.encode()).decode())+'}\n')
    
    # decrypts logs and returns the plaintext
    def decrypt_logs(self, date:str):
        # decrypt and return log
        with open(os.path.join('logs', f'{date}.log')) as l:
            to_decrypt = l.read()[1:-1].replace('\n', '') 
            return self.decrypt_aes(to_decrypt.encode())
        
    # converts dates in the user's preffered format to dd-mm-yy for accessing files
    def format_date(self, date: str) -> str:
        format = self.prefs['date-format'].split('/')
        indexes = {'day': format.index('dd'), 'month': format.index('mm'), 'year': format.index('yy')}
        date = date.split('/')
        return f'{date[indexes["day"]]}-{date[indexes["month"]]}-{date[indexes["year"]]}'    

    
# this won't work with all pem files as it doesn't account for multiple entries, however, it works
# for any pem files HIDE is likely to encounter
def parse_pem(pem_file: str, has_salt=False) -> tuple:
    salt = None
    with open(pem_file, 'rb') as p:
        pem_dat = b''.join(p.readlines()[1:-1]).replace(b'\n', b'')
    if has_salt:
        salt = pem_dat[:24]
        pem_dat = pem_dat[24:]
    return pem_dat, salt
    

# encrypts data and combines it with its iv for either for local storage or to be sent as a message
def write_secure_data(plaintext: bytes, aes_key: bytes, iv: bytes = None) -> bytes:
    if not iv:
        iv = secrets.token_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plaintext, 16))
    return base64.b64encode(iv)+base64.b64encode(cipher_text)


# decrypts the messages created by the above function
def read_secure_data(ciphertext: bytes, aes_key: bytes) -> bytes:
    iv = base64.b64decode(ciphertext[:24])
    data = base64.b64decode(ciphertext[24:])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(data), 16)
    except ValueError:
        raise DecryptionError()

# formats encrypted data to be stored in a file by inserting a new line at regular increments
def break_lines(data, increment=75):
    return '\n'.join(data[i:i+increment] for i in range(0, len(data), increment))
