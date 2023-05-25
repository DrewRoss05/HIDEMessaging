import os
import zipfile
import base64
import secrets
import json

from tkinter import ttk, filedialog , messagebox
from tkinter import StringVar, BooleanVar
from tkinter import END
from ttkthemes import ThemedTk

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from datetime import datetime


def format_pem(data: bytes, key_name: str):
    output = f'-----BEGIN {key_name}-----\n'.encode()
    output += b'\n'.join(data[i:i+64] for i in range(0, len(data), 64))
    output += f'\n-----END {key_name}-----'.encode()
    return output
    

# encrypts data and combines it with its iv for either for local storage or to be sent as a message
def write_secure_data(plaintext: bytes, aes_key: bytes, iv: bytes = None) -> bytes:
    if not iv:
        iv = secrets.token_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plaintext, 16))
    return base64.b64encode(iv)+base64.b64encode(cipher_text)


# generates a seed file to create user information based on. This should be cryptographically sufficient as 
# there are ~3.11e+126 possible seeds (including pin) and 2^128 possible salts
def generate_seed_file(target_dir: str):
    char_bank = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]'
    seed = ''
    pin = secrets.randbelow(340282366920938463463374607431768211457)
    for i in range(48):
        seed += secrets.choice(char_bank)
    seed += str(pin)
    key_salt = secrets.token_hex(16)
    id_salt = secrets.token_hex(16)
    file_name =  os.path.join(target_dir, f'{datetime.now().strftime("%d%-Y%M%S")}.sed')
    with open(file_name, 'w') as seed_file:
        seed_file.write(f'{seed}\n{key_salt}\n{id_salt}')
    return file_name


# creates the local files for a HIDE user based on a seed file and save them to a desired directory
def create_user(username: str, password: str, seed_file: str, target_dir: str, proxy: tuple = None, node: tuple = None):
    # load randomized/cryptographic information from seed file
    with open(seed_file) as s:
        seed_dat, pw_salt, id_salt = s.readlines()
    seed = seed_dat[:48]
    pin = int(seed_dat[48:]).to_bytes(16, 'big')
    id_salt = bytearray.fromhex(id_salt)
    key_salt = bytearray.fromhex(pw_salt) # this is hashed with the user's password to encrypt the main key
    # create information to encrypt local AES key
    key_iv = seed[:16].encode()
    key_pw = SHA256.new(password.encode()+key_salt).digest()
    # create and encrypt local AES key
    aes_key = SHA256.new(seed[16:32].encode()+pin).digest()
    enc_aes_key = base64.b64encode(key_salt)+write_secure_data(aes_key, key_pw, key_iv)
    # generate RSA keys and encrypt private key
    rsa_keys = RSA.generate(4096)
    rsa_prv = rsa_keys.export_key('PEM', passphrase=seed[32:])
    rsa_pub = rsa_keys.public_key().export_key()
    # generate user id
    u_id = base64.b64encode(SHA256.new(seed.encode()+username.encode()+id_salt).digest()).decode('ascii')
    # create requiste directories
    key_dir = os.path.join(target_dir, 'keys')
    dat_dir = os.path.join(target_dir, 'data')
    os.mkdir(key_dir)
    os.mkdir(dat_dir)
    os.mkdir(os.path.join(target_dir, 'logs'))
    os.mkdir(os.path.join(dat_dir, 'archives'))
    # save rsa keys
    with open(os.path.join(key_dir, 'public.pem'), 'wb') as pub, open(os.path.join(key_dir, 'private.pem'), 'wb') as prv:
        pub.write(rsa_pub)
        prv.write(rsa_prv)
    # save aes keys
    with open(os.path.join(key_dir, 'symetric.pem'), 'wb') as key:
        key.write(format_pem(enc_aes_key, 'ENCRYPTED AES KEY'))
    # encrypt and save user data
    with open(os.path.join(dat_dir, 'info.usr'), 'wb') as i:
        if proxy:
            has_proxy = 'Y'
        else:
            has_proxy = 'N'
        user_dat = f'{u_id}{seed[32:]}{has_proxy}{username}'.encode()
        i.write(write_secure_data(user_dat, aes_key))
    # set and save preferences (to be expaneded in the future)
    prefs = {'theme': 'light', 'notification': 'boop.wav', 'msg-font': 'Helvetica', 'date-format': 'mm/dd/yy', 'erase-limit': 0}
    with open(os.path.join(dat_dir, 'prefs.json'), 'w') as p:
        json.dump(prefs, p)
    # create user's contact information file
    # saving this info is obviously not nessecary, but it's just there to generate some data to put in the contacts file
    contact_dat = write_secure_data(json.dumps({u_id: {'Username': username, 'Address': '127.0.0.1'}}).encode(), aes_key)
    with open(os.path.join(dat_dir, 'contacts.txt'), 'wb') as c:
        c.write(contact_dat)
    # encrypt and save the information for the HIDE proxy for proxy mode
    if proxy:
        address, port = proxy
        proxy_dir = os.path.join(dat_dir, 'proxy')
        os.mkdir(proxy_dir)
        # encrypt and save proxy configuration (set default) 
        config_dat = write_secure_data(json.dumps({'address': address, 'port': port, 'allow':'all', 'white-list':[], 'black-list':[]}).encode(), aes_key)
        with open(os.path.join(proxy_dir, 'prox_config.dat'), 'wb') as conf:
            conf.write(config_dat)
    # encrypt and save primary node data if provided
    if node:
        node_name, node_address = node
        node_iv = secrets.token_bytes(16)
        node_dat = write_secure_data(json.dumps({node_name: node_address}).encode(), aes_key)
        with open(os.path.join(dat_dir, 'nodes.dat'), 'wb') as n:
            n.write(node_dat)



class MainFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=(15, 0))
        self.using_proxy = BooleanVar(value=False)
        self.account_type = StringVar(value='registered')
        # build GUI
        ttk.Label(self, text='Welcome to HIDE!', padding=(0, 20), font='bold').grid(row=0, column=0)
        # determine user's login information
        ttk.Label(self, text='Login Information:').grid(row=1, column=0)
        login_frame = ttk.Frame(self, padding=(0, 10))
        self.username = ttk.Entry(login_frame)
        self.password = ttk.Entry(login_frame, show='•')
        self.confirm_pw = ttk.Entry(login_frame, show='•')
        entries = [(self.username, 'Username: '), ( self.password, 'Password: '), (self.confirm_pw, 'Confirm: ')]
        for i in range(3):
            ttk.Label(login_frame, text=entries[i][1]).grid(row=i, column=0)
            entries[i][0].grid(row=i, column=1)
        login_frame.grid(row=2, column=0)
        # determine if the user is using a "registered" or "local" account
        radio_frame = ttk.Frame(self)
        ttk.Radiobutton(radio_frame, text='Registered (recommended)', variable=self.account_type, value='registered').grid(row=0, column=0)
        ttk.Radiobutton(radio_frame, text='Local', variable=self.account_type, value='local').grid(row=0, column=1)
        radio_frame.grid(row=3, column=0)
        self.node_frame = ttk.Frame(self)
        self.node_name = ttk.Entry(self.node_frame)
        self.node_addr = ttk.Entry(self.node_frame)
        ttk.Label(self.node_frame, text='Node Name:').grid(row=0, column=0)
        ttk.Label(self.node_frame, text='Node Address:').grid(row=1, column=0)
        self.node_name.grid(row=0, column=1)
        self.node_addr.grid(row=1, column=1)
        self.node_frame.grid(row=4, column=0) 
        # determine where the user would like to install HIDE to
        ttk.Label(self, text='Where would you like to store HIDE?').grid(row=5, column=0)
        path_frame = ttk.Frame(self)
        self.hide_dir = ttk.Entry(path_frame, state='readonly')
        self.hide_dir.grid(row=1, column=0)
        ttk.Button(path_frame, text='Select', command= lambda: self.get_path(self.hide_dir)).grid(row=1, column=1)
        path_frame.grid(row=7, column=0)
        # determine where the user would like to put their seed file
        ttk.Label(self, text='Where would you like to store your seed file?').grid(row=8, column=0)
        seed_frame = ttk.Frame(self)
        self.seed_dir = ttk.Entry(seed_frame)
        self.seed_dir.grid(row=1, column=0)
        ttk.Button(seed_frame, text='Select', command=lambda: self.get_path(self.seed_dir)).grid(row=1, column=1)
        seed_frame.grid(row=9, column=0)
        # determine if the user would like to use a proxy, and if so what address and port to use
        ttk.Checkbutton(self, text='Use a Proxy?', variable=self.using_proxy, onvalue=True, offvalue=False).grid(row=10, column=0)
        self.proxy_frame = ttk.Frame(self)
        self.proxy_addr = ttk.Entry(self.proxy_frame)
        self.proxy_port = ttk.Entry(self.proxy_frame)
        ttk.Label(self.proxy_frame, text='Proxy Address:').grid(row=0, column=0)
        ttk.Label(self.proxy_frame, text='Proxy Port:').grid(row=1, column=0)
        self.proxy_addr.grid(row=0, column=1)
        self.proxy_port.grid(row=1, column=1)
        # final button
        ttk.Button(self, text='Install', command=self.install).grid(row=12, column=0)
        self.await_change()
    
    def install(self):
        # get basic install info
        uname = self.username.get()
        pw = self.password.get()
        seed = self.seed_dir.get()
        # valdiate username
        if len(uname) < 6:
            messagebox.showerror('Error', 'Please ensure your username is at least 6 characters long')
            return
        for char in '/\\~. ':
            if char in uname:
                messagebox.showerror('Error', 'Your username contains illegal characters')
        # validate password
        if pw != self.confirm_pw.get():
            messagebox.showerror('Error', 'Your password does not match the confirmation')
            return
        if len(pw) < 12:
            messagebox.showerror('Error', 'Please ensure your password is at least 12 characters long')
        has_upper = False
        has_lower = False
        has_digit = False
        has_other = False
        valid = False
        for char in pw:
            if has_upper and has_lower and has_digit and has_other:
                valid = True
                break
            if char.isupper():
                has_upper = True
            elif char.islower():
                has_lower = True
            elif char.isdigit():
                has_digit = True
            else:
                has_other = True
        if not valid:
            messagebox.showerror('Error', 'Please ensure your password has at least one of each of the following:\nUppercase Letters\nLowercase Letters'\
                                          '\nNumbers\nSpecial Characters')
            return
        seed_file = generate_seed_file(seed)
        options = {'username': uname, 'password': pw, 'seed_file': seed_file}
        # validate proxy details if provided
        if self.using_proxy.get(): 
            prox_addr, prox_port = self.using_proxy.get()
            if not self.validate_ip(prox_addr):
                messagebox.showerror('Error', 'Invalid Proxy IP')
                return
            elif not prox_port.isdigit() or int(prox_port) < 1024 or int(prox_port) > 65535:
                messagebox.showerror('Error', 'Please ensure your proxy port is a valid integer between 1024 and 65535')
                return
            options['proxy'] = (prox_addr, prox_port)
        if self.account_type.get() == 'register':
            node_addr = self.node_addr.get()
            node_name = self.node_name.get()
            if not self.validate_ip(self.node_addr):
                messagebox.showerror('Error', 'Invalid Node IP')
                return
            options['node'] = (node_addr, node_name)
        hide_dir = self.hide_dir.get()
        options['target_dir'] = os.path.join(hide_dir, 'user')
        with zipfile.ZipFile('HIDE.zip') as hide:
            hide.extractall(hide_dir)

        os.mkdir(options['target_dir'])
        create_user(**options)
        messagebox.showinfo('Success', 'Your account was created and installed to the target directory succesfully')
        exit()

            
    def validate_ip(self, addr: str):
        octets = addr.split('.')
        if len(octets) != 4:
            return False
        for i in octets:
            if not i.isdigit() or int(i) > 255:
                return False
        return True

    def get_path(self, entry: ttk.Entry):
        path = filedialog.askdirectory()
        entry.config(state='normal')
        entry.delete(0, END)
        entry.insert(0, path)
        entry.config(state='readonly')

    # changes widgets based on the account_type, and using_proxy variables 
    def await_change(self):
        if self.account_type.get() == 'registered':
            self.node_frame.grid(row=4, column=0)
        else:
            self.node_frame.grid_forget()
        if self.using_proxy.get():
            self.proxy_frame.grid(row=11, column=0)
        else:
           self.proxy_frame.grid_forget()
        self.after(10, self.await_change) 

root = ThemedTk(theme='breeze')
root.title('Install HIDE')
root.resizable(False, False)
MainFrame(root).grid(row=0, column=0)
root.mainloop()
