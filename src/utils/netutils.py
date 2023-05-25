import socket
import base64
import time
import random
import logging
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from datetime import datetime

from utils import userutils as uu

class HideSocket:
    def __init__(self, user: uu.User, initiate:bool=False, addr: str = '', port=22800):
        self.user = user
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tunnel = None
        log_name = datetime.now().strftime("%d-%m-%y.log")
        if os.path.exists(os.path.join('logs', log_name)):
            file_mode = 'a+'
        else:
            file_mode = 'w' 
            
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s]: %(message)s', filename=os.path.join('logs', log_name), filemode=file_mode)
        self.logger = logging.getLogger()
        if initiate:
            # start a connection
            self.sock.connect((addr, port))
        else:
            # await a connection
            self.sock.bind((addr, port))
            self.sock.listen()
            self.sock, addr = self.sock.accept()
            self.handle_conn(self.recv_msg())

    # sends a message of any size
    def send_msg(self, msg: bytes):
        # make every 1024th byte '-' to keep the reciever receiving until every byte has been recieved
        msg = b'-'.join(msg[i:i+1023] for i in range(0, len(msg), 1023))
        self.sock.send(msg) 

    # recieves a message of any size
    def recv_msg(self):
        msg = b''
        receiving = True
        while receiving:
            try:
                packet = self.sock.recv(1024)
                if packet[-1] == 45:
                    msg += packet[:-1]
                else:
                    msg += packet
                    receiving = False
            except (TypeError, IndexError, ConnectionResetError): # can only be raised if there's no data being transmitted 
                return None
        return msg    
    
    # this method should only be used "initiate" is false
    def handle_conn(self, msg: bytes):
        msg = msg.decode()
        if msg != b'00':
            match msg[:2]:
                case '01':
                    self.send_msg(b'10')
                case '02':
                    # send user's public key and establish a secure tunnel
                    peer_key = RSA.import_key(base64.b64decode(msg[2:].encode('ascii')))
                    rsa_cipher = PKCS1_v1_5.new(peer_key)
                    self.logger.info(f'Connection Established With {self.sock.getpeername()[0]}')
                    self.logger.info('Sending Public Key...')
                    self.send_msg(f'20{base64.b64encode(self.user.rsa_pub.export_key("DER")).decode("ascii")}'.encode())
                    logging.info('Public Key Sent')
                    self.logger.info('Awaiting AES Key...')
                    # receive and decrypt AES key
                    aes_key =  self.user.decrypt_rsa(self.recv_msg())
                    if aes_key != b'ERROR':
                        self.logger.info('AES Key Recieved')
                        self.logger.info('Sending local username and ID...')
                        # encrypt and send local username and ID
                        self.send_msg(uu.write_secure_data(f'00{self.user.name}~{self.user.u_id}'.encode(), aes_key))
                        self.logger.info('Sent local username and ID')
                        self.logger.info('Awaiting peer\'s username and ID...')
                        # receive and decrypt peer's username and ID
                        msg = uu.read_secure_data(self.recv_msg(), aes_key).decode()
                        peer_name, peer_id = msg[2:].split('~')
                        # determine which ports to communicate over
                        self.logger.info('Received peer\'s username and ID')
                        self.logger.info('Sending local listener port...')
                        incoming = random.randint(50000, 60000)
                        while incoming in self.user.active_ports:
                            incoming = random.randint(50000, 60000)
                        self.user.active_ports.append(incoming)
                        self.send_msg(rsa_cipher.encrypt(incoming.to_bytes(2, 'big')))
                        self.logger.info('Sent local listener port')
                        self.logger.info('Awaiting peer\'s listner port...')
                        outgoing = self.user.decrypt_rsa(self.recv_msg())
                        if outgoing != b'ERROR':
                            outgoing = int().from_bytes(outgoing, 'big')
                            self.logger.info('Recieved peer\'s listener port')
                            self.logger.info('Establishing HIDE Tunnel')
                        else:
                            return None
                        peer_addr = self.sock.getpeername()[0]
                        self.sock.shutdown(socket.SHUT_RDWR)
                        self.sock.close()
                        self.tunnel = HideTunnel(self.user, self.logger, peer_name, peer_id, peer_key, peer_addr, incoming, outgoing, aes_key)
                    else:
                        self.logger.error('AES Key Could Not Be Read')
                case _:
                    self.send_msg(b'01BAD REQUEST')

    # the following methods should only be used if "initiate" is true
    def ping(self):
        self.sock.send('01')
        try:
            response = self.recv_msg()
            if response == '10':
                return True
            return False
        except (ConnectionError, ConnectionRefusedError):
            return False
    
    def establish_tunnel(self):
        self.logger.info(f'Attempting to establish connection with {self.sock.getpeername()[0]}')
        self.send_msg(f'02{base64.b64encode(self.user.rsa_pub.export_key("DER")).decode("ascii")}'.encode())
        response = self.recv_msg().decode()
        if response[:2] == '20': # messaging request was accepted
            # create cipher from peer's public key
            self.logger.info(f'Connection Established With {self.sock.getpeername()[0]}')
            self.logger.info('Sending Public Key...')
            peer_key = RSA.import_key(base64.b64decode(response[2:].encode('ascii')))
            rsa_cipher = PKCS1_v1_5.new(peer_key)
            # generate and send AES key
            self.logger.info('Peer\'s public key received')
            self.logger.info('Sending AES key...')
            aes_key = uu.secrets.token_bytes(32)
            self.send_msg(rsa_cipher.encrypt(aes_key))
            self.logger.info('AES Key Sent\nAwaiting peer\'s username and ID...')
            msg = uu.read_secure_data(self.recv_msg(), aes_key).decode()
            # receive and decrypt peer's username and ID
            if msg[:2] == '00':
                peer_name, peer_id = msg[2:].split('~')
                self.logger.info('Peer\'s username and ID received.')
                self.logger.info('Sending local username and ID...')
                self.send_msg(uu.write_secure_data(f'00{self.user.name}~{self.user.u_id}'.encode(), aes_key))
            else:
                return None
            # determine ports to communicate over
            self.logger.info('Local username and ID sent')
            self.logger.info('Awaiting peer\'s listener port...')
            outgoing = self.user.decrypt_rsa(self.recv_msg())
            if outgoing != b'ERROR':
                outgoing = int().from_bytes(outgoing, 'big')
                self.logger.info('Peer\'s listening port received.')
                self.logger.info('Sending local listener port...')
                incoming = random.randint(50000, 60000)
                while incoming in self.user.active_ports:
                    incoming = random.randint(50000, 60000)
                self.user.active_ports.append(incoming)
                self.send_msg(rsa_cipher.encrypt(incoming.to_bytes(2, 'big')))
                self.logger.info('Sent local listener port, establishing HIDE Tunnel...')
                peer_addr = self.sock.getpeername()[0]
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                return HideTunnel(self.user, self.logger, peer_name, peer_id, peer_key, peer_addr, incoming, outgoing, aes_key, True)
            else:
                self.logger.error('AES Key could not be read')
                return None
        else: # messaging request was declined
            self.logger.error('Connection could not be established.')
            return None


# A secure tunnel that encrypts and decrypts user messages
class HideTunnel:
    def __init__(self, user: uu.User, logger: logging.Logger, peer_name: str, peer_id: str, peer_key, peer_addr: str, incoming: str, outgoing: str, aes_key: bytes, initiating: bool=False):
        self.user = user
        self.peer_name = peer_name
        self.peer_id = peer_id
        self.peer_key = peer_key
        self.aes_key = aes_key
        self.history = ['Connection Established\n----------------------']
        self.logger = logger
        # establish ports to communicate over
        if initiating: 
            # allow peer time to open a new socket
            time.sleep(0.25)
            self.outgoing = HideSocket(user, True, addr=peer_addr, port=outgoing)
            self.outgoing.send_msg(b'00')
            self.incoming = HideSocket(user, addr='', port=incoming)
        else:
            self.incoming = HideSocket(user, addr='', port=incoming)
            time.sleep(0.25)
            self.outgoing = HideSocket(user, True, addr=peer_addr, port=outgoing)
            self.outgoing.send_msg(b'00')
        
        self.logger.info(f'HIDE tunnel established with: {self.peer_name} (ID: {self.peer_id})')
        self.logger.info(f'Listening on port: {incoming}. Sending on port: {outgoing}')
        self.user.encrypt_logs()
    
    def send_secure_msg(self, msg: str):
        # create a digital signature for the message 
        self.history.append(f'{self.user.name}: {msg}')
        msg_hash = SHA256.new(msg.encode())
        signature = self.user.sign_msg(msg_hash)
        msg = uu.write_secure_data(msg.encode(), self.aes_key)
        self.outgoing.send_msg(f'{base64.b64encode(signature).decode()}~{msg.decode()}'.encode())
        
    def recv_secure_msg(self) -> str:
        msg = self.incoming.recv_msg()
        if msg:
            signature, msg = msg.decode().split('~')
            msg = uu.read_secure_data(msg.encode(), self.aes_key).decode()
            # verify authenticity of the message and it's sender
            pkcs1_15.new(self.peer_key).verify(SHA256.new(msg.encode()), base64.b64decode(signature.encode()))
            self.history.append(f'{self.peer_name}: {msg}')
            return msg
        else: # catch a closed connection
            return None

    # terminates the connection, does nothing if the connection has already been terminated on the other end 
    def terminate(self):
        try:
            self.incoming.sock.shutdown(socket.SHUT_RDWR)
            self.outgoing.sock.shutdown(socket.SHUT_RDWR)
            self.incoming.sock.close()
            self.outgoing.sock.close()
        except Exception(): 
            pass            

