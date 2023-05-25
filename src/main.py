import os
import json
import threading
import base64
import shutil

from tkinter import ttk
from tkinter import messagebox
from tkinter import StringVar, BooleanVar, Variable
from tkinter import Listbox, Text, ACTIVE
from ttkthemes import ThemedTk

from playsound import playsound

from time import sleep

from sys import exit

from utils import userutils as uu
from utils import netutils as nu

# a daemon to create a HIDE tunnel
class TunnelBuilder(threading.Thread):
    def __init__(self, user: uu.User, target_addr: str, parent: ttk.Frame, msg_nav: ttk.Notebook):
        super().__init__(daemon=True)
        self.user = user
        self.target_addr = target_addr
        self.parent = parent
        self.msg_nav = msg_nav

    def run(self):
        # try to create a tunnel with a desired IP address
        # clear error text 
        raise_error(self.parent, '', self.parent.err_row)
        try:
            sock = nu.HideSocket(self.user, True, self.target_addr)
            tunnel = sock.establish_tunnel()
            # create a messaging frame from the newly established tunnel
            if tunnel:
                # prevent duplicate windows by ensuring the user isn't already chatting with the peer
                if tunnel.peer_id in self.user.active_partners:
                    tunnel.incoming.sock.close()
                    tunnel.outgoing.sock.close()
                    raise_error(self.parent, 'Already chatting with that user', self.parent.err_row)
                else:
                    self.user.active_partners.append(tunnel.peer_id)
                    msg_frame = MessageFrame(self.msg_nav, self.user, tunnel)
                    msg_frame.grid(row=0, column=0)
                    self.msg_nav.add(msg_frame, text=tunnel.peer_name)
                    self.msg_nav.select(len(self.msg_nav.tabs())-1)
        except (ConnectionError, ConnectionRefusedError, OSError):
            raise_error(self.parent, 'Could Not Connect', self.parent.err_row)
            

# a daemon to listen for HIDE tunnels
class TunnelListener(threading.Thread):
    def __init__(self, user: uu.User, msg_nav:ttk.Notebook):
        super().__init__(daemon=True)
        self.user = user
        self.msg_nav = msg_nav
    
    def run(self):
        self.await_msg()

    # recursively awaits new tunnels and displays them
    def await_msg(self):
        sock = nu.HideSocket(self.user)
        if sock.tunnel:
            self.msg_nav.add(MessageFrame(self.msg_nav, self.user, sock.tunnel), text=sock.tunnel.peer_name)
            playsound(os.path.join('..', 'media', 'notifications', self.user.prefs['notification']))
        self.await_msg()


# frames for the navigation bar
class AddContact(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, user:uu.User):
        super().__init__(parent, padding=(0, 5))
        self.user = user
        self.config(height=225, width=250)
        ttk.Label(self, text='Add Contact:', font='bold').grid(row=0, column=0)
        entry_frame = ttk.Frame(self, padding=(20, 20))
        ttk.Label(entry_frame, text='Username:').grid(row=0, column=0)
        self.p_name = ttk.Entry(entry_frame)
        self.p_name.grid(row=1, column=0)
        ttk.Label(entry_frame, text='ID:').grid(row=2, column=0)
        self.p_id = ttk.Entry(entry_frame)
        self.p_id.grid(row=3, column=0) 
        ttk.Label(entry_frame, text='IP Address:').grid(row=4, column=0)
        self.p_addr = ttk.Entry(entry_frame)
        self.p_addr.grid(row=5, column=0)
        entry_frame.grid(row=1, column=0)
        ttk.Button(self, text='Add', command=self.add_contact).grid(row=2, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=3, column=0)

    def add_contact(self):
        # validate ID
        peer_id = self.p_id.get()
        try:
            # at once check if the given ID is base64-valid and 32-bits long
            if len(base64.b64decode(self.peer_id)) != 32:
                raise ValueError()
        except Exception:
            raise_error(self, 'Invalid ID', 3)
            return
        # validate IP address (for now this only accepts IPv4 addresses)
        ip_addr = self.p_addr.get()
        octets = ip_addr.split('.')
        for i in octets:
            if not i.isdigit() or int(i) > 255:
                raise_error(self, 'Invalid IP', 3)
                return
        self.user.modify_contacts('add', self.peer_id, self.p_name.get(), self.ip_addr)


# a frame for people who don't like chat commands...
class ChatFunctions(ttk.Frame):
    def __init__(self, parent:ttk.Notebook, user:uu.User, msg_nav:ttk.Notebook):
        super().__init__(parent)
        self.user = user
        self.msg_nav = msg_nav
        # build GUI
        ttk.Label(self, text='Chat Functions:', font='bold', padding=(0, 5)).grid(row=0, column=0)
        btn_frame = ttk.Frame(self, padding=(60, 30))
        ttk.Button(btn_frame, text='Archive Chat', padding=(0, 10), command=self.archive).grid(row=1, column=0)
        ttk.Button(btn_frame, text='Add Contact', padding=(0, 10), command=self.add_usr).grid(row=2, column=0)
        ttk.Button(btn_frame, text='Disconnect', padding=(0, 10), command=self.end_connection).grid(row=3, column=0)
        btn_frame.grid(row=1, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=2, column=0)

    def archive(self):
        msg_box = self.get_msg()
        if msg_box:
            msg_box.archive()

    def add_usr(self):
        msg_box = self.get_msg()
        if msg_box:
            msg_box.add_usr()

    def end_connection(self):
        msg_box = self.get_msg()
        if msg_box:
            msg_box.end_connection()

    # verifies if the currently selected frame is a messaging frame by checking if it has a tunnel and returns the frame if it does
    def get_msg(self):
        msg_box = self.msg_nav.nametowidget(self.msg_nav.select())
        if hasattr(msg_box, 'tunnel'): 
            return msg_box
        else:
            raise_error(self, 'Not in a chat window', 2)
            return None
        

# a frame to establish connections with peers that aren't in the user's contact list
class ConnectFrame(ttk.Frame):
    def __init__(self, parent:ttk.Notebook, user: uu.User, msg_nav: ttk.Notebook()):
        super().__init__(parent, padding=(0, 6))
        self.user = user
        self.msg_nav = msg_nav
        self.err_row = 7 # this is referenced when an outside class tries to raise an error here
        use_node = BooleanVar(self, value=False)
        ttk.Label(self, text='Connect:', font='bold').grid(row=0, column=0)
        entry_frame = ttk.Frame(self, padding=(17, 0))
        ttk.Label(entry_frame, text='IP Address:', padding=(0, 10)).grid(row=0, column=0)
        self.addr = ttk.Entry(entry_frame)
        self.addr.grid(row=1, column=0)
        ttk.Label(entry_frame, text='ID (Optional):', padding=(0, 10)).grid(row=2, column=0)
        self.p_id = ttk.Entry(entry_frame) # "p_id" means Peer ID
        self.p_id.grid(row=3, column=0)
        entry_frame.grid(row=1, column=0)
        node_frame = ttk.Frame(self)
        for i in (self.addr, self.p_id):
            i.bind('<Return>', self.connect)
        ttk.Label(node_frame, text='Connect via node:', padding=(0, 30)).grid(row=0, column=0)
        ttk.Checkbutton(node_frame, variable=use_node, onvalue=True, offvalue=False).grid(row=0, column=1)
        node_frame.grid(row=3, column=0)
        ttk.Button(self, text='Connect', padding=(0, -20), command=self.connect).grid(row=4, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=5, column=0)
    
    def connect(self, event=None):
        # ensure the user is not already in contact with the target peer
        TunnelBuilder(self.user, self.addr.get(), self, self.msg_nav ).start()


# a frame to edit the information of a given contact
class ContactEditFrame(ttk.Frame):
    def __init__(self, parent: ThemedTk, contact_frame: ttk.Notebook, name: str, contact: dict):
        super().__init__(parent)
        self.parent = parent
        self.contact = contact
        self.contact_frame = contact_frame
        self.user = contact_frame.user
        ttk.Label(self, text='Edit Contact').grid(row=0, column=0)
        entry_frame = ttk.Frame(self)
        self.entries = {'Name:': ttk.Entry(entry_frame), 'IP Address:': ttk.Entry(entry_frame), 'ID:': ttk.Entry(entry_frame)}
        values = {'Name:': name, 'IP Address:': contact['addr'], 'ID:': contact['id']}
        row_count = 0
        for i in self.entries:
            ttk.Label(entry_frame, text=i).grid(row=row_count, column=0)
            self.entries[i].insert(0, values[i])
            self.entries[i].grid(row=row_count, column=1)
            row_count += 1
        entry_frame.grid(row=1, column=0)
        ttk.Button(self, text='Update', command = self.modify).grid(row=2, column=0)
        ttk.Button(self, text='Delete', command = self.remove).grid(row=3, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=4, column=0)

    def remove(self):
        self.user.modify_contacts('del', self.contact['id'])
        self.parent.destroy()
            
    def modify(self):
        # remove old entry if the contact's ID has changed
        if self.entries['ID:'].get() != self.contact['id']:
            self.del_user()
        self.user.modify_contacts('add', self.entries['ID:'].get(), self.entries['Name:'].get(), self.entries['IP Address'].get())
        self.parent.destroy()


# lists the users contacts and allows them to communicate with a selected contact
class ContactFrame(ttk.Frame):
    def __init__(self, parent:ttk.Notebook, user:uu.User, msg_nav:ttk.Notebook):
        super().__init__(parent, padding=(25, 6))
        self.user = user
        self.msg_nav = msg_nav
        self.err_row = 4 # this is referenced when an outside class tries to raise an error here
        ttk.Label(self, text='Contacts:', font='bold').grid(row=0, column=0)
        self.usr_contacts = Listbox(self)
        self.update_contacts()
        theme_style(self.user, self.usr_contacts)
        self.usr_contacts.grid(row=1, column=0)
        ttk.Button(self, text='Connect', command=self.connect).grid(row=2, column=0)
        ttk.Button(self, text='Edit', command=self.edit).grid(row=3, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=4, column=0)

    def connect(self):
        # clear error box
        raise_error(self, '', 4)
        # attempt to establish connection to the currently selected user
        username = self.usr_contacts.get(ACTIVE)
        if username == self.user.name:
            raise_error(self, 'Can\'t Connect', 4)
        TunnelBuilder(self.user, self.contact_info[self.usr_contacts.get(ACTIVE)]['addr'], self, self.msg_nav).start()

    def edit(self):
        name = self.usr_contacts.get(ACTIVE)
        edit_win = ThemedTk(theme={'light': 'breeze', 'dark': 'equilux'}[self.user.prefs['theme']])
        edit_win.title(name)
        edit_win.resizable(False, False)
        ContactEditFrame(edit_win, self, name, self.contact_info[self.usr_contacts.get(ACTIVE)]).grid(row=0, column=0)
        edit_win.mainloop()

    def update_contacts(self): 
        users = []
        self.contact_info = {}
        # create a dictonary of contact info using usernames as the keys and display all of said usernames
        for i in self.user.contacts:
            user = self.user.contacts[i]
            username = user['Username']
            # if a user has multiple contacts with the same username, the last 5 characters of their id
            # get added to their name to distinguish them
            if username in self.contact_info:
                username += f' ({i[39:]})'
            self.contact_info[username] = {'id': i}
            if 'Address' in user.keys():
                self.contact_info[username]['addr'] = user['Address']
            users.append(username)
        usernames = Variable(self, value=users)
        self.usr_contacts.config(listvariable=usernames)
        self.usr_contacts.grid(row=1, column=0)
        self.after(150, self.update_contacts)


# a frame to allow the user to set UI preferences 
class SettingsFrame(ttk.Frame):
    def __init__(self, parent:ThemedTk, user: uu.User, main_win: ThemedTk):
        super().__init__(parent)
        self.user = user
        self.main_win = main_win
        ttk.Label(self, text='Theme changes will restart HIDE', foreground='#d9534f').grid(row=0, column=0)
        # theme selection
        ttk.Label(self, text='Theme:').grid(row=1, column=0)
        self.usr_theme = StringVar(self, value=user.prefs['theme'])
        themes = ('dark', 'light')
        ttk.OptionMenu(self, self.usr_theme, self.usr_theme.get(), *themes).grid(row=2, column=0)
        # notification selection
        ttk.Label(self, text='Notification Sound').grid(row=3, column=0)
        self.usr_notif = StringVar(self, value=user.prefs['notification'])
        notifs = []
        for i in os.listdir(os.path.join('..', 'media', 'notifications')):
            if i.endswith('.wav') or i.endswith('.mp3'):
                notifs.append(i)
        ttk.OptionMenu(self, self.usr_notif, self.usr_notif.get(), *notifs).grid(row=4, column=0)
        # font selection
        ttk.Label(self, text='Message Font:').grid(row=5, column=0)
        self.msg_font = ttk.Entry(self)
        self.msg_font.insert(0, user.prefs['msg-font'])
        self.msg_font.grid(row=6, column=0)
        # final buttons to tie it together
        ttk.Button(self, text='Confirm', command=self.update_prefs).grid(row=7, column=0)
        ttk.Button(self, text='Cancel', command=self.master.destroy).grid(row=8, column=0)

    def update_prefs(self):
        old_theme = self.user.prefs['theme']
        self.user.update_prefs(self.usr_theme.get(), self.usr_notif.get(), self.msg_font.get(), self.user.prefs['date-format'], self.user.prefs['erase-limit'])
        self.master.destroy()
        # redraw main window if the theme is changed
        if old_theme != self.user.prefs['theme']:
            os.chdir('../')
            self.main_win.destroy()
            self.main_win.__init__({'dark': 'equilux', 'light': 'breeze'}[self.user.prefs['theme']])

# a frame that builds archive/log viewers
class LogArchiveBuilder(ttk.Frame):
    def __init__(self, user: uu.User, parent: ThemedTk, msg_nav: ttk.Notebook):
        super().__init__(parent)
        # initalize frame and variables
        self.user = user
        self.msg_nav = msg_nav
        self.archive_type = StringVar(self, 'messages')
        self.contacts = os.listdir(os.path.join('data', 'archives'))
        if len(self.contacts) == 0:
            self.contacts = ['n/a']
        self.peer = StringVar(self, self.contacts[0])
        # build GUIs
        ttk.Label(self, text='View Message Archives/Activity Logs').grid(row=0, column=0)
        # a frame to select the archive type
        type_frame = ttk.Frame(self)
        ttk.Label(type_frame, text='Archive Type:').grid(row=0, column=0)
        ttk.OptionMenu(type_frame, self.archive_type, 'messages', 'messages', 'logs', command=self.update_archives).grid(row=0, column=1)
        type_frame.grid(row=1, column=0)
        # a frame to select the chatting partner to look for archives under
        self.user_frame = ttk.Frame(self)
        ttk.Label(self.user_frame, text='Peer:').grid(row=0, column=0)
        ttk.OptionMenu(self.user_frame, self.peer, self.contacts[0], *self.contacts, command=self.update_archives).grid(row=0, column=1)
        self.user_frame.grid(row=2, column=0)
        ttk.Label(self, text='Archives:').grid(row=3, column=0)
        self.archives = Listbox(self)
        self.archives.grid(row=4, column=0)
        theme_style(self.user, self.archives)
        self.go_button = ttk.Button(self, text='Go', command=self.submit)
        self.go_button.grid(row=5, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=0, column=6)
        self.update_archives()
        
    # update viewable archives based on type/peer 
    def update_archives(self, event=None):
        # enable go button in case it's disabled
        self.go_button.config(state='normal')
        if self.archive_type.get() == 'messages':
            self.user_frame.grid(row=2, column=0)
            if self.contacts[0] == 'n/a':
                self.archives.config(listvariable=Variable(self, ['No archives to show!']))
                self.go_button.config(state='disabled')
                return
            archives = []
            for i in os.listdir(os.path.join('data', 'archives', self.peer.get())):
                day, month, year, time = i.removesuffix('.txt').split('-')
                archives.append(f'{self.user.prefs["date-format"].replace("dd", str(day)).replace("mm", month).replace("yy", year)} {time[:2]}:{time[2:]}')
            self.archives.config(listvariable=Variable(self, archives))
        else:
            logs = []
            log_list = os.listdir('logs')
            self.user_frame.grid_forget()
            if len(log_list) == 0:
                self.archives.config(listvariable=Variable(self, ['No archives to show!']))
                self.go_button.config(state='disabled')
                return
            for i in log_list:
                day, month, year = i.removesuffix('.log').split('-')
                logs.append(self.user.prefs['date-format'].replace('dd', day).replace('mm', month).replace('yy', year).replace('-', '/'))
            self.archives.config(listvariable=Variable(self, logs))

    def submit(self):
        # clear error message
        raise_error(self, '', 6)
        archive_name = self.archives.get(ACTIVE)
        date = self.user.format_date(archive_name)
        if self.archive_type.get() == 'messages':
            args = (self.msg_nav, self.user, 'messages', date, self.peer.get())
        else:
            args = (self.msg_nav, self.user, 'logs', date)
        try:
            self.msg_nav.add(LogArchiveFrame(*args), text=archive_name)
            self.msg_nav.select(len(self.msg_nav.tabs())-1)
            self.master.destroy()
        except ValueError:
            raise_error(self, 'Archive could not be read!', 6)
       

# a frame that displays messaging archives and logs
class LogArchiveFrame(ttk.Frame):
    def __init__(self, parent:ttk.Notebook, user: uu.User, archive_type: str, date: str, peer: str = None):
        # initalize frame and decrypt the requested archive/log
        super().__init__(parent)
        self.user = user
        if archive_type == 'logs':
            archive = self.user.decrypt_logs(date)
        elif archive_type == 'messages':
            archive = self.user.decrypt_archives(peer, date)
        # build GUI
        scroll = ttk.Scrollbar(self, orient='vertical')
        self.log = Text(self, width=145, height=40, font=(self.user.prefs['msg-font'], 9), yscrollcommand=scroll.set)
        self.log.insert(1.0, archive)
        self.log.config(state='disabled')
        self.log.grid(row=0, column=0)
        scroll.config(command = self.log.yview)
        scroll.grid(row=0, column=1, columnspan=2)
        ttk.Button(self, text='Exit', command=self.destroy).grid(row=1, column=0)
        theme_style(user, self.log)

        
# a frame that shows information about HIDE and the user
class AboutFrame(ttk.Frame):
    def __init__(self, user: uu.User, parent: ThemedTk):
        super().__init__(parent)
        ttk.Label(self, text='User:', font='bold').grid(row=0, column=0)
        user_info = ttk.Frame(self)
        ttk.Label(user_info, text='Username:').grid(row=0, column=0)
        ttk.Label(user_info, text=user.name).grid(row=0, column=1)
        ttk.Label(user_info, text='ID:').grid(row=1, column=0)
        ttk.Label(user_info, text=user.u_id).grid(row=1, column=1)
        user_info.grid(row=1, column=0)
        ttk.Label(self, text='HIDE:', font='bold', padding=(0, 10)).grid(row=2, column=0)
        hide_info = ttk.Frame(self)
        ttk.Label(hide_info, text='Version:').grid(row=0, column=0)
        ttk.Label(hide_info, text='v0.1.0').grid(row=0, column=1)
        hide_info.grid(row=3, column=0)


# a frame for menus that don't fit anywhere else
class EtcFrame(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, user: uu.User, msg_nav: ttk.Notebook):
        super().__init__(parent)
        self.user = user
        self.msg_nav = msg_nav
        ttk.Label(self, text='Other Functions:', font='bold', padding=(0, 5)).grid(row=0, column=0)
        btn_frame = ttk.Frame(self, padding=(60, 10))
        ttk.Button(btn_frame, text='Settings', padding=(0, 10), command=lambda: self.call_win(SettingsFrame, {'user': self.user, 'main_win':self.master.master.master})).grid(row=0, column=0)
        ttk.Button(btn_frame, text='Archive Viewer', padding=(0, 5), command=lambda: self.call_win(LogArchiveBuilder, {'user': self.user, 'msg_nav': self.msg_nav})).grid(row=1, column=0)
        ttk.Button(btn_frame, text='About', padding=(0,10), command=lambda: self.call_win(AboutFrame, {'user': user})).grid(row=2, column=0)
        ttk.Button(btn_frame, text='Exit', padding=(0,10), command=exit).grid(row=3, column=0)
        btn_frame.grid(row=1, column=0)
    
    # creates a window with a specified frame
    def call_win(self, frame: ttk.Frame, args: dict):
        win = ThemedTk(theme={'dark': 'equilux', 'light': 'breeze'}[self.user.prefs["theme"]])
        win.title("HIDE")
        win.resizable(False, False)
        args['parent'] = win
        frame(**args).grid(row=0, column=0)
        win.mainloop()        

# just as the name implies, a frame to do messaging activities within
class MessageFrame(ttk.Frame):
    def __init__(self, parent:ttk.Notebook, user: uu.User, tunnel:nu.HideTunnel):
        # initalize frame
        super().__init__(parent)
        self.user = user
        self.tunnel = tunnel
        # build GUI
        self.msg_log = Text(self, state='disabled', width=145, height=40, font=(self.user.prefs['msg-font'], 9))
        theme_style(user, self.msg_log)
        self.msg_log.grid(row=0, column=0)
        send_frame = ttk.Frame(self)
        self.msg_entry = ttk.Entry(self, width=145, font=(self.user.prefs['msg-font'], 10))
        self.msg_entry.bind('<Return>', self.send_msg)
        self.msg_entry.grid(row=1, column=0) 
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=2, column=0)
        t1 = threading.Thread(target=self.await_msg, daemon=True)
        t1.start()
        
    # listens for messages and displays them when received
    def await_msg(self):
        msg = self.tunnel.recv_secure_msg()
        if msg:
            self.update_msg_log(f'{self.tunnel.peer_name}: {msg}\n')
            self.await_msg()
        else: # connection was closed
            # clear and disable message input box
            self.msg_entry.delete(0, 'end')
            self.msg_entry.config(state='disabled')
            self.update_msg_log('CONNECTION TERMINATED!\n-----------------------------------\nAUTOMATICALLY CLOSING IN 10 SECONDS\n')
            for i in range(10):
                sleep(1)
                self.update_msg_log(f'{10-i}\n')
            self.destroy()
            
                    
    # sends a message via the HIDE tunnel and displays it or accepts chat commands and executes them
    def send_msg(self, event=None):
        msg = self.msg_entry.get()
        self.msg_entry.delete(0, 'end')
        # clear error message
        raise_error(self, '', 2)
        # send a message
        if msg != '' and msg[0] != '>':
            self.tunnel.send_secure_msg(msg)
            self.update_msg_log(f'{self.user.name}: {msg}\n')
        # parse chat commands 
        elif msg[0] == '>':
            match msg[1:]:               
                case 'archive':
                    self.archive()
                case 'addusr':
                    self.add_usr()
                case 'disconnect':
                    self.end_connection()
                case _:
                    raise_error(self, 'Unrecognized Command', 2)
    
    # stores encrypted archives of the current conversation
    def archive(self):
        self.user.encrypt_archives(self.tunnel)
        self.update_msg_log('CONVERSATION ARCHIVED\n')

    # adds the current peer to user's contacts
    def add_usr(self):
        self.user.modify_contacts('add', self.tunnel.peer_id, self.tunnel.peer_name, self.tunnel.incoming.sock.getpeername()[0])
        self.update_msg_log(f'ADDED "{self.tunnel.peer_name}" TO CONTACTS\n')

    # writes provided text to the message log
    def update_msg_log(self, message):
        self.msg_log.config(state='normal')
        self.msg_log.insert('end', message)
        self.msg_log.config(state='disabled')

    # terminates the connection
    def end_connection(self):
        self.destroy()
        self.tunnel.terminate()
        

# just as the name implies, a frame to navigate the app
class NavigationBar(ttk.Frame):
    def __init__(self, parent:ThemedTk, user:uu.User, msg_nav: ttk.Notebook()):
        super().__init__(parent)
        # build the top navigation notebook
        top_nav = ttk.Notebook(self)
        connect = ConnectFrame(top_nav, user, msg_nav)
        contacts = ContactFrame(self, user, msg_nav)
        top_nav.add(contacts, text='Contacts')
        top_nav.add(connect, text='Connect')
        top_nav.grid(row=0, column=0)
        # build the bottom navigation bar
        btm_nav = ttk.Notebook(self)
        add_contact = AddContact(btm_nav, user)
        chat_funcs = ChatFunctions(btm_nav, user, msg_nav)
        etc = EtcFrame(btm_nav, user, msg_nav)
        btm_nav.add(chat_funcs, text='Chat')
        btm_nav.add(add_contact, text='Add Contact')
        btm_nav.add(etc, text='Etc.')
        btm_nav.grid(row=1, column=0)
        
# the primary frame that should introduce users to HIDE
class HomeFrame(ttk.Frame):
    def __init__(self, parent:ThemedTk, user:uu.User):
        super().__init__(parent,width=1040, height=580)


# the "topbar" that allows you navigate between messaging partners and the home screen
class MessageNavigator(ttk.Notebook):
    def __init__(self, parent:ThemedTk, user:uu.User):
        super().__init__(parent,width=1040, height=581)
        self.user = user
        TunnelListener(self.user, self).start()

# a simple frame for existing users to login
class PassFrame(ttk.Frame):
    def __init__(self, parent: ThemedTk):
        # initalize frame
        super().__init__(parent, padding=(5, 5))
        with open(os.path.join('data', 'prefs.json')) as p:
            try:
                # check if messages should be destroyed if the password incorrect too many times
                erase_limit = json.load(p)['erase-limit']
                if erase_limit > 0:
                    self.destruct = True
                    self.erase_count = erase_limit
                else:
                    self.destruct = False
                    self.erase_count = 1
            except KeyError:
                messagebox.showerror('Error', 'Prefs file is invalid')
                exit()

        # build GUI
        self.pw = ttk.Entry(self, show='•')
        self.pw.bind('<Return>', self.check_pass)
        self.pw.grid(row=0, column=0)
        ttk.Button(self, text='Login', command=self.check_pass).grid(row=1, column=0)
        self.err_txt = ttk.Label(self, foreground='#d9534f')
        self.err_txt.grid(row=2, column=0)
    
    def check_pass(self, event=None):
        try:
            user = uu.User(self.pw.get())
            self.destroy()
            msg_nav = MessageNavigator(self.master, user)
            nav_bar = NavigationBar(self.master, user, msg_nav)
            nav_bar.grid(row=0, column=0)
            home = HomeFrame(msg_nav, user)
            msg_nav.add(home, text='Home')
            msg_nav.grid(row=0, column=1)
        except uu.DecryptionError:
            if self.destruct:
                self.erase_count -= 1
                if self.erase_count == 0:
                    messagebox.showerror('Data Erasure', 'An incorrect password has been provided too many times!\nAll logs and message archives will be deleted!')
                    # erase all logs and message archives
                    shutil.rmtree(os.path.join('data', 'archives'))
                    shutil.rmtree(os.path.join('logs'))
                    os.mkdir(os.path.join('data', 'archives'))
                    os.mkdir(os.path.join('logs'))
                    # erase user contacts
                    with open(os.path.join('data', 'contacts.txt'), 'w+') as c:
                        pass
                    exit()
                else:
                    err_txt = f'Incorrect Password.\n{self.erase_count} attempt(s) remain.'
            else:
                err_txt = 'Incorrect Password'
            raise_error(self, err_txt, 2)


# The primary window that displays all frames for user activity
class MainWindow(ThemedTk):
    def __init__(self, theme_name):
        # build window
        super().__init__(theme=theme_name)
        self.title("HIDE")
        self.resizable(False, False)
        # log user in 
        if os.path.exists('../user'):
            PassFrame(self).grid(row=0, column=0)
        else:
            messagebox.showerror('Error', 'HIDE Data File not found')
           

def create_entries(entries, entry_frame):
    row_count = 0
    for i in entries:
        ttk.Label(entry_frame, text=i).grid(row=row_count, column=0)
        entries[i].grid(row=row_count, column=1)
        row_count += 1

def raise_error(frame, msg, row):
    frame.err_txt.config(text=msg)
    frame.err_txt.grid(row=row, column=0) 

# get colors for non-themed widgets based on user preferences 
def theme_style(user, widget):
    theme = {'light': 'breeze', 'dark': 'equilux'}[user.prefs['theme']]
    if theme == 'breeze':
        bg = '#FFFFFF'
        fg = '#000000'
        bord = None
    else:
        bg = '#414141'
        fg = '#FFFFFF'
        bord = '#000000'
    theme = {'background': bg, 'foreground': fg}
    if bord:
        theme['highlightcolor'] = bord
        theme['highlightbackground'] = bord
    widget.config(**theme)

os.chdir('user')
theme_dict = {'dark': 'equilux', 'light': 'arc'}
try:
    with open(os.path.join('data', 'prefs.json')) as p:
        theme = json.load(p)['theme']
except (FileNotFoundError, json.JSONDecodeError):
    messagebox.showerror('Error', 'Prefs file is missing or invalid')
if theme in theme_dict:
    MainWindow(theme_dict[theme]).mainloop()
else:
    MainWindow('breeze').mainloop()
