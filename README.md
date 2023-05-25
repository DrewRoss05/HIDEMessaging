# HIDEMessaging
A simple peer-to-peer secure messaging app
<br><br><br>

# Description
HIDE Messsaging is a free and open-source peer-to-peer messaging application. Its underlying messaging protocl uses SHA256,
RSA4096, and AES256 for cryptographic primitives. HIDE's intended use case is for individuals or small orginizations who would like secure, unmonitored communication over the internet.
<br><br><br>

# Installation
The HIDE Installer, in addition to installing HIDE messaging creates the local files for the user's prfile based on a seed. In the
future, this seed will be used for account recovery. When running the HIDE Installer, you are greeted with the following GUI:
![Screenshot from 2023-05-25 08-18-40](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/0a3251f3-e12f-4455-97aa-d907bc1671c4)
## What do each of the fields mean?
### Simple User Account Information
**Username:** This field is used to input your chosen username, the only requirements are that it is at least 6 characters long
and does not contain any of the following characters: /. ~\\<br>
**Password:** This field is used to input your password. Passwords must be at least 12 characters long, and contain the following:

 - At least one uppercase letter</li>
 - At least one lowercase letter</li>
 - At least one special character</li>
 - At least one number</li>

**Confirm:** This field is a simple password comfirmation.<br>
### Node Settings (optional):
Nodes will act as a phonebook of that allows users to search for eachother by either username or ID instead of manually entering an IP address.<br><br>
**Node Name:** A friendly name that the user's choosen node is saved under<br>
**Node Address:** The IP address of the node
### Installation Settings:
**"Where would you like to store HIDE?":** Allows the user to choose where on their computer they'd like to store HIDE Messaging.<br>
**"Where would you like to store your seed file?":** Allows the user to choose where to store the seed file that is used for account creation and recovery.<br>
### Proxy Settings (optional):
HIDE will officially support using proxy servers to both recieve messages offline, and protect the user's identity. <br><br>
**Proxy Address:** This field is used to input the IP address of the user's proxy.<br>
**Proxy Port:** This field is used to input the TCP port that the user's proxy uses.
<br><br><br>

# Using HIDE Messaging
The main disadvantage of HIDE Messaging is that it can be somewhat unintuitive to use at times, so, this section of the FAQ will serve as the "instruction manual"
## Connecting to peers:
There are two ways to connect to another user, the first, and simpler of the two is done through the Contact menu. The alternative is done through the Connect menu. 
### Contact Menu:
![Screenshot from 2023-05-25 09-06-18](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/e30ad9fa-e238-4a5d-8f69-c29b9cfdb3aa)<br>
This menu is used to edit or connect to one's saved contacts, to connect to a contact, simply select their username and press connect, if they are online, a new chat window will open, allowing one to communicate with them.
### Adding Contacts:
If one would like to save a user who's presently offline in thier contacts, then they must use the "Add Contact" tab. The user will be asked for for their desired contacts username, IP Address and ID. The ID is a unique identifier in the form a base64-encoded SHA256 hash of various account/seed information for that user. It's best to request the ID and IP address directly from the peer themselves.<br>![Screenshot from 2023-05-25 11-27-18](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/0d883411-63c9-4a40-bd91-08816c7a66a2)

### Connect menu:
This menu is used to connect to user's that aren't saved in contacts. To connect to such a user, one must type their IP Address into the "IP Address" entry. Currently, inputing ID's does nothing, and neither does toggling "Connect via node." In the future, it will be possible to select "Connect via node" and input the ID of the user one would like to connect to, but this functionality has yet to be built.)<br>
![Screenshot from 2023-05-25 09-05-39](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/0f546b9c-b3e4-4f19-b96b-abe004aac5e8)
## Messaging peers 
Once you have established a connection with another user, the following tab will appear (Peer's username is censored for hopefully obvious reasons)<br>![Example](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/93ccad45-e467-44cf-a8be-5727a6f2ec44)<br>
### Sending Messages:
Sending messages is straightforward, to send a message, simply type your message into the input, and press the Enter key.
### Chat Commands:
In addition to being able to send messages in the messaging window, there are a few commands that users can input. To input a command, one must simply insert >[COMAND NAME] into the message input and press enter. As of V0.1.0, there are three commands that can be accessed this way:
- **addusr:** Adds the current messaging peer to  contacts
- **archive:** Locally saves an encrypted archive of the current conversation
- **disconnect:** Severs the current connection with your peer, and deletes the messaging window.<br><br>
Each of these commands can also be used by pressing their respective button in the Chat Commands tab:<br>![Screenshot from 2023-05-25 11-13-35](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/4b4ecb11-ca1b-45fc-9184-f9e872fce4a4)
### Message Archives:
As mentioned above, one can store encrypted archives of messages, these messages are encrypted with an AES256 key that's generated based on the user's password. To view these archive, one must go the "Etc." tab and select "Archive Viewer" then for the archive type, select "messages" and select the name of the user who they'd like to view archives of.<br>![Screenshot from 2023-05-25 11-20-32](https://github.com/DrewRoss05/HIDEMessaging/assets/131941664/ea01ced7-8cd4-4f92-993d-9ecfca7b016e)
### HIDE Logs:
In addition to storing archives of chats when requested, HIDE additionally stores encrypted logs of all network activity from the app's usage, these logs can be accessed via the afformentioned Archive View by selecting "logs" instead of "messages" for the archive type.







