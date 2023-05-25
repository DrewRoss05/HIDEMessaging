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
### Proxy Setting (optional):
HIDE will officially support using proxy servers to both recieve messages offline, and protect the user's identity. <br><br>
**Proxy Address:** This field is used to input the IP address of the user's proxy.<br>
**Proxy Port:** This field is used to input the TCP port that the user's proxy uses.
<br><br><br>
#Using HIDE Messaging


