# ansible-orvibo_s20
Ansible module to control Orvibo S20 sockets on the LAN

It uses the code from https://github.com/cherezov/orvibo for all the Orvibo S20 stuff. Some of the functionality has been stripped off since I didn't care about other devices.

## Usage

The module allows for device discovery and changing the status to on or off. Check mode is also supported. 

Drop it in the library folder inside your playbook folder and it should be good to go. Check the samples folder for sample playbooks.
