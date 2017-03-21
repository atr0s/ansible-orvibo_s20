#!/usr/bin/env python

DOCUMENTATION = '''
---
module: orvibo_s20
short_description: Discovers and controls state of Orvibo S20 sockets
description:
    -  This module allows discovery and state control of Orvibo S20 devices. It will also return information about the device if it exists.
version_added: "2.2"
author: Christian Costa (atros@atros.org)
options:
  address:
    description:
      - IP address of the socket device
    required: false
  state:
    description:
      - Sets the socket state to on or off
    required: false
    default: None
    choices: ["on", "off"]
  
'''

EXAMPLES = '''
---
# Simple example to turn on a socket
- hosts: localhost
  tasks:
    - name: turning on socket
      orvibo_s20:
        address: 10.0.0.10
        state: on'''


RETURN = '''
---
sockets:
    description: list of IP addresses of sockets on the local network when address is not passed to the module
    type: list
address:
    description: IP address of the socket being queried or acted upon
    type: string
mac:
    description: MAC address of the socket being queried or acted upon
    type: string
state:
    description: state of the socket after an action has been taken
    type: string


'''

try:
    from contextlib import contextmanager
    import logging
    import struct
    import select
    import random
    import socket
    import binascii
    import time
    import sys

except ImportError, e:
    print "failed=True msg='failed to import python module: %s'" % e
    sys.exit(1)

py3 = sys.version_info[0] == 3

BROADCAST = '255.255.255.255'
PORT = 10000

MAGIC = b'\x68\x64'
SPACES_6 = b'\x20\x20\x20\x20\x20\x20'
ZEROS_4 = b'\x00\x00\x00\x00'

ON = b'\x01'
OFF = b'\x00'

# CMD CODES
DISCOVER = b'\x71\x61'
DISCOVER_RESP = DISCOVER

SUBSCRIBE = b'\x63\x6c'
SUBSCRIBE_RESP = SUBSCRIBE

CONTROL = b'\x64\x63'
CONTROL_RESP = CONTROL

SOCKET_EVENT = b'\x73\x66' # something happend with socket

LEARN_IR = b'\x6c\x73'
LEARN_IR_RESP = LEARN_IR

BLAST_IR = b'\x69\x63'

BLAST_RF433 = CONTROL
LEARN_RF433 = CONTROL

class OrviboException(Exception):
    """ Module level exception class.
    """
    def __init__(self, msg):
        super(OrviboException, self).__init__(msg)

def _reverse_bytes(mac):
    """ Helper method to reverse bytes order.

    mac -- bytes to reverse
    """
    ba = bytearray(mac)
    ba.reverse()
    return bytes(ba)

def _random_byte():
    """ Generates random single byte.
    """
    return bytes([int(256 * random.random())])

def _random_n_bytes(n):
    res = b''
    for n in range(n):
        res += _random_byte()
    return res

def _packet_id():
    return _random_n_bytes(2)

_placeholders = ['MAGIC', 'SPACES_6', 'ZEROS_4', 'CONTROL', 'CONTROL_RESP', 'SUBSCRIBE', 'LEARN_IR', 'BLAST_RF433', 'BLAST_IR', 'DISCOVER', 'DISCOVER_RESP' ]
def _debug_data(data):
    data = binascii.hexlify(bytearray(data))
    for s in _placeholders:
        p = binascii.hexlify(bytearray( globals()[s]))
        data = data.replace(p, b" + " + s.encode() + b" + ")
    return data[3:]

def _parse_discover_response(response):
    """ Extracts MAC address and Type of the device from response.

    response -- dicover response, format:
                MAGIC + LENGTH + DISCOVER_RESP + b'\x00' + MAC + SPACES_6 + REV_MAC + ... TYPE
    """
    header_len = len(MAGIC + DISCOVER_RESP) + 2 + 1  # 2 length bytes, and 0x00
    mac_len = 6
    spaces_len = len(SPACES_6)

    mac_start = header_len
    mac_end = mac_start + mac_len
    mac = response[mac_start:mac_end]

    type = None
    if b'SOC' in response:
        type = Orvibo.TYPE_SOCKET

    elif b'IRD' in response:
        type = Orvibo.TYPE_IRDA

    return (type, mac)

def _create_orvibo_socket(ip=''):
    """ Creates socket to talk with Orvibo devices.

    Arguments:
    ip - ip address of the Orvibo device or empty string in case of broadcasting discover packet.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for opt in [socket.SO_BROADCAST, socket.SO_REUSEADDR, socket.SO_BROADCAST]:
        sock.setsockopt(socket.SOL_SOCKET, opt, 1)
    if ip:
        sock.connect((ip, PORT))
    else:
        sock.bind((ip, PORT))
    return sock

@contextmanager
def _orvibo_socket(external_socket = None):
    sock = _create_orvibo_socket() if external_socket is None else external_socket

    yield sock

    if external_socket is None:
        sock.close()
    else:
        pass

class Packet:
    """ Represents response sender/recepient address and binary data.
    """

    Request = 'request'
    Response = 'response'

    def __init__(self, ip = BROADCAST, data = None, type = Request):
        self.ip = ip
        self.data = data
        self.type = type

    def __repr__(self):
        return 'Packet {} {}: {}'.format('to' if self.type == self.Request else 'from', self.ip, _debug_data(self.data))

    @property
    def cmd(self):
        """ 2 bytes command of the orvibo packet
        """
        if self.data is None:
            return b''
        return self.data[4:6]

    @property
    def length(self):
        """ 2 bytes command of the orvibo packet
        """
        if self.data is None:
            return b''
        return self.data[2:4]


    def send(self, sock, timeout = 10):
        """ Sends binary packet via socket.

        Arguments:
        sock -- socket to send through
        packet -- byte string to send
        timeout -- number of seconds to wait for sending operation
        """
        if self.data is None:
            # Nothing to send
            return

        for i in range(timeout):
            r, w, x = select.select([], [sock], [sock], 1)
            if sock in w:
                sock.sendto(bytearray(self.data), (self.ip, PORT))
            elif sock in x:
                raise OrviboException("Failed while sending packet.")
            else:
                # nothing to send
                break

    @staticmethod
    def recv(sock, expectResponseType = None, timeout = 10):
        """ Receive first packet from socket of given type

        Arguments:
        sock -- socket to listen to
        expectResponseType -- 2 bytes packet command type to filter result data
        timeout -- number of seconds to wait for response
        """
        response = None
        for i in range(10):
            r, w, x = select.select([sock], [], [sock], 1)
            if sock in r:
                data, addr = sock.recvfrom(1024)

                if expectResponseType is not None and data[4:6] != expectResponseType:
                    continue

                response = Packet(addr[0], data, Packet.Response)
                break
            elif sock in x:
                raise OrviboException('Getting response failed')
            else:
                # Nothing to read
                break

        return response

    @staticmethod
    def recv_all(sock, expectResponseType = None, timeout = 10):
       res = None
       while True:
           resp = Packet.recv(sock, expectResponseType, timeout)
           if resp is None:
                break
           res = resp
       return res

    def compile(self, *args):
        """ Assemblies packet to send to orvibo device.

        *args -- number of bytes strings that will be concatenated, and prefixed with MAGIC heaer and packet length.
        """

        length = len(MAGIC) + 2 # len itself
        packet = b''
        for a in args:
            length += len(a)
            packet += a

        msg_len_2 = struct.pack('>h', length)
        self.data = MAGIC + msg_len_2 + packet
        return self

class Orvibo(object):
    """ Represents Orvibo device, such as wifi socket (TYPE_SOCKET) or AllOne IR blaster (TYPE_IRDA)
    """

    TYPE_SOCKET = 'socket'
    TYPE_IRDA = 'irda'

    def __init__(self, ip, mac = None, type = 'Unknown'):
        self.ip = ip
        self.type = type
        self.__last_subscr_time = time.time() - 1 # Orvibo doesn't like subscriptions frequently that 1 in 0.1sec
        self.__logger = logging.getLogger('{}@{}'.format(self.__class__.__name__, ip))
        self.__socket = None
        self.mac = mac

        # TODO: make this tricky code clear
        if py3 and isinstance(mac, str):
            self.mac = binascii.unhexlify(mac)
        else:
            try:
                self.mac = binascii.unhexlify(mac)
            except:
                pass

        if mac is None:
            self.__logger.debug('MAC address is not provided. Discovering..')
            d = Orvibo.discover(self.ip)
            self.mac = d.mac
            self.type = d.type

    def __del__(self):
        self.close()

    def close(self):
        if self.__socket is not None:
            try:
                self.__socket.close()
            except socket.error:
                # socket seems not alive
                pass
            self.__socket = None

    @property
    def keep_connection(self):
        """ Keeps connection to the Orvibo device.
        """
        return self.__socket is not None

    @keep_connection.setter
    def keep_connection(self, value):
        """ Keeps connection to the Orvibo device.
        """
        # Close connection if alive
        self.close()

        if value:
            self.__socket = _create_orvibo_socket(self.ip)
            if self.__subscribe(self.__socket) is None:
                raise OrviboException('Connection subscription error.')
        else:
            self.close()

    def __repr__(self):
        mac = binascii.hexlify(bytearray(self.mac))
        return "Orvibo[type={}, ip={}, mac={}]".format(self.type, 'Unknown' if self.ip == BROADCAST else self.ip, mac.decode('utf-8') if py3 else mac)

    @staticmethod
    def discover(ip = None):
        """ Discover all/exact devices in the local network

        Arguments:
        ip -- ip address of the discovered device

        returns -- map {ip : (ip, mac, type)} of all discovered devices if ip argument is None
                   Orvibo object that represents device at address ip.
        raises -- OrviboException if requested ip not found
        """
        devices = {}
        with _orvibo_socket() as s:
            logger = logging.getLogger(Orvibo.__class__.__name__)
            logger.debug('Discovering Orvibo devices')
            discover_packet = Packet(BROADCAST)
            discover_packet.compile(DISCOVER)
            discover_packet.send(s)

            for indx in range(512): # supposer there are less then 512 devices in the network
                p = discover_packet.recv(s)
                if p is None:
                    # No more packets in the socket
                    break

                orvibo_type, orvibo_mac = _parse_discover_response(p.data)
                logger.debug('Discovered values: type={}, mac={}'.format(orvibo_type, orvibo_mac));

                if not orvibo_mac:
                    # Filter ghosts devices
                    continue

                devices[p.ip] = (p.ip, orvibo_mac, orvibo_type)

        if ip is None:
            return devices

        if ip not in devices.keys():
            raise OrviboException('Device ip={} not found in {}.'.format(ip, devices.keys()))

        return Orvibo(*devices[ip])

    def subscribe(self):
        """ Subscribe to device.

        returns -- last response byte, which represents device state
        """
        with _orvibo_socket(self.__socket) as s:
            return self.__subscribe(s)

    def __subscribe(self, s):
        """ Required action after connection to device before sending any requests

        Arguments:
        s -- socket to use for subscribing

        returns -- last response byte, which represents device state
        """

        if time.time() - self.__last_subscr_time < 0.1:
            time.sleep(0.1)

        subscr_packet = Packet(self.ip)
        subscr_packet.compile(SUBSCRIBE, self.mac, SPACES_6, _reverse_bytes(self.mac), SPACES_6)
        subscr_packet.send(s)
        response = subscr_packet.recv_all(s, SUBSCRIBE_RESP)

        self.__last_subscr_time = time.time()
        return response.data[-1] if response is not None else None

    def __control_s20(self, switchOn):
        """ Switch S20 wifi socket on/off

        Arguments:
        switchOn -- True to switch on socket, False to switch off

        returns -- True if switch success, otherwise False
        """

        with _orvibo_socket(self.__socket) as s:
            curr_state = self.__subscribe(s)

            if self.type != Orvibo.TYPE_SOCKET:
                self.__logger.warn('Attempt to control device with type {} as socket.'.format(self.type))
                return False

            if curr_state is None:
                self.__logger.warn('Subscription failed while controlling wifi socket')
                return False

            state = ON if switchOn else OFF
            if curr_state == state:
                self.__logger.warn('No need to switch {0} device which is already switched {0}'.format('on' if switchOn else 'off'))
                return False

            self.__logger.debug('Socket is switching {}'.format('on' if switchOn else 'off'))
            on_off_packet = Packet(self.ip)
            on_off_packet.compile(CONTROL, self.mac, SPACES_6, ZEROS_4, state)
            on_off_packet.send(s)
            if on_off_packet.recv(s, CONTROL_RESP) is None:
                self.__logger.warn('Socket switching {} failed.'.format('on' if switchOn else 'off'))
                return False

            self.__logger.info('Socket is switched {} successfuly.'.format('on' if switchOn else 'off'))
            return True

    @property
    def on(self):
        """ State property for TYPE_SOCKET

        Arguments:
        returns -- State of device (True for on/False for off).
        """

        onValue = 1 if py3 else ON
        return self.subscribe() == onValue

    @on.setter
    def on(self, state):
        """ Change device state for TYPE_SOCKET

        Arguments:
        state -- True (on) or False (off).

        returns -- nothing
        """
        self.__control_s20(state)

def main():
    changed = False
    message = ''

    module = AnsibleModule(
        argument_spec = dict(
            state = dict(default=None,choices=['on','off'],required=False),
            address = dict(required=False,default=None)
        ),
        supports_check_mode=True
    )
    r = {}
    if module.params['address'] == None:
        result = []
        for m in Orvibo.discover().values():
            result.append(m[0])
            r['sockets'] = result

    if module.params['address'] is not None:
        try:
            o = Orvibo.discover(module.params['address'])
            r['address']=o.ip
            r['mac']=binascii.hexlify(o.mac)
            r['state']='on' if o.on else 'off'
        except OrviboException:
            module.fail_json(msg="Device not found at %s" % module.params['address'])
        if module.params['state'] is not None:
            desired_state = True if module.params['state']=='on' else False
            changed = desired_state ^ o.on
            if changed:
                try:
                    if not module.check_mode:
                        o.on = desired_state
                    r['state'] = o.on
                except OrviboException:
                    module.fail_json(msg="Failed to set device state to %s" % module.params['state'])

    module.exit_json(changed=changed, **r)

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()