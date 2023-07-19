"""Module to communicate with Nokia routers using the HTTP."""
from __future__ import print_function

import logging
import requests
import os
import urllib

from collections import namedtuple
from datetime import datetime, timedelta
from time import sleep
from ipaddress import IPv6Address
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from .crypto_page import base64url_escape
from .crypto_page import AESCipher
from . import const_nokia as c
from base64 import urlsafe_b64encode

_LOGGER = logging.getLogger(__name__)

disable_warnings(InsecureRequestWarning)


Device = namedtuple(
    "Device",
    [
        "mac",
        "name",
        "ip",
    ],
)


class Nokia(object):
    """Represents a session to a Nokia Router."""

    def __init__(
        self,
        password=None,
        host=None,
        user=None,
        url=None,
    ):
        """Initialize a Nokia session."""
        if not host:
            host = c.DEFAULT_HOST
        if not user:
            user = c.DEFAULT_USER

        try:
            IPv6Address(host)
        except ValueError:
            pass
        else:
            host = "[%s]" % (host)

        self.username = user
        self.password = password
        self.url = url
        self.host = host

        self.cookie = None
        self.config_started = False
        self._logging_in = False

        self._info = None
        self._session = requests.Session()


    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        # cookie is also used to track if at least
        # one login attempt has been made
        self.cookie = None

        base_url = 'http://{}'.format(self.host)

        login_nonce_api = c.LOGIN_NONCE_API
        login_api = c.LOGIN_API

        login_nonce_url = base_url+login_nonce_api
        login_url = base_url+login_api

        
        login_nonce_payload = "userName=" + self.username
        
        # define a header
        header = {
            'Referer': base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'Origin': base_url,
            'Host': self.host,
            'Content-Type' : 'text/html'
        }
        # Lets get our session
        client = self._session

        # STEP 1: Get (POST) a number once (nonce), public key and randomkey
        response = client.post(login_nonce_url, allow_redirects = False, data = login_nonce_payload, timeout = 10, headers = header)
        
        _LOGGER.debug('POST {}'.format(login_nonce_url))
        _LOGGER.debug('response status: {}'.format(response.status_code))
        
        nonce = response.json()['nonce']
        pubkey = response.json()['pubkey']
        randomkey = response.json()['randomKey']
        nohash = '1'
        
        # get the part from the public key we want
        pubkey = pubkey.split('-----')[2]
        
        # prepare the payload for our next request, authentication
        enckey = base64url_escape(urlsafe_b64encode(os.urandom(16)).decode('utf-8'))
        enciv = base64url_escape(urlsafe_b64encode(os.urandom(16)).decode('utf-8'))
        
        # TODO: urllib vervangne door een andere

        g1 =  "userhash=" + self.username
        g1 += "&RandomKeyhash=" + randomkey
        g1 += "&response=" + urllib.parse.quote(self.password)
        g1 += "&nonce=" + base64url_escape(nonce)
        g1 += "&enckey=" + enckey
        g1 += "&enciv=" + enciv
        g1 += "&nohash=" + nohash
        g1 += "&hPassword=undefined"
        
        # New AESCipher object
        aes = AESCipher()
        
        header['Content-Type'] = 'application/x-www-form-urlencoded'

        ct = aes.encrypt(pubkey, g1)
        # encrypt fucntion also encrypts (RSA) the key, iv pair (ck) that has been used to (AES) encrypt the login string g1
        ck = aes.ck
        
        login_payload = {
            'encrypted' : 1,
            'ct' : ct,
            'ck' : ck
        }
        # STEP 2: Authentication
        response = client.post(login_url, allow_redirects = False, data = login_payload, timeout = 10, headers = header)

        
            
        if response.status_code == 299:
            self.cookie = 'succes'
            auth_succesfull = True
            _LOGGER.debug('logged in succesfully')
        else:
            auth_succesfull = False
            _LOGGER.debug('login failed')
            _LOGGER.debug('POST {}'.format(login_url))
            _LOGGER.debug('response status: {}'.format(response.status_code))
            _LOGGER.debug('response text: {}'.format(response.text))
        return auth_succesfull

    def logged_in(self):
        """
        Checks if we are logged in to the router.

        """
        client = self._session
        base_url = 'http://{}'.format(self.host)
        logged_in_url = base_url + c.LOGGED_IN_API

        header = {
            'Referer': base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'Origin': base_url,
            'Host': self.host,
            'Content-Type' : 'text/html'
        }

        response = client.post(logged_in_url, allow_redirects = False, timeout = 10, headers = header)

        if response.json()['expired'] == 'no':
            _LOGGER.debug('logged in? Yes')
            return True

        _LOGGER.debug('Logged in? No')
        _LOGGER.debug('response status: {}'.format(response.status_code))
        _LOGGER.debug('response text: {}'.format(response.text))
        return False


    def get_info(self, use_cache=True):
        """
        Return router informations, like:
            "ManufacturerOUI": "04B6BE",
            "ProductClass": "XS-2426G-B",
            "ModelName": "XS-2426G-B",
            "Vendor": "Nokia",
            "SerialNumber": "AAABBBBCCCDDD",
            "HardwareVersion": "3FE49546BBAA",
            "SoftwareVersion": "3FE49544MJJJ05(1.2202.705)",
            "X_ASB_COM_Chipset": "CA8289",
            "AdditionalSoftwareVersion": "Uboot May-16-2020.18:32:20 ",
            "UpTime": 671283,
            "lot_number": "220705"

        Returns None if error occurred.
        """

        base_url = 'http://{}'.format(self.host)
        device_info_url = base_url + c.DEVICE_INFO_API

        header = {
            'Referer': base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'Origin': base_url,
            'Host': self.host,
            'Content-Type' : 'text/html'
        }

        if self._info is not None and use_cache:
            _LOGGER.debug("Info from cache.")
            return self._info

        if not self.logged_in():
            self.login()
        
        client = self._session

        response = client.get(device_info_url, allow_redirects = False, timeout = 10, headers=header)

        if response is None:
            return None

        self._info = response.json()
        return self._info

    def get_attached_devices(self):
        """
        Return list of devices attached with a connection to the router.
        """

        base_url = 'http://{}'.format(self.host)
        lan_status_api = '/lan_status_web_app.cgi?wlan'
        lan_status_url = base_url + lan_status_api

        if not self.logged_in():
            _LOGGER.debug('not logged in')
            self.login()
        
        client = self._session
        header = {
            'Referer': base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'Origin': base_url,
            'Host': self.host,
            'Content-Type' : 'text/html'
        }
                
        response = client.get(lan_status_url, allow_redirects = False, timeout = 10, headers = header)
        _LOGGER.debug('GET {}'.format(lan_status_url))
        _LOGGER.debug('response status: {}'.format(response.status_code))
        
        result = response.json()
        
        # start with an empty list, we will add all the devices we see
        last_results = []
        if result['device_cfg']:
            _LOGGER.info('Got {} devices'.format(len(result['device_cfg'])))
            for line in result['device_cfg']:
                # Only active devices
                if line['Active'] == 1:
                    name = line['HostName']
                    ip = line['IPAddress']
                    mac = line['MACAddress']

                    _LOGGER.debug(line)

                    last_results.append(Device(mac.upper(), name, ip))

            # replace the last results list, any devices that left will eventually report "not_home"
            self.last_results = last_results
            return last_results
        _LOGGER.error('Got no devices')
        return None
    
    # def reboot(self):
    #     """Reboot the router"""
    #     return self._set(c.SERVICE_DEVICE_CONFIG, c.REBOOT)

    # def check_ethernet_link(self):
    #     """
    #     Check the ethernet link status and return dict like:
    #     - NewEthernetLinkStatus
    #     """
    #     return self._get(
    #         c.SERVICE_WAN_ETHERNET_LINK_CONFIG,
    #         c.GET_ETHERNET_LINK_STATUS,
    #     )