"""
Support for Nokia XS-2426G-B router
"""
import base64
from base64 import urlsafe_b64encode
import hashlib
import logging
import os
import re
import urllib
from collections import namedtuple
from datetime import datetime, timezone

import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_SSL, CONF_SCAN_INTERVAL

from .crypto_page import base64url_escape
from .crypto_page import AESCipher


_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
})

def get_scanner(hass, config):
    """Validate the configuration and return an ExperiaBox V10A device scanner."""
    try:
        return NokiaDeviceScanner(config[DOMAIN])
    except ConnectionError:
        return None

Device = namedtuple('Device', ['mac', 'name', 'ip', 'last_update'])

class NokiaDeviceScanner(DeviceScanner):
    """This class queries an Nokia XS-2426G-B router for connected devices"""


    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username, self.password = config[CONF_USERNAME], config[CONF_PASSWORD]
        
        _LOGGER.debug('Initializing for host: {}'.format(self.host))

        self.last_results = []
        self.success_init = self._update_info()

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        filter_named = [result.name for result in self.last_results
                        if result.mac == device]

        if filter_named:
            return filter_named[0]
        return None

    def get_extra_attributes(self, device):
        """Return the extra attibutes of the given device."""
        filter_device = next((
            result for result in self.last_results
            if result.mac == device), None)
        return {'ip': filter_device.ip}

    def _update_info(self):
        """Ensure the information from the Nokia up to date. Return boolean if scanning successful."""

        _LOGGER.info("Loading devices...")
        
        base_url = 'http://{}'.format(self.host)

        login_nonce_api = '/login_web_app.cgi?nonce'
        login_api = '/login_web_app.cgi'
        lan_status_api = '/lan_status_web_app.cgi?wlan'

        login_nonce_url = base_url+login_nonce_api
        login_url = base_url+login_api
        lan_status_url = base_url + lan_status_api
        
        login_nonce_payload = "userName=" + self.username
        
        # define a header
        header = {
            'Referer': base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'Origin': base_url,
            'Host': self.host,
            'Content-Type' : 'text/html'
        }
        # We need to store a cookie
        client = requests.Session()

        # get (POST) a one time number (nonce), public key and randomkey
        response = client.post(login_nonce_url, allow_redirects = False, data = login_nonce_payload, timeout = 10, headers = header)
        _LOGGER.debug('GET {}'.format(login_nonce_url))
        _LOGGER.debug('response status: {}'.format(response.status_code))
        
        nonce = response.json()['nonce']
        pubkey = response.json()['pubkey']
        randomkey = response.json()['randomKey']
        nohash = '1'
        
        # get the part we want
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
        
        response = client.post(login_url, allow_redirects = False, data = login_payload, timeout = 10, headers = header)
        _LOGGER.debug('POST {}'.format(login_url))
        _LOGGER.debug('response status: {}'.format(response.status_code))
        
        header['Content-Type'] = 'text/html'
        response = client.get(lan_status_url, allow_redirects = False, timeout = 10, headers = header)
        _LOGGER.debug('POST {}'.format(login_url))
        _LOGGER.debug('response status: {}'.format(response.status_code))
        client.close()
        
        result = response.json()
        
        now = dt_util.now()

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

                    last_results.append(Device(mac.upper(), name, ip, now))

            # replace the last results list, any devices that left will eventually report "not_home"
            self.last_results = last_results
            return True
        _LOGGER.error('Got no devices')
        return False