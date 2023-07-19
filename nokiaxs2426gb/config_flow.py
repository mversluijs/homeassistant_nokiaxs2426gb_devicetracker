"""Config flow for nokiaxs2426gb integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

import aiohttp
import urllib
import os
import re

from base64 import urlsafe_b64encode
from .crypto_page import base64url_escape
from .crypto_page import AESCipher

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import (
    DOMAIN,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_HOST,
)

_LOGGER = logging.getLogger(__name__)


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_HOST): str,
    }
)

# TODO options voor consider_home en scaninteval toevoegen: https://github.com/home-assistant/core/pull/50741/commits/70dd8e46c8e73cf1ac5249989962d810d3b5037a


class PlaceholderHub:
    """placeholder, change name?"""

    def __init__(self, host: str) -> None:
        """Initialize."""
        self.host = host

    async def authenticate(self, username: str, password: str) -> bool:
        """Check if we can authenticate."""
        _LOGGER.info("Loading devices...")
        
        base_url = 'http://{}'.format(CONF_HOST)

        login_nonce_api = '/login_web_app.cgi?nonce'
        login_api = '/login_web_app.cgi'
        lan_status_api = '/lan_status_web_app.cgi?wlan'

        login_nonce_url = base_url+login_nonce_api
        login_url = base_url+login_api
        lan_status_url = base_url + lan_status_api
        
        login_nonce_payload = "userName=" + CONF_USERNAME
        
        # define a header
        header = {
            'Referer': base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'Origin': base_url,
            'Host': CONF_HOST,
            'Content-Type' : 'text/html'
        }
        # We need to store a cookie
        # client = requests.Session()
        async with aiohttp.ClientSession(base_url)as session:

            _LOGGER.debug('GET {}'.format(login_nonce_url))
            # get (POST) a one time number (nonce), public key and randomkey
            response = session.post(login_nonce_url, allow_redirects = False, data = login_nonce_payload, timeout = 10, headers = header)
            nonce = response.json()['nonce']
            pubkey = response.json()['pubkey']
            randomkey = response.json()['randomKey']
            nohash = '1'
            
            # get the part we want
            pubkey = pubkey.split('-----')[2]
            
            # prepare the payload for our next request, authentication
            enckey = base64url_escape(urlsafe_b64encode(os.urandom(16)).decode('utf-8'))
            enciv = base64url_escape(urlsafe_b64encode(os.urandom(16)).decode('utf-8'))
            
            g1 =  "userhash=" + CONF_USERNAME
            g1 += "&RandomKeyhash=" + randomkey
            g1 += "&response=" + urllib.parse.quote(CONF_PASSWORD)
            g1 += "&nonce=" + base64url_escape(nonce)
            g1 += "&enckey=" + enckey
            g1 += "&enciv=" + enciv
            g1 += "&nohash=" + nohash
            g1 += "&hPassword=undefined"
            
            # New AESCipher object
            aes = AESCipher()
            
            header['Content-Type'] = 'application/x-www-form-urlencoded'

            ct = aes.encrypt(pubkey, g1)
            ck = aes.ck
            
            login_payload = {
                'encrypted' : 1,
                'ct' : ct,
                'ck' : ck
            }
            
            response = session.post(login_url, allow_redirects = False, data = login_payload, timeout = 10, headers = header)
            if resp.status == 299:
                auth_succesfull = True
            else:
                auth_succesfull = False
        await session.close()

        return auth_succesfull


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    # validate the data can be used to set up a connection.

    # If your PyPI package is not built with async, pass your methods
    # to the executor:
    # await hass.async_add_executor_job(
    #     your_validate_func, data["username"], data["password"]
    # )
    print(data)
    hub = PlaceholderHub(data['host'])

    if not await hub.authenticate(data['username'], data['password']):
        raise InvalidAuth

    # If you cannot connect:
    # throw CannotConnect
    # If the authentication is wrong:
    # InvalidAuth

    # Return info that you want to store in the config entry.
    return {'title': 'Nokia XS2426G-B @ ' + data[CONF_HOST]}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Nokia XS2426G-B Router."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
