import logging

import requests
from urllib import parse
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.chrome import ChromeDriverManager

from random import choices  # Used when generating the STATE field
from string import ascii_letters, digits  # Used when generating the STATE field

import json
from datetime import datetime, timezone
import appdirs
from pathlib import Path
import os

class SmartLinkAuthClient(object):

    HOST_AUTH = "https://frtest.auth0.com"
    HOST_SMARTLINK = "https://smartlink.flexradio.com"
    TOKEN_FILENAME = "token.json"
    TOKEN_PATH = "."
    client_id = "4Y9fEIIsVYyQo5u6jr7yBWc4lV5ugC2m"
    token = None

    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)

        # Enable extra debugging output for Requests.
        # import http.client
        # http.client.HTTPSConnection.debuglevel = 1

    def store_token(self, token):
        filepath = Path(self.TOKEN_PATH).joinpath(self.TOKEN_FILENAME)
        Path(self.TOKEN_PATH).mkdir(parents=True, exist_ok=True)
        # Todo: Handle if token file already exists
        with open(filepath, 'w+') as f:
            json.dump(token, f)
            logging.debug('Saved token to: {}'.format(filepath))

    def load_token(self):
        filepath = Path(self.TOKEN_PATH).joinpath(self.TOKEN_FILENAME)
        Path(self.TOKEN_PATH).mkdir(parents=True, exist_ok=True)
        filepath
        token = None
        try:
            with open(filepath, 'r') as f:
                token = json.load(f)
        except (EnvironmentError, json.JSONDecodeError):
            logging.warning('Unable to read saved token from {}'.format(filepath))
        return token

    def login(self):
        # Check for stored token
        filepath = Path(self.TOKEN_PATH).joinpath(self.TOKEN_FILENAME)
        if filepath.exists():
            self.token = self.load_token()
            expiry_str = datetime.utcfromtimestamp(self.token['expiry']).strftime('%Y-%m-%d %H:%M:%S')

            if datetime.now(timezone.utc).timestamp() <= self.token['expiry']:
                logging.debug(f"Stored token is valid until {expiry_str}.")
                # Token is still valid
                return

            else:
                logging.debug(f"Token expired at {expiry_str}. Attempting to use refresh_token.")
                # Refresh credentials if expired
                payload = {
                    'grant_type': 'refresh_token',
                    'refresh_token': self.token['refresh_token'],
                    'client_id': self.client_id
                }
                r = requests.post(self.HOST_AUTH + '/frtest.oauth0.com/oauth/token', data=payload)
                logging.debug(f'Token Refresh request returned status code: {r.status_code}')

                self.token = r.json()
                self.token['expiry'] = int(self.token['expires_in'] + datetime.now(timezone.utc).timestamp() - 60)
                expiry_str = datetime.utcfromtimestamp(self.token['expiry']).strftime('%Y-%m-%d %H:%M:%S')
                logging.debug(f'Token Refresh succeeded. New token expires at {expiry_str}')
                return

        # Request Flex Radio's Auth0 service to start a login
        state_len = 16
        state = "".join(choices(ascii_letters+digits, k=state_len))
        scope = " ".join(["openid", "profile", "offline_access"])
        payload = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': f'{self.HOST_AUTH}/mobile',
            'scope': scope,
            'state': state,
        }

        r = requests.get(self.HOST_AUTH + '/authorize', params=payload, allow_redirects=False)
        if r.status_code != 302:
            logging.error(f"Initial request to login service failed with status {r.status_code}")
            return
        
        # Open browser window for user to enter credentials
        login_url = self.HOST_AUTH + r.headers['Location']
        driver = webdriver.Firefox(executable_path=GeckoDriverManager().install())
        # driver = webdriver.Chrome(executable_path=ChromeDriverManager().install())
        driver.get(login_url)
        driver.execute_script("window.focus();")

        try:
            WebDriverWait(driver, 300).until(
                expected_conditions.url_changes(self.HOST_AUTH + r.headers['Location'])
            )
        except:
            logging.error("Problem with login page")
        
        # Todo: handle unsuccessful logins
        response_url = driver.current_url
        driver.close()

        try:
            auth_code = parse.parse_qs(parse.urlparse(response_url).query)['code'][0]
            state = parse.parse_qs(parse.urlparse(response_url).query)['state'][0]
        except (KeyError):
            logging.error("Problem with login page")
            return

        # Exchange auth code for an OAuth token
        payload = {
            'response_type': 'token',
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': self.client_id,
            'redirect_uri': f'{self.HOST_AUTH}/mobile',
            'scope': scope,
            'state': state,
        }

        logging.debug(f'Exchanging auth code for Oauth token')
        r = requests.post(self.HOST_AUTH + '/frtest.auth0.com/oauth/token', data=payload)
        if r.status_code != 200:
            logging.error("Failed to exchange auth code for tokens")
            return

        self.token = r.json()
        self.token['expiry'] = int(self.token['expires_in']) + datetime.now(timezone.utc).timestamp() - 60
        self.store_token(self.token)

if __name__ == "__main__":
    client = SmartLinkAuthClient()
    from selenium.webdriver.remote.remote_connection import LOGGER as weblogger
    weblogger.setLevel(logging.WARNING)
    #client.login()