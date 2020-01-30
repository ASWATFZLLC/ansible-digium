#!/usr/bin/env python

# Copyright: (c) 2020, Gaël Barbier form Ziwo Ops team <gael@ziwo.io>

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

import ssl
import re
import mechanize
import http.cookiejar as cookielib
import urllib
import json
from pprint import pprint

from ansible.module_utils.basic import AnsibleModule

class Digium():
    def __init__(self, host, port, user, password, ssl_ignore=False):
        self.host = "https://" + host + ":" + port
        self.user = user
        self.password = password
        self.ssl_ignore = ssl_ignore
        self.cookiejar = cookielib.LWPCookieJar()
        self.connect = self.api_connect()

    def api_connect(self):
        data = {
            'admin_uid': self.user,
            'admin_password': self.password
        }
        data_str = '&'.join(['%s=%s' % (k,v) for k,v in data.items()])

        if self.ssl_ignore is True:
            try:
                _create_unverified_https_context = ssl._create_unverified_context
            except AttributeError:
                pass
            else:
                ssl._create_default_https_context = _create_unverified_https_context
        req = mechanize.Request("%s/admin/main.html" % self.host, data_str)
        self.cookiejar.add_cookie_header(req)
        res = mechanize.urlopen(req)
        lines = res.read().decode('utf-8')
     
        # Response from login is an HTML page. Check that the main page's init()
        # function is called to be sure we have logged in and are looking at
        # the main page.
        if re.search("Welcome,\s+%s" % self.user, lines) is None:
            self.module.fail_json(msg='Login incorrect for user %s' % (self.user))
        print("Connected")
        return 0

    def api_request(self, data):
        data_str = json.dumps(data, separators=(',',':'))
        req = mechanize.Request("%s/json" % self.host, data_str)
        res = mechanize.urlopen(req)
        lines = res.read()
        print(lines)
        response = json.loads(lines)
        result = json.loads(response['response']['result'])
        return result