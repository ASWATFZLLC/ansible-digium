#!/usr/bin/env python

# Copyright: (c) 2020, Gaël Barbier form Ziwo Ops team <gael@ziwo.io>

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: digium_access
version_added: "1.0"
short_description: Manage Digium gateways access list
description:
  >
    Manage Digium gateways access list
author: Gaël Barbier from Ziwo Ops team(@gaedb)
notes:
options:
  name:
    description: The name of the access rule
    required: true
    type: str
  state:
    description: State in which to leave the access
    default: present
    choices: [ "present", "absent" ]
    type: str
  network:
    description: Network or IP to allow (you MUST specify subnet like /32)
    type: str
  sip:
    description: Allow this network to use SIP (0: yes, 1: no)
    default: "1"
    choices: [ "0", "1" ]
    type: str
  admin_web:
    description: Allow this network to admin GW (0: yes, 1: no)
    default: "1"
    choices: [ "0", "1" ]
    type: str
  host:
    description: URL / IP of the gateway
    required: true
    type: str
  port:
    description: Port of the gateway
    default: "443"
    type: str
  user:
    description: User to use gateway API
    required: true
    type: str

  password:
    description: password to use gateway API
    required: true
    type: str
  ssl_ignore:
    description: "Skip HTTPS cerficate checking = UNSAFE !"
    default: False
    type: bool
"""

EXAMPLES = """
- name: Add or update an access
  digium_access:
    host: "my_digium_gateway"
    port: "my_digium_port"
    user: "user"
    password "pass"
    state: present
    name: "my_google_office"
    network: 8.8.8.8/32
    sip: "1"
    admin_web: "1"

- name: Remove user
  pfsense_user:
    host: "my_digium_gateway"
    port: "my_digium_port"
    user: "user"
    password "pass"
    name: my_google_office
    state: absent
"""

RETURN = """
"""

import sys
import ssl
import mechanize
import http.cookiejar as cookielib
import urllib
import json
from pprint import pprint

from ansible.module_utils.network.digium_core import Digium
from ansible.module_utils.basic import AnsibleModule

class digiumAccess(object):
    def __init__(self, module):
        self.gw = Digium(
            module.params['host'],
            module.params['port'],
            module.params['user'],
            module.params['password'],
            module.params['ssl_ignore']
            ) 
        self.list = self._list_access()
        self.module = module
        self.diff = {}

    #Request control access list
    def _list_access(self):
        data = {
            "request" : {
                "method": "access_control.list",
                "parameters": {}
            }
        }
        # Something (mechanize?) doesn't like JSON with spaces in it.
        data_str = json.dumps(data, separators=(',',':'))
        req = mechanize.Request("%s/json" % self.gw.host, data_str)
        res = mechanize.urlopen(req)
        lines = res.read()
        response = json.loads(lines)
        return(json.loads(response['response']['result']))

    # Find if a rule already exists
    def _find_access(self, name):
        for rule in self.list['access_control']['rules']:
            if rule['name'] == name:
                return rule
        return None

    def remove(self, access):
        changed = False
        name = access['name']
        rule = self._find_access(name)
        self.diff['before'] = name
        self.diff['after'] = {}
        if rule is not None:
            if ("0.0.0.0" in name or "LOCAL" in name):
                self.module.fail_json(msg='0.0.0.0 and LOCAL* cannot be remove (see API doc)')
            else:
                changed = True
        if changed:
            data = {
                "request" : {
                    "method": "access_control.delete",
                    "parameters": {
                        'object_name': name
                    }
                }
            }
            response = self.gw.api_request(data)
            if (response["result"] != 'success'):
                self.module.fail_json(msg='Error when removing %s: %s (%s)' % (name, result['error'], result['error_key']))
        self.module.exit_json(changed=changed, diff=self.diff)

    def add(self, access):
        changed = False
        stdout = None
        stderr = None
        name = access['name']
        admin_web = access['admin_web']
        sip = access['sip']
        network = access['network']
        rule = self._find_access(name)

        # Need to create it from scratch
        if rule is None:
            changed = True
            self.diff['before'] = {}

        # Need to check difference and update it if needed
        if rule is not None:
            if (rule['admin_web'] != admin_web or
                rule['sip'] != sip or
                rule['network'] != network):
                changed = True
            self.diff['before'] = {
                name: {
                    "admin_web": "yes" if rule['admin_web'] == "1" else "no",
                    "sip": "yes" if rule['sip'] == "1" else "no",
                    "network": rule['network']
                }
            }
        if changed:
            data = {
                "request" : {
                    "method": "access_control.save",
                    "parameters": {
                        "admin_web": admin_web,
                        "sip": sip,
                        "network": network,
                        "name": name,
                    }
                }
            }
            response = self.gw.api_request(data)
            if (response['result'] != 'success'):
                self.module.fail_json(msg='Error when adding %s: %s (%s)' % (name, result['error'], result['error_key']))
            self.diff['after'] = {
                name: {
                    "admin_web": "yes" if admin_web == "1" else "no",
                    "sip": "yes" if sip == "1" else "no",
                    "network": network
                }
            } 
        self.module.exit_json(changed=changed, diff=self.diff)

    def print_list(self, update=True):
        if update:
            self.list = self._list_access()
        for rule in self.list['access_control']['rules']:        
            print("Name: %s, network: %s, SIP: %s, Admin: %s" % (
                rule['name'], rule['network'], "allow" if rule["sip"] == '1' else "deny", "allow" if rule["admin_web"] == '1' else "deny"))

def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'state': {
                'type': 'str',
                'default': 'present',
                'choices': ['present', 'absent']
            },
            'admin_web': {
                'default': False,
                'type': 'bool'
                },
            'sip': {
                'default': False,
                'type': 'bool'
            },
            'network': {'type': 'str'},
            'host': {'required': True, 'type': 'str'},
            'user': {'required': True, 'type': 'str'},
            'password': {'required': True, 'type': 'str', 'no_log': True},
            'port': {'type': 'str', 'default': '443'},
            'ssl_ignore': {'type': 'bool', 'default': False}
        },
        supports_check_mode=True)

    gw = digiumAccess(module)

    access = dict()
    access['name'] = module.params['name'].replace(" ", "_")
    access['admin_web'] = "1" if module.params['admin_web'] == True else "0"
    access['sip'] = "1" if module.params['sip'] == True else "0"
    access['network'] = module.params['network']
    state = module.params['state']

    if state == 'absent':
        gw.remove(access)
    elif state == 'present':
        gw.add(access)

if __name__ == '__main__':
    main()
