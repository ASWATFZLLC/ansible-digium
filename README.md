# Ansible-digium

This is a set of modules to allow you to configure Digium gateways with ansible.

## Modules
The following modules are currently available:

* [digium_access] for access control management

## Example
See main.yaml
```
- hosts: 127.0.0.1
  connection: local

  vars:
    digium_host: "MY_DIGIUM_GW"
    digium_port: "MY_DIGIUM_PORT"
    user: "test"
    password: "test"

  tasks:
    ###################
    # Add new access rule
    ###################
    - name: Add Google office access for administration only (no SIP)
      digium_access:
        host: "{{ digium_host }}"
        port: "{{ digium_port }}"
        user: "{{ user }}"
        password: "{{ password }}"
        name: "my_google_office"
        state: present
        network: "8.8.8.8/32"
        sip: no
        admin_web: yes

    ###################
    # Remove access rule
    ###################
    - name: Remove Google office access
      digium_access:
        host: "{{ digium_host }}"
        port: "{{ digium_port }}"
        user: "{{ user }}"
        password: "{{ password }}"
        name: "my_google_office"
        state: absent
```
