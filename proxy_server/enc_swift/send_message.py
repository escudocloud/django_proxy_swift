#!/usr/bin/env python
# -*- coding: utf-8 -
import requests

from config import *
from Crypto.PublicKey import RSA

class sender:

    def send_message(self,mode,obj):
        """
        Send a message to daemon
        Args:
            mode: type of request
            obj: info to send
        """
        headers={}
        info = obj.split('#')
        if mode == 'update':
            #Add a new node in catalogs
            headers['X-Auth-Token'] = info[0]
            headers['receiver'] = info[1]
            headers['id'] = info[2]
            data = info[3]
        if mode == 'create':
            #Create new users
            daemon_pubKey = requests.get(DAEMON_URL+'/'+mode).content
            encpass = self.encrypt(info[1],daemon_pubKey).encode('base64')
            data = '#'.join([info[0],encpass,info[2],info[3]])
        if mode in ('get_id','get_name'):
            #Retrieve user information
            headers['X-Auth-Token'] = info[0]            
            data = info[1]
        resp = requests.put(DAEMON_URL+'/'+mode,data=data,headers=headers)
        return resp

    def encrypt(self,secret, key):
        """
        Encrypt the message to send
        """
        receiver_pub_key = RSA.importKey(key)
        return receiver_pub_key.encrypt(secret, 'x')[0]
