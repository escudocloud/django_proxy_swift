#!/usr/bin/env python
# -*- coding: utf-8 -*-

from client import EncSwiftclient
from swiftclient import client
from config import *

class EncSwiftclientAPI:

    def __init__(self, auth_token, project_id):
        self.esc = EncSwiftclient(auth_token, project_id)
        
    def put_container(self, container, headers=None):
        return self.esc.put_enc_container(container, headers)

    def delete_container(self, container):
        return self.esc.delete_container(container)

    def post_container(self, container, headers=None):
        return self.esc.post_enc_container(container, headers)

    def head_container(self, container):
        return self.esc.head_container(container)

    def get_container(self, container, delimiter=None, prefix=None, marker= None):
        return self.esc.get_container(container, marker=marker, delimiter=delimiter, prefix=prefix)

    def get_account(self):
        return self.esc.get_account()

    def head_account(self):
        return self.esc.head_account()
        
    def post_account(self,header):
        return self.esc.post_account(header)
    
    def put_object(self, container, name, contents):
        return self.esc.put_enc_object(container, name, contents)

    def delete_object(self, container, obj_name):
        return self.esc.delete_object(container, obj_name)

    def head_object(self, container, obj):
        return self.esc.head_object(container, obj)

    def post_object(self, container, obj, headers):
        return self.esc.post_object(container, obj, headers)

    def get_object(self, container, obj_name):
        return self.esc.get_enc_object(container, obj_name)
        
    def getUserID(self,username):
        return self.esc.getUserID(username)

    def getUsername(self,userid):
        return self.esc.getUsername(userid)
