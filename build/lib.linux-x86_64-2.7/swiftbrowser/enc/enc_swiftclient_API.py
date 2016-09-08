#!/usr/bin/env python
# -*- coding: utf-8 -*-

from client import EncSwiftclient
from swiftclient import client

class EncSwiftclientAPI:

    def __init__(self, auth_token, project_id):
        print auth_token
        print project_id
        #self.esc = EncSwiftclient(auth_token, project_id)
        self.esc = client.Connection(preauthtoken=auth_token,preauthurl="http://127.0.0.1:8001/AUTH_%s" %project_id, auth_version='2.0')

    def put_container(self, container, headers=None):
        return self.esc.put_container(container, headers)

    def delete_container(self, container):
        return self.esc.delete_container(container)

    def post_container(self, container, headers=None):
        return self.esc.post_container(container, headers)

    def head_container(self, container):
        return self.esc.head_container(container)

    def get_container(self, container, delimiter=None, prefix=None, marker= None):
        return self.esc.get_container(container, marker, delimiter, prefix)

    def get_account(self):
        return self.esc.get_account()

    def head_account(self):
        return self.esc.head_account()
    
    def put_object(self, container, name, contents):
        return self.esc.put_object(container, name, contents)

    def delete_object(self, container, obj_name):
        return self.esc.delete_object(container, obj_name)

    def head_object(self, container, obj):
        return self.esc.head_object(container, obj)

    def post_object(self, container, obj, headers):
        return self.esc.post_object(container, obj, headers)

    def get_object(self, container, obj_name):
        return self.esc.get_object(container, obj_name)
        
    def getUserID(self,username):
        return self.esc.getUserID(username)

    def getUsername(self,userid):
        return self.esc.getUsername(userid)
