#!/usr/bin/env python
# -*- coding: utf-8 -*-

from swiftclient import client
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as kc
from keystoneclient.v3 import tokens
from config import *

class EncSwiftclientAPI:

    def __init__(self, auth_token, project_id):
        self.aut =  auth_token
        self.pro =  project_id
       
        print "OPOPOPOPOP"
        print "%s/AUTH_%s"%(STORAGE_URL,str(project_id))
        self.esc = client.Connection(preauthtoken=auth_token,preauthurl="%s/AUTH_%s"%(STORAGE_URL,str(project_id)), auth_version='3')

    def put_container(self, container, headers=None):
        return self.esc.put_container(container, headers)

    def delete_container(self, container):
        return self.esc.delete_container(container)

    def post_container(self, container, headers=None):
        print "container",container
        print "headers", headers
        print self.aut 
        print self.pro
        try:
            a = self.esc.post_container(container, headers)
            print a, "FINITA LA POST"
        except Exception, err:
            print Exception, err
        print "RETURN A"
        return a
        #return client.post_container(token = self.aut,url = "http://127.0.0.1:8001/AUTH_%" %self.pro,container=container,headers=headers)
    def head_container(self, container):
        return self.esc.head_container(container)

    def get_container(self, container, delimiter=None, prefix=None, marker= None):
        return self.esc.get_container(container, marker=marker, delimiter=delimiter, prefix=prefix)

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
        """
        Get the user ID from Keystone
        param: username
        """
        auth_obj = v3.Token(auth_url=AUTH_URL, token=self.aut,  project_domain_name="Default",project_id=self.pro)
        sess = session.Session(auth=auth_obj)
        kc_conn = kc.Client(session=sess)
        ret_id = filter(lambda x: x.name == username, kc_conn.users.list())
        print ret_id
        print ret_id[0].id
        return ret_id[0].id

    def getUsername(self,userid):
        """
        Get the username from Keystone
        param: user ID
        """
        auth_obj = v3.Token(auth_url=AUTH_URL, token=self.aut,  project_domain_name="Default",project_id=self.pro)
        sess = session.Session(auth=auth_obj)
        kc_conn = kc.Client(session=sess)
        username = kc_conn.users.get(userid).name
        return username
