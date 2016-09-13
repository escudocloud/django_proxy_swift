#!/usr/bin/env python

from config import *
from simpleKeystoneClient import SimpleKeystoneClient

class CreateUser:

    def __init__(self, user_name, user_password, user_tenant, dict_pub_keys, user_role, authurl):
        # Simple Keystone Client
        self.client = SimpleKeystoneClient("admin", "secretsecret", "demo", authurl)
        self.user = user_name
        self.password = user_password
        self.tenant = user_tenant
        self.pub_keys = dict_pub_keys
        self.role = user_role
        self.url = authurl

    def start(self):
        """
        Create the new user, creating the tenant 
        Add user role to the tenant 
        """
        us_role = self.client.ks_client.roles.find(name=self.role)
        observer_role = self.client.ks_client.roles.find(name="observer")
        creator_role = self.client.ks_client.roles.find(name="creator")
        # Find or create user tenant
        tenant = self.client.create_tenant(name=self.tenant)

        # Create user
        user = self.client.create_user(self.user, self.password, self.tenant, description=self.pub_keys)
        print self.pub_keys
        # Set role to the user
        self.client.add_user_role(user, us_role, tenant)
        self.client.add_user_role(user, observer_role, tenant)
        self.client.add_user_role(user, creator_role, tenant)

