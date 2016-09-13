#!/usr/bin/env python

from keystoneclient.exceptions import NotFound, Conflict
from keystoneauth1.identity import v3
from keystoneclient.auth import identity
from keystoneclient import session
from keystoneclient.v3 import client

from myLogger import *

class SimpleKeystoneClient:
    """
    Add enc functions to creation request 
    """
    def __init__(self, admin_user, admin_pass, admin_tenant, auth_url):
        auth = v3.Password(auth_url=auth_url, username=admin_user,
                     password=admin_pass, project_name=admin_tenant,
                     user_domain_id="default", project_domain_id="default")
        sess = session.Session(auth=auth)
        self.ks_client = client.Client(session=sess)

    def create_tenant(self, name, **kwargs):
        try:
            project = self.ks_client.projects.find(name=name)
            logger.info('Project %s exists [id: %s].' % (name, project.id))
        except NotFound:
            project = self.ks_client.projects.create(name=name, domain="default",**kwargs)
            logger.info('Project %s created [id: %s].' % (name, project.id))
        return project

    def create_user(self, name, password, tenant_name, **kwargs):
        try:
            user = self.ks_client.users.find(name=name)
            logger.info('User %s exists (password unchanged).' % name)
        except NotFound:
            tenant = self.create_tenant(tenant_name)
            user = self.ks_client.users.create(name=name, password=password,
                                               tenant_id=tenant.id, **kwargs)
            logger.info('User %s created.' % name)
        return user

    def create_role(self, role_name, **kwargs):
        try:
            role = self.ks_client.roles.find(name=role_name)
            logger.info('Role %s exists.' % role_name)
        except NotFound:
            role = self.ks_client.roles.create(role_name, **kwargs)
            logger.info('Role %s created.' % role_name)
        return role

    def add_user_role(self, user, role, tenant, **kwargs):
        try:
            self.ks_client.roles.grant(user=user, role =role, project =tenant,**kwargs)
            logger.info('Role given to user.')
        except Conflict:
            logger.info('User already has the requested role.')
