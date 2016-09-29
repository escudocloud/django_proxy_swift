#!/usr/bin/env python
import os
from config import *
from escudo_user_properties import EscudoUserProperties

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as kc
from barbicanclient import client as bc

auth = v3.Password(auth_url=AUTH_URL, username="admin",
                     password="secretsecret", project_name="demo",
                     user_domain_id="default", project_domain_id="default")
sess = session.Session(auth=auth)
barbican = bc.Client(session=sess)
keystone = kc.Client(session=sess)
while(True):
    try:
        print('\nUser creation...\n\n')
        for i in range (1,6):
            u = EscudoUserProperties('demo:enctest'+str(i),'enctest'+str(i),barbican,keystone)
            u.create_user()
        #u = EscudoUserProperties('demo:swift','secretsecret',barbican,keystone)
        #u.create_user()
        break
        
    except SyntaxError:
        continue
        

    
