#!/usr/bin/env python

import json, base64
from itertools import *
from config import *

from keystoneauth1.identity import v3
from keystoneclient import session
from keystoneclient import client as kc
from barbicanclient import client as bc

from key_manager import key_manager
from myLogger import *

class sec_manager:

    def __init__(self, sess, iduser):
    
        self.iduser = iduser
        
        self.barbican = bc.Client(session=sess)
        self.keystone = kc.Client(session=sess)
        self.key_manager = key_manager(self.barbican,self.keystone)

    def store_secrets (self, container_ref, list_receivers, node, DEK_id):
        """
        Update the catalogs storing the secrets in Barbican
        Args:
            container_ref: reference of the container 
            list_receivers: receivers to notify
            node: catalog node to send 
            DEK_id: key id to send
        """
        if DEK_id is None:
            return None

        container = self.barbican.containers.create(name=node['IDCONTAINER'])
         
        if container_ref is not None:
            container_ref = "%s/containers/%s" %(BARBICAN_URL,container_ref)
            #Add keys already in the old container keys
            old_container = self.barbican.containers.get(container_ref)
            secrets = old_container.secrets
            for sec in secrets.keys():
                container.add(sec,secrets[sec])
             
        ciph_node = node.copy()  
        for rec in list_receivers:
            if ciph_node:
                #Encrypt kek and sign it
                kek, signature = self.key_manager.encrypt_DEK(secret=node['KEK'], sender=self.iduser,receiver=rec)
                ciph_node['KEK'] = base64.b64encode(kek)
                ciph_node['SIGNATURE'] = base64.b64encode(signature)
                key_id = str(DEK_id)+str(rec)
                secret = self.barbican.secrets.create(name=key_id,payload=json.dumps(ciph_node))
                secret.store()
                try:
                    container.add(key_id,secret)
                except:
                    continue
        container.store()
        container_ref = container.container_ref[container.container_ref.find('containers/')+11:]
        return container_ref

    def get_secret(self, iduser,container_ref,idkey):
        """
        Get the key value from barbican
        Args:
            iduser: user's id
            container_ref: the reference of the container
            idkey: the id of the key to find
        """
        container_ref = "%s/containers/%s" %(BARBICAN_URL,container_ref)
        container = self.barbican.containers.get(container_ref)
        idkey = str(idkey) + str(iduser)
        #container.secrets contains all the references to secrets
        for sec in container.secrets.keys():
            if sec == idkey:
                secret_node = self.barbican.secrets.get(container.secrets[sec].secret_ref)
                secret_node = json.loads(secret_node.payload)
                node = secret_node.copy()
                if node:
                    dek = self.key_manager.decrypt_KEK(secret=base64.b64decode('%s' % node['KEK']),signature=base64.b64decode('%s' % node['SIGNATURE']), sender=node['OWNERID'],receiver=iduser)
                    node['KEK'] = dek
                    return node
    
    def create_node (self, iduser, idcontainer):
        """
        Create a new node to put into the user catalog.
        The node includes the KEK, the owner id and the container id
        Args:
            iduser: The user id
            idcontainer: The container id
        Returns:
            idkey: the KEK id
            obj: the created node
        """
        DEK_id, dek = self.key_manager.generate_container_key()
        obj = {}
        obj['KEK'] = base64.b64encode(dek)
        obj['IDCONTAINER'] = idcontainer
        obj['OWNERID'] = iduser
        return DEK_id, obj # clear token in obj



