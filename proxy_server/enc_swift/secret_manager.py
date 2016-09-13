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

    def __init__(self, auth_token, iduser):
    
        self.iduser = iduser
        
        self.auth = v3.Token(auth_url=AUTH_URL,token=auth_token,project_name='demo',project_domain_id="default")
        sess = session.Session(auth=self.auth)
        self.barbican = bc.Client(session=sess)
        self.keystone = kc.Client(session=sess)
        self.key_manager = key_manager(self.barbican,self.keystone)

    def store_secrets (self, container_ref, list_receivers, node, DEK_id):
        """
        Send message to daemon to update the catalogs
        Args:
            list_receivers: receivers to notify
            node: catalog node to send 
            DEK_id: key id to send
        """
        if DEK_id is None:
            return None

        container = self.barbican.containers.create(name=node['IDCONTAINER'])
         
        if container_ref is not None:
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
        return container.container_ref

    def get_secret(self, iduser,container_ref,idkey):
        print iduser, container_ref, idkey
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
        
    #Not used any more ?        
    def get_catalog (self, iduser):
        """
        Get the catalog from the meta-container
        Args:
            iduser: The user id 
        Returns:
            json_data_catalog: User catalog (json format)
        """
        CatContainer = '.Cat_usr%s' % iduser
        CatSource = '$cat_graph%s.json' % iduser
        try:
            hdrs, json_data_catalog = self.key_manager.meta_conn.get_object(CatContainer, CatSource)
        except: 
            logger.debug("Error in get catalog")
            json_data_catalog = '{}'
        return json_data_catalog

    def load_catalog(self, iduser):
        """
        Load the catalog (json format) into the cat variable
        Args:
            iduser: The user id
        Returns:
            cat: The user catalog in json format 
        """
        cat = self.get_catalog(iduser)
        return json.loads(cat)
        
    def get_cat_node (self, iduser,idkey):
        """
        Load the catalog and get a node with idkey from it
        Args:
            iduser: The user id
            idkey: The KEK id
        Returns:
            node: The stored node, with the correspondent DEK
        """
        cat = self.load_catalog(iduser)
        return self.get_node(cat,iduser,idkey)

    def get_node(self, cat,iduser,idkey):
        """
        Get a node with idkey from the user catalog
        Args:
            cat: The user catalog
            iduser: The user id
            idkey: The KEK id
        Returns:
            node: The stored node, with the correspondent DEK
        """
        _node = cat.get(idkey,{})
        node = _node.copy()
        if node:
            dek = self.key_manager.decrypt_KEK(secret=base64.b64decode('%s' % node['KEK']),signature=base64.b64decode('%s' % node['SIGNATURE']), sender=node['OWNERID'],receiver=iduser)
            node['KEK'] = dek
        return node # return a node with a clear key



