#!/usr/bin/env python

import ast, base64, json
from secret_manager import sec_manager
from Crypto.PublicKey import RSA
from swiftclient import client
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as kc
from keystoneclient.v3 import tokens
from config import *
from myLogger import *

class EncSwiftclient:

    def __init__(self, auth_token, project_id):
        auth_obj = v3.Token(auth_url=AUTH_URL, token=auth_token,  project_domain_name="Default",project_id=project_id)
        #auth_obj = v3.Password(auth_url=AUTH_URL, username='enctest1',password='enctest1', project_domain_name="Default",user_domain_name="Default", project_name="demo")
        sess = session.Session(auth=auth_obj)
        #Store auth_token
        self.auth = auth_token
        #Retrieve tenant id
        self.idtenant = project_id#sess.get_project_id()
        
        self.kc_conn = kc.Client(session=sess)
        
        storage_url = '%s/AUTH_%s' %(STORAGE_URL,str(self.idtenant))
        self.swift_conn = client.Connection(preauthtoken=auth_token,preauthurl=storage_url, auth_version='3')
        # Connection to daemon only to retrieve users' ID 
        self.iduser = sess.get_user_id()     
        #self.iduser   = self.getUserID(user_name)
        self.SWIFT_ID = self.getUserID(SWIFT_USER)
                
        #Key manager instance 
        self.sec_manager = sec_manager(auth_token,self.iduser)

    def getUserID(self,username):
        """
        Get the user ID from Keystone
        param: username
        """
        ret_id = filter(lambda x: x.name == username, self.kc_conn.users.list())[0]
        return ret_id.id
        #resp = sender().send_message('get_id','#'.join([self.auth,username]))
        #return resp.content

    def getUsername(self,userid):
        """
        Get the username from Keystone
        param: user ID
        """
        username = self.kc_conn.users.get(userid).name
        return username
        #resp = sender().send_message('get_name','#'.join([self.auth,userid]))
        #return resp.content
            
    def get_enc_object (self,container,obj):
        """
        Get an object from a specific container
        Decrypt the object with the DEK retrieved from the catalog
        Args:
            container: the name of the container
            obj: the object name
        """
        try:
            #Obtain container headers and keys id
            cont_header = self.head_container(container)
        
            actual_acl = self.extractACL(cont_header)
            
            #Control ACL on the client side on private containers
            if actual_acl and (self.iduser not in actual_acl):
                return         
            
            #catalog = self.sec_manager.load_catalog(self.iduser)
            
            hdrs, content = self.swift_conn.get_object(container,obj)
        except Exception,err:
            logger.info("Error in get_enc_object")
            return
   
        container_sel_id = cont_header.get('x-container-meta-sel-id',None)
        container_ref = cont_header.get('x-container-meta-container-ref',None)
        object_bel_id = hdrs.get('x-object-meta-bel-id',None)
        object_sel_id = hdrs.get('x-object-meta-sel-id',None)

        if object_bel_id is None:
            #Clear object stored
            logger.debug('Clear content >>> %s' % content)
            return hdrs, str(content)
            
        # Decrypt object with SEL dek (if exists)
        try:
            if container_sel_id is not None:# and container_sel_id != hdrs.get('x-object-meta-sel-id',None):
                sel_DEK = self.sec_manager.get_secret(self.iduser,container_ref, container_sel_id).get('KEK',None)
                if sel_DEK is not None:
                    logger.debug('Content encrypted with SEL >>> %s\n' % content)
                    content = self.sec_manager.key_manager.decrypt_msg(str(content),sel_DEK)
                else:
                    logger.info("You cannot obtain this object")
                    return
        except:
            logger.error('Decrypt msg (SEL)')
            return

        # Decrypt object with BEL dek
        #try:
        bel_DEK = self.sec_manager.get_secret(self.iduser,container_ref,object_bel_id).get('KEK',None)
        if bel_DEK is not None:
            logger.debug('Content encrypted with BEL >>> %s\n' % content)     
            content = self.sec_manager.key_manager.decrypt_msg(str(content), bel_DEK)
        logger.debug('Clear content >>> %s' % content)
        return hdrs, str(content)
        #except:
        #    logger.error('Decrypt msg (BEL)')
        #    return
    
    def add_user_to_acl(self,headers,meta,usrID):
        """
        Add user usrID to acl included in headers
        """
        acl = self.extractACL_param(headers,meta)
        acl.append(unicode(usrID))
        acl = list(set(acl))
        return str({self.idtenant: acl})
    
    def put_enc_container (self,container, headers= None):

        """
        Create a container with a specific ACL and a DEK for that.
        Args:
            container: the name of the new cont ainer
            headers: the metadata for this container
        """
        if headers is None or not self.extractACL(headers):
            try:
                #Put container without encryption option 
                self.swift_conn.put_container(container)
            except:
                logger.info("Error in Put container")
            return
        
        #Add self user id to acl
        headers['x-container-read'] = self.add_user_to_acl(headers,'x-container-read' ,self.iduser)
        headers['x-container-write']= self.add_user_to_acl(headers,'x-container-write',self.iduser)
        listACL = self.extractACL(headers)
       
        try:
            #Return if container exists
            self.head_container(container)
            logger.info("Container already created")
        except:
            #Create catalog node (new BEL DEK associated to the container)
            bel_DEK_id, obj = self.sec_manager.create_node(self.iduser, container)
            # Send messages (for updating the graph)
            container_ref = self.sec_manager.store_secrets(None,listACL,obj,bel_DEK_id)
            
            #if self.send_message(listACL, obj, bel_DEK_id)!= 200:
            #    logger.info('Error in send_message')
            #    return

            # Create container
            try:
                headers['x-container-meta-container-ref'] = container_ref
                headers['x-container-meta-bel-id'] = bel_DEK_id
                self.swift_conn.put_container(container, headers=headers)
                logger.info("Container %s created" % container)
            except:
                logger.info('Error put new container')

    def encrypt_obj(self,container_ref,bel_DEK_id, content):
        """
        Retrieve BEL DEK from the catalog
        Encrypt the object
        """
        bel_DEK = self.sec_manager.get_secret(self.iduser,container_ref, bel_DEK_id).get('KEK',None)
        if bel_DEK is None:
            return None
        
        return self.sec_manager.key_manager.encrypt_msg(str(content),bel_DEK)

    def put_enc_object (self,container,obj_name,content):
        """
        Put an object into a specific container
        Encrypt the object with the DEK retrieved from the catalog
        Args:
            container: the name of the container
            obj_name: the object name
            content: object content
        """
        try:
            resp_header = self.head_container(container)
            actual_acl = self.extractACL(resp_header)
            
            #Permitted upload of clear objects
            if not actual_acl:
                self.swift_conn.put_object(container, obj_name, content)
                return
        except:
            logger.info("Error in Put Object (container header)") 
            return

        #Not allowed Put
        if self.iduser not in actual_acl:
            return
            
        sel_DEK_id = resp_header.get('x-container-meta-sel-id', None)
        version_sel_DEK = resp_header.get('x-container-meta-sel-version',0)
        bel_DEK_id = resp_header.get('x-container-meta-bel-id', None)
        container_ref = resp_header.get('x-container-meta-container-ref',None)
        enc_content = self.encrypt_obj(container_ref, bel_DEK_id,content)
        
        #Transient phase. No correct BEL key in the catalog
        if enc_content is None:
            logger.info("You have not the rights to access the container yet")
            return  
        
        obj_headers = {}
        
        #If SEL applied, update object headers
        if sel_DEK_id is not None:
            obj_headers['x-object-meta-sel-id'] = sel_DEK_id
            obj_headers['x-object-meta-sel-version'] = version_sel_DEK
        obj_headers['x-object-meta-bel-id'] = bel_DEK_id
          
        try:    
            # Put object
            self.swift_conn.put_object(container, obj_name, enc_content,headers=obj_headers)
            logger.info("Object %s uploaded" % obj_name)
        except Exception,err:
            print Exception,err
            logger.info("Error in Put Object")

    def postcontainer_public_to_private(self,container,headers,new_acl):
        """
        Change a container visibility. A public container becomes private.
        All the objects must be ciphered with a new BEL DEK
        """
        #Add self.iduser to new_acl
        new_acl.append(unicode(self.iduser))
        new_acl = list(set(new_acl))
        #Create a new BEL key
        bel_id, obj_bel = self.sec_manager.create_node(self.iduser, container)
        # Send messages (for updating the graph)
        #if self.send_message(new_acl, obj_bel, bel_id)!= 200:
        #    logger.info('Error in send_message')
        #    return
        container_ref = self.sec_manager.store_secrets(None,new_acl,obj_bel,bel_id)
        cont_headers={}
        cont_headers['x-container-meta-container-ref'] = container_ref
        cont_headers['x-container-meta-bel-id'] = str(bel_id)
        cont_headers['x-container-read'] = self.add_user_to_acl(headers,'X-Container-Read' ,self.iduser)
        cont_headers['x-container-write']= self.add_user_to_acl(headers,'X-Container-Write',self.iduser)
        try:
            # Post header container
            self.swift_conn.post_container(container,headers=cont_headers)
            #Download the objects and upload them ciphered with BEL key
            head, list_obj = self.get_container(container)
            for obj in list_obj:
                if obj['name'][-1] != '/' or obj['content_type'] != 'application/directory':
                   head, content = self.swift_conn.get_object(container, obj['name'])
                   self.put_enc_object(container,obj['name'],content)  
        except Exception,err:
            print Exception,err
            logger.info("Error in post container (become private)")

    def postcontainer_private_to_public(self,container,headers):
        """
        Change a container visibility. A private container becomes public.
        All the objects must be deciphered and uploaded clear
        """
        #Remove acl and key information from container headers
        headers[u'x-container-meta-sel-id']= u''
        headers[u'x-container-meta-sel-acl']= u''
        headers[u'x-container-meta-sel-version']= u''
        headers[u'x-container-meta-bel-id']= u''
        headers[u'X-Container-Read']= u''
        headers[u'X-Container-Write']= u''
        
        try:
            self.swift_conn.post_container(container,headers=headers)
    
            #Download the objects and upload them clear
            head, list_obj = self.get_container(container)
            for obj in list_obj:
                if obj['name'][-1] != '/' or obj['content_type'] != 'application/directory':
                    head, content = self.get_enc_object(container, obj['name'])
                    self.swift_conn.put_object(container,obj['name'],content)
        except:
            logger.info("Error in post container (become public)")

    def store_actual_BEL_DEKs(self,cont_secret_ref,container_name,added_users,actual_bel_id):
        """
        Send the BEL DEKs, protecting all the objects included in the container, to all the added users 
        
        """
        #Retrieve all the BEL keys
        
        dict_bel_DEKs = self.retrieve_bel_DEKs(container_name,cont_secret_ref)
        #Add BEL container DEK if no object has been uploaded
        dict_bel_DEKs[actual_bel_id] = self.sec_manager.get_secret(self.iduser,cont_secret_ref,actual_bel_id)
        new_cont_secret_ref = cont_secret_ref
        for bel_DEK_id,obj in dict_bel_DEKs.items():
            #Send messages
            new_cont_secret_ref = self.sec_manager.store_secrets(cont_secret_ref,added_users,obj,bel_DEK_id)
        return new_cont_secret_ref

    def postcontainer_changepolicy(self, container_name, headers, actual_head, new_acl, actual_acl):
        """
        Change policy (add or revoke users) on a container
        Apply Over-encryption if config.OVER_ENCRYPTION is set True
        """
        #Add user id to acl 
        headers['X-Container-Read'] = self.add_user_to_acl(headers,'X-Container-Read' ,self.iduser)
        headers['X-Container-Write']= self.add_user_to_acl(headers,'X-Container-Write',self.iduser)
        new_acl.append(unicode(self.iduser))
        new_acl = list(set(new_acl))
        
        #Retrieve SEL information
        initial_acl_sel = self.extractACL_param(actual_head,'x-container-meta-sel-acl')
        version_sel_DEK = actual_head.get("x-container-meta-sel-version",'0')
        actual_sel_id   = actual_head.get('x-container-meta-sel-id',None)
        cont_secret_ref = actual_head.get('x-container-meta-container-ref',None)
        new_cont_secret_ref = cont_secret_ref
        removed_users = list(set(actual_acl).difference(new_acl))
        added_users   = list(set(new_acl).difference(actual_acl))
        #try:
        if added_users:
            #Send the BEL DEKs protecting the objects included in the container, to all the added users
            new_cont_secret_ref = self.store_actual_BEL_DEKs(cont_secret_ref,container_name,added_users,actual_head['x-container-meta-bel-id'])
            headers['x-container-meta-container-ref'] = new_cont_secret_ref
            if not removed_users and OVER_ENCRYPTION: 
                if not set(new_acl).issuperset(set(initial_acl_sel)):
                    #No change to the actual protection layers
                    if initial_acl_sel:
                        new_list = list(set(initial_acl_sel + added_users))
                        headers['x-container-meta-sel-acl'] = str({self.idtenant : map(lambda x: "AUTH_" + str(x),new_list)})
                    new_cont_secret_ref = self.sec_manager.store_secrets(new_cont_secret_ref,added_users,self.sec_manager.get_secret(self.iduser,new_cont_secret_ref,actual_sel_id),actual_sel_id)
                    headers['x-container-meta-container-ref'] = new_cont_secret_ref
                else:
                    #Remove SEL protection (if exists)
                    headers[u'x-container-meta-sel-id']= u''
                    headers[u'x-container-meta-sel-acl']= u''
                    headers[u'x-container-meta-sel-version']= u''
                    #self.send_message(actual_acl + [self.SWIFT_ID],{},actual_sel_id)
        if removed_users:
            bel_id, obj_bel = self.sec_manager.create_node(self.iduser, container_name)
            headers['x-container-meta-bel-id'] = str(bel_id)
            new_cont_secret_ref = self.sec_manager.store_secrets(new_cont_secret_ref,new_acl,obj_bel,bel_id)
            headers['x-container-meta-container-ref'] = new_cont_secret_ref
            if not OVER_ENCRYPTION:
                #Only BEL option: download all the files, re-encrypt and upload them 
                self.swift_conn.post_container(container_name,headers=headers)
                head, list_obj = self.get_container(container_name)
                for obj in list_obj:
                    if obj['name'][-1] != '/' or obj['content_type'] != 'application/directory':
                        head, content = self.get_enc_object(container_name, obj['name'])
                        self.put_enc_object(container_name,obj['name'],content)
                return
            if OVER_ENCRYPTION:
                #Apply a new Surface Encryption Layer
                sel_id, obj_sel = self.sec_manager.create_node(self.iduser, container_name)
                init_acl = list(set(initial_acl_sel + added_users)) if initial_acl_sel else list(set(new_acl + actual_acl))
                headers['x-container-meta-sel-id'] = str(sel_id)
                headers['x-container-meta-sel-acl'] = str({self.idtenant:map(lambda x:"AUTH_"+str(x), init_acl)})
                headers['x-container-meta-sel-version'] = str(eval(version_sel_DEK)+1)
                new_cont_secret_ref = self.sec_manager.store_secrets(new_cont_secret_ref, new_acl+ [self.SWIFT_ID],obj_sel,sel_id)
                headers['x-container-meta-container-ref'] = new_cont_secret_ref
                #new_cont_secret_ref = self.send_message(new_cont_secret_ref, actual_acl + [self.SWIFT_ID],{},actual_sel_id)!= 200:
        self.swift_conn.post_container(container_name,headers=headers)
        """except Exception, err:
            print Exception,err
            logger.debug("Error in Post container.")
            raise Exception"""

    def post_enc_container (self,container,headers):
        """
        Change headers of a specific container
        Args:
            container: the name of the container
            headers: the metadata for this container
        """
        if type(headers) is not dict:
            headers = {}

        actual_head = self.head_container(container)
        actual_acl = sorted(self.extractACL(actual_head))
        new_acl = sorted(self.extractACL(headers))
        if not actual_acl and not new_acl:
            #Container not ciphered yet. It has to remain public
            try:
                # Change Swift not encrypted container headers:
                self.swift_conn.post_container(container, headers)
                return
            except:
                logger.error("Post container (not encrypted)")
        
        if not actual_acl and new_acl:
            #Container not ciphered yet. It has to become private
            self.postcontainer_public_to_private(container, headers, new_acl)
 
        if actual_acl and not new_acl:
            #Container already ciphered. It has to become public
            self.postcontainer_private_to_public(container,headers)

 
        if actual_acl and new_acl:
            #Container already ciphered. It has to remain private
            self.postcontainer_changepolicy(container,headers, actual_head, new_acl,actual_acl)
                 
            
    def retrieve_bel_DEKs(self,container,cont_secret_ref):
        """
        Retrieve the DEKs used for the object in the container
        Args:
            container: the name of the container
            cat: User catalog
        Returns:
            dic: A dictionary with all the DEKs use in the container 
        """
        dic = {}
        #Obtain objects list
        headers, list_obj = self.get_container(container)
        for obj in list_obj:
            if obj['name'][-1] != '/' or obj['content_type'] != 'application/directory':
                #Obtain each BEL key from own catalog
                header = self.head_object(container, obj['name'])
                bel_DEK_id = header['x-object-meta-bel-id']
                dic[bel_DEK_id] = self.sec_manager.get_secret(self.iduser,cont_secret_ref,bel_DEK_id)
        return dic
         
    def extractACL_param(self, headers,meta):
        """
        Extract the ACL from the container headers with the meta parameter
        """
        # Get ACLs from the headers
        acl = ast.literal_eval(headers.get(meta, '{}'))
        list_acl = reduce(lambda x, y: x + y, acl.values(), [])
        # Remove duplicates:
        list_acl = list(set(list_acl))
        # Remove AUTH_ from names
        list_clean = map(lambda x: x.replace('AUTH_', ''), list_acl)
        return list_clean

    def extractACL(self, headers):
        """
        Extract the ACL from the container headers
        """
        # Get ACLs from the headers
        if headers.has_key('x-container-read'):
            acl_read = ast.literal_eval(headers['x-container-read'])
        elif headers.has_key('X-Container-Read'):
            acl_read = ast.literal_eval(headers['X-Container-Read'])
        else:
            acl_read = {}
        if headers.has_key('x-container-write'):
            acl_write = ast.literal_eval(headers['x-container-write'])
        elif headers.has_key('X-Container-Write'):
            acl_write = ast.literal_eval(headers['X-Container-Write'])
        else:
            acl_write = {}
        acl = reduce(lambda x, y: x + y, acl_read.values(), []) + reduce(lambda x, y: x + y, acl_write.values(), [])
        # Remove duplicates:
        acl = list(set(acl))
        # Remove AUTH_ from names
        acl_clean = map(lambda x: x.replace('AUTH_', ''), acl)
        return acl_clean

    def get_container (self, container, marker=None, delimiter=None, prefix=None):
        return self.swift_conn.get_container(container, marker=marker, delimiter=delimiter, prefix=prefix)

    def get_account (self):
        account, containers = self.swift_conn.get_account()
        list_cont = []
        for cont in containers:
            cont_name = cont.get('name','')
            headers = self.head_container(cont_name)
            list_acl = self.extractACL(headers)
            if list_acl == [] or (self.iduser in list_acl):
                list_cont.append(cont)
        return account, list_cont

    def delete_object(self, container, obj):
        if obj[-1] == '/':# or obj['content_type'] != 'application/directory':
            meta, objects = self.get_container(container, marker=None, delimiter='/', prefix=obj)
            if len(objects) > 1:
                # pseudofolder is not empty
                raise Exception
                return
        return self.swift_conn.delete_object(container, obj)

    def head_object(self, container, obj):
        return self.swift_conn.head_object(container, obj)

    def post_object(self, container, obj, headers):
        return self.swift_conn.post_object(container, obj, headers)

    def head_container(self, container):
        return self.swift_conn.head_container(container)

    def delete_container(self, container):
        return self.swift_conn.delete_container(container)

