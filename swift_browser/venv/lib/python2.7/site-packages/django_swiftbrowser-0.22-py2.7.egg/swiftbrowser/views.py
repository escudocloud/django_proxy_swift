""" Standalone webinterface for Openstack Swift. """
# -*- coding: utf-8 -*-
import os, random
import time
import urlparse
import hmac, ast
import traceback
from hashlib import sha1
from keystoneauth1.identity import v3
from keystoneauth1 import session
from swiftclient import client

from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.contrib import messages
from django.conf import settings
from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse

from django.core.files.base import ContentFile 
from django.http import HttpResponse
from wsgiref.util import FileWrapper

from swiftbrowser.forms import CreateContainerForm, PseudoFolderForm, \
    LoginForm, AddACLForm
from swiftbrowser.utils import replace_hyphens, prefix_list, \
    pseudofolder_object_list, get_temp_key, get_base_url, get_temp_url

import swiftbrowser
from swiftbrowser.enc_swiftclient_API import EncSwiftclientAPI
from swiftbrowser.config import *


def login(request):
    """ Tries to login user and sets session data """
    request.session.flush()
    form = LoginForm(request.POST or None)
    
    if form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        try:
            auth_version = settings.SWIFT_AUTH_VERSION or 1
            
            user = username[username.find(':')+1:]
            project = username[:username.find(':')]
            auth_obj = v3.Password(auth_url=AUTH_URL, username=user,password=password, project_domain_name="Default",  user_domain_name="Default", project_name=project)
            sess = session.Session(auth=auth_obj)
            auth_token = sess.get_token()
            project_id = sess.get_project_id()
            storage_url = '%s/AUTH_%s' %(STORAGE_URL, str(sess.get_project_id()))
            #(storage_url, auth_token) = client.get_auth(
            #    settings.SWIFT_AUTH_URL, username, password,
            #    auth_version=auth_version)
            #(meta_storage_url, meta_auth_token) = client.get_auth(
            #    settings.SWIFT_AUTH_URL, META_TENANT + username[username.find(':'):], password,
            #    auth_version=auth_version)
            request.session['auth_token'] = auth_token
            #request.session['meta_auth_token'] = meta_auth_token
            request.session['storage_url'] = storage_url
            #request.session['meta_storage_url'] = meta_storage_url
            request.session['project_id'] = project_id
            request.session['username'] = user
            request.session['name'] = user
            return redirect(containerview)

        except client.ClientException:
            traceback.print_exc()
            messages.add_message(request, messages.ERROR, _("Login failed."))
        except Exception,err:
            print Exception, err

    return render_to_response('login.html', {'form': form, },
                              context_instance=RequestContext(request))

def containerview(request):
    """ Returns a list of all containers in current account. """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    if not storage_url or not auth_token:
        return redirect(login)

    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        account_stat, containers = conn.get_account()
    except client.ClientException as exc:
        traceback.print_exc()
        if exc.http_status == 403:
            account_stat = {}
            containers = []
            base_url = get_base_url(request)
            msg = 'Container listing failed. You can manually choose a known '
            msg += 'container by appending the name to the URL, for example: '
            msg += '<a href="%s/objects/containername">' % base_url
            msg += '%s/objects/containername</a>' % base_url
            messages.add_message(request, messages.ERROR, msg)
        else:
            return redirect(login)
    except Exception:
        traceback.print_exc()
        return redirect(login)

    account_stat = replace_hyphens(account_stat)

    return render_to_response('containerview.html', {
        'account_stat': account_stat,
        'containers': containers,
        'session': request.session,
    }, context_instance=RequestContext(request))


def create_container(request):
    """ Creates a container (empty object of type application/directory) """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    form = CreateContainerForm(request.POST or None)
    if form.is_valid():
        container = form.cleaned_data['containername']
        try:
            conn = EncSwiftclientAPI(auth_token, project_id)
            conn.put_container(container)
            messages.add_message(request, messages.INFO,
                                 _("Container created."))
        except client.ClientException:
            traceback.print_exc()
            messages.add_message(request, messages.ERROR, _("Access denied."))
        except Exception:
            traceback.print_exc()
            messages.add_message(request, messages.ERROR, _("Something goes wrong. Try again!"))

        return redirect(containerview)

    return render_to_response('create_container.html', {
        'session': request.session,
    }, context_instance=RequestContext(request))


def delete_container(request, container):
    """ Deletes a container """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        conn.delete_container(container)
        messages.add_message(request, messages.INFO, _("Container deleted."))
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied. If there are some files in %s, before delete them!" % container))

    return redirect(containerview)


def objectview(request, container, prefix=None):
    """ Returns list of all objects in current container. """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        meta, objects = conn.get_container(container, delimiter='/',
                                           prefix=prefix)
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))
        return redirect(containerview)

    prefixes = prefix_list(prefix)
    pseudofolders, objs = pseudofolder_object_list(objects, prefix)
    base_url = get_base_url(request)
    account = storage_url.split('/')[-1]

    read_acl = meta.get('x-container-read', '').split(',')
    public = False
    required_acl = ['.r:*', '.rlistings']
    if [x for x in read_acl if x in required_acl]:
        public = True

    return render_to_response("objectview.html", {
        'container': container,
        'objects': objs,
        'folders': pseudofolders,
        'session': request.session,
        'prefix': prefix,
        'prefixes': prefixes,
        'base_url': base_url,
        'account': account,
        'public': public},
        context_instance=RequestContext(request))


def upload(request, container, prefix=None):
    """ Display upload form using swift formpost """
    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    redirect_url = get_base_url(request)
    redirect_url += reverse('objectview', kwargs={'container': container, })

    swift_url = storage_url + '/' + container + '/'
    
    if prefix:
        swift_url += prefix
        redirect_url += prefix
    url_parts = urlparse.urlparse(swift_url)
    path = url_parts.path

    max_file_size = 5 * 1024 * 1024 * 1024
    max_file_count = 1
    expires = int(time.time() + 15 * 60)
    key = get_temp_key(storage_url, auth_token)
    if not key:
        messages.add_message(request, messages.ERROR, _("Access denied."))
        if prefix:
            return redirect(objectview, container=container, prefix=prefix)
        else:
            return redirect(objectview, container=container)

    hmac_body = '%s\n%s\n%s\n%s\n%s' % (
        path, redirect_url, max_file_size, max_file_count, expires)
    signature = hmac.new(str(key), str(hmac_body), sha1).hexdigest()

    prefixes = prefix_list(prefix)
    
    return render_to_response('upload_form.html', {
                              'swift_url': swift_url,
                              'redirect_url': redirect_url,
                              'max_file_size': max_file_size,
                              'max_file_count': max_file_count,
                              'expires': expires,
                              'signature': signature,
                              'container': container,
                              'prefix': prefix,
                              'prefixes': prefixes,
                              'session': request.session,
                              }, context_instance=RequestContext(request))

def put_object(request,container,prefix=None):

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    
    redirect_url = get_base_url(request)
    redirect_url += reverse('objectview', kwargs={'container': container, })
    
    data = request.FILES.get('file1','')
    if data == '':
        messages.add_message(request, messages.ERROR, _("Wrong File. Select it again."))
        if prefix:
            return redirect(upload, container=container, prefix=prefix)
        else:
            return redirect(upload, container=container)

    
    if prefix:
        obj_url = prefix + data.name
        redirect_url += prefix
    else: obj_url = data.name

    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        conn.put_object(container,obj_url,data.read())
        messages.add_message(request, messages.INFO, _("Object uploaded."))
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Upload denied."))
        return redirect(containerview)
    except Exception:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Something goes wrong. Try again!"))
        return redirect(containerview)

    return redirect(redirect_url)
    

def download_dec(request, container, objectname):
    """ Download an object (clear content) from Swift """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    
    redirect_url = get_base_url(request)
    redirect_url += reverse('objectview', kwargs={'container': container, })

    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        header, obj = conn.get_object(container, objectname)
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))
        return redirect(objectview, container=container)
    except Exception:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Something goes wrong. Try again!"))
        return redirect(objectview, container=container)

    response = HttpResponse(FileWrapper(ContentFile(obj)), content_type=header['content-type'])
    response['Content-Disposition'] = 'attachment; filename=%s' % objectname.split('/')[-1]
    return response

def download_enc(request, container, objectname):
    """ Download an object (encrypted content) from Swift """

    '''storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    
    redirect_url = get_base_url(request)
    redirect_url += reverse('objectview', kwargs={'container': container, })

    try:
        #conn = EncSwiftclientAPI(username[username.find(':')+1:],auth_token,meta_auth_token,storage_url,meta_storage_url)
        header, obj = client.get_object(storage_url, auth_token, container, objectname)
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))
        return redirect(objectview, container=container)
    except Exception:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Something goes wrong. Try again!"))
        return redirect(objectview, container=container)

    response = HttpResponse(FileWrapper(ContentFile(obj)), content_type=header['content-type'])
    response['Content-Disposition'] = 'attachment; filename=%s_enc' % objectname.split('/')[-1]
    return response'''

def delete_object(request, container, objectname):
    """ Deletes an object """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        conn.delete_object(container, objectname)
        messages.add_message(request, messages.INFO, _("Object deleted."))
    except client.ClientException:
        traceback.print_exc()
        if objectname[-1] == '/':
            messages.add_message(request, messages.ERROR, _("It's not an empty pseudofolder. First, delete all the included objects!"))
        else: messages.add_message(request, messages.ERROR, _("Access denied."))
    if objectname[-1] == '/':  # deleting a pseudofolder, move one level up
        objectname = objectname[:-1]
    prefix = '/'.join(objectname.split('/')[:-1])
    if prefix:
        prefix += '/'
    return redirect(objectview, container=container, prefix=prefix)


def toggle_public(request, container):
    """ Sets/unsets '.r:*,.rlistings' container read ACL """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        meta = conn.head_container(container)
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))
        return redirect(containerview)

    read_acl = meta.get('x-container-read', '')
    if '.rlistings' and '.r:*' in read_acl:
        read_acl = read_acl.replace('.r:*', '')
        read_acl = read_acl.replace('.rlistings', '')
        read_acl = read_acl.replace(',,', ',')
    else:
        read_acl += '.r:*,.rlistings'
    headers = {'x-container-read': read_acl, }
    try:
        conn = EncSwiftclientAPI(auth_token, project_id)
        conn.post_container(container, headers)
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))
    except Exception:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Something goes wrong. Try again!"))

    return redirect(objectview, container=container)


def public_objectview(request, account, container, prefix=None):
    messages.add_message(request, messages.ERROR, _("Function 'public_objectview' not implemented."))    

    '''""" Returns list of all objects in current container. """
    storage_url = settings.STORAGE_URL + account
    auth_token = ' '
    username =  request.session.get('username', '')
    try:
        conn = EncSwiftclientAPI(username[username.find(':')+1:],auth_token,meta_auth_token,storage_url,meta_storage_url)
        _meta, objects = conn.get_container(container)

    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))
        return redirect(containerview)

    prefixes = prefix_list(prefix)
    pseudofolders, objs = pseudofolder_object_list(objects, prefix)
    base_url = get_base_url(request)
    account = storage_url.split('/')[-1]

    return render_to_response("publicview.html", {
        'container': container,
        'objects': objs,
        'folders': pseudofolders,
        'prefix': prefix,
        'prefixes': prefixes,
        'base_url': base_url,
        'storage_url': storage_url,
        'account': account},
        context_instance=RequestContext(request))
    '''

def tempurl(request, container, objectname):
    """ Displays a temporary URL for a given container object """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    url = get_temp_url(storage_url, auth_token,
                       container, objectname, 7 * 24 * 3600)

    if not url:
        messages.add_message(request, messages.ERROR, _("Access denied."))
        return redirect(objectview, container=container)

    prefix = '/'.join(objectname.split('/')[:-1])
    if prefix:
        prefix += '/'
    prefixes = prefix_list(prefix)

    return render_to_response('tempurl.html',
                              {'url': url,
                               'account': storage_url.split('/')[-1],
                               'container': container,
                               'prefix': prefix,
                               'prefixes': prefixes,
                               'objectname': objectname,
                               'session': request.session,
                               },
                              context_instance=RequestContext(request))


def create_pseudofolder(request, container, prefix=None):
    """ Creates a pseudofolder (empty object of type application/directory) """
    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    form = PseudoFolderForm(request.POST)
    if form.is_valid():
        foldername = request.POST.get('foldername', None)
        if prefix:
            foldername = prefix + '/' + foldername
        foldername = os.path.normpath(foldername)
        foldername = foldername.strip('/')
        foldername += '/'

        content_type = 'application/directory'
        obj = None

        try: 
            conn = EncSwiftclientAPI(auth_token,project_id)
            conn.put_object(container, foldername, obj)
            messages.add_message(request, messages.INFO,
                                 _("Pseudofolder created."))
        except client.ClientException:
            traceback.print_exc()
            messages.add_message(request, messages.ERROR, _("Access denied."))

        if prefix:
            return redirect(objectview, container=container, prefix=prefix)
        return redirect(objectview, container=container)

    return render_to_response('create_pseudofolder.html', {
                              'container': container,
                              'prefix': prefix,
                              'session': request.session,
                              }, context_instance=RequestContext(request))


def get_acls(storage_url, auth_token, container, username,project_id):
    """ Returns ACLs of given container. """
    conn = EncSwiftclientAPI(auth_token, project_id)
    try:
        cont = conn.head_container(container)
    except client.ClientException:
        traceback.print_exc()
        messages.add_message(request, messages.ERROR, _("Access denied."))

    return extractACL(cont)

def extractACL(headers):
        """
        Extract the ACL from the container headers
        """
        # Get ACLs from the headers
        acl_read = ast.literal_eval(headers.get('x-container-read', '{}'))
        acl_write = ast.literal_eval(headers.get('x-container-write', '{}'))
        
        if acl_read != {}:
            acl_r  = reduce(lambda x, y: x + y, acl_read.values(), [])
             # Remove AUTH_ from names
            readers = map(lambda x: x.replace('AUTH_', ''), acl_r)
            aclr = ','.join(readers)
        else: aclr = ""

        if acl_write != {}:
            acl_w  = reduce(lambda x, y: x + y, acl_write.values(), [])
            writers = map(lambda x: x.replace('AUTH_', ''), acl_w)
            aclw = ','.join(writers)
        else: aclw = ""

        return (aclr,aclw)

def remove_duplicates_from_acl(acls):
    """ Removes possible duplicates from a comma-separated list. """
    entries = acls.split(',')
    cleaned_entries = list(set(entries))
    acls = ','.join(cleaned_entries)
    return acls

def add_acl(tenant,users,usrID):

    if users != "":
        list_us = users.split(',')
    else: list_us = []
    
    if usrID != "":
        list_us.append(unicode(usrID))

    return str({str(tenant): map(lambda x: "AUTH_" + x,list_us)})

def rem_acl(tenant,users,usrID): 

    if users != "":
        list_us = users.split(',')
        list_us.remove(unicode(usrID))

    return str({str(tenant): map(lambda x: "AUTH_" + x,list_us)})

def rem_all_acl(tenant):

    return str({str(tenant): map(lambda x: "AUTH_" + x,[])})

def edit_acl(request, container):
    """ Edit ACLs on given container. """

    storage_url = request.session.get('storage_url', '')
    #meta_storage_url = request.session.get('meta_storage_url', '')
    auth_token = request.session.get('auth_token', '')
    #meta_auth_token = request.session.get('meta_auth_token', '')
    username =  request.session.get('username', '')
    project_id = request.session.get('project_id','')
    conn = EncSwiftclientAPI(auth_token, project_id)
    tenant = storage_url[storage_url.find('AUTH_')+5:]
    
    readers, writers = get_acls(storage_url, auth_token, container, username,project_id)

    readers = remove_duplicates_from_acl(readers)
    writers = remove_duplicates_from_acl(writers)

    make_public = request.POST.get('make_public')
    make_private = request.POST.get('make_private')
    
    if request.method == 'POST':

        form = AddACLForm(request.POST)

        if form.is_valid():
            
            user_n = form.cleaned_data['username']
            usrID = conn.getUserID(user_n)

            headers={}

            headers['x-container-read'] = add_acl(tenant,readers,usrID)
            if form.cleaned_data['right'] == "1":
                headers['x-container-write']= add_acl(tenant,writers,usrID)
            elif form.cleaned_data['right'] == "0":
                headers['x-container-write']= add_acl(tenant,writers,"")

            try:
                
                conn.post_container(container, headers)
                message = "ACL updated."
                messages.add_message(request, messages.INFO, message)
            except client.ClientException:
                traceback.print_exc()
                message = "ACL update failed"
                messages.add_message(request, messages.ERROR, message)
            except Exception:
                traceback.print_exc()
                message = "Something goes wrong. Try again!"
                messages.add_message(request, messages.ERROR, message)
        elif make_public == None and make_private == None: 
            message = "You must specify the username and the access right (\"only read\" or \"read & write\")."
            messages.add_message(request, messages.ERROR, message)

    if request.method == 'GET':

        # delete == user ID, it is removed from ACL
        delete = request.GET.get('delete', None)
        
        if delete:
            
            users = delete.split(',')

            '''new_readers = ""
            for element in readers.split(','):
                if element not in users:
                    new_readers += element
                    new_readers += ","

            new_writers = ""
            for element in writers.split(','):
                if element not in users:
                    new_writers += element
                    new_writers += ","
            '''
            headers = {}

            for element in readers.split(','):
                if element in users:
                    headers['x-container-read'] = rem_acl(tenant,readers,delete)

            for element in writers.split(','):
                if element in users:
                    headers['x-container-write'] = rem_acl(tenant,writers,delete)  

            try:
                conn.post_container(container, headers)
                message = "User removed."
                messages.add_message(request, messages.INFO, message)
            except client.ClientException:
                traceback.print_exc()
                message = "ACL update failed."
                messages.add_message(request, messages.ERROR, message)
            except Exception:
                traceback.print_exc()
                message = "Something goes wrong. Try again!"
                messages.add_message(request, messages.ERROR, message)

    #if acls.get('.r:*', False) and acls.get('.rlistings', False):
    #    public = True

    if make_public != None:
        public = True
        readers, writers = get_acls(storage_url, auth_token, container,username,project_id)
        headers = {}
        headers['x-container-read'] = rem_all_acl(tenant)
        headers['x-container-write'] = rem_all_acl(tenant)  
        try:
            conn.post_container(container, headers)
            message = "ACL removed."
            messages.add_message(request, messages.INFO, message)
        except client.ClientException:
            traceback.print_exc()
            message = "ACL update failed."
            messages.add_message(request, messages.ERROR, message)
        except Exception:
                traceback.print_exc()
                message = "Something goes wrong. Try again!"
                messages.add_message(request, messages.ERROR, message)   
    if make_private != None:
        public = False
        readers, writers = get_acls(storage_url,auth_token, container,username,project_id)
        usrID = conn.getUserID(username)#[username.find(':')+1:])
        headers = {}
        headers['x-container-read']  = add_acl(tenant,readers,usrID)
        headers['x-container-write'] = add_acl(tenant,writers,usrID)  
        try:
            conn.post_container(container, headers)
            message = "ACL added your ID."
            messages.add_message(request, messages.INFO, message)
        except client.ClientException:
            traceback.print_exc()
            message = "ACL update failed."
            messages.add_message(request, messages.ERROR, message)
        except Exception:
            traceback.print_exc()
            message = "Something goes wrong. Try again!"
            messages.add_message(request, messages.ERROR, message)

    readers, writers = get_acls(storage_url, auth_token, container,username,project_id)

    if len(readers) == 0 and len(writers) == 0:    
        public = True
    else: public = False

    acls = {}
    if readers != "":
        readers = remove_duplicates_from_acl(readers)
        for entry in readers.split(','):
            acls[entry] = {}
            acls[entry]['read'] = True
            acls[entry]['write'] = False
    if writers != "":
        writers = remove_duplicates_from_acl(writers)
        for entry in writers.split(','):
            if entry not in acls:
                acls[entry] = {}
                acls[entry]['read'] = True
            acls[entry]['write'] = True
    if len(acls) != 0:
        for key,value in acls.iteritems():
            acls[key]['name'] = conn.getUsername(key)
    if request.is_secure():
        base_url = "https://%s" % request.get_host()
    else:
        base_url = "http://%s" % request.get_host()

    return render_to_response('edit_acl.html', {
        'container': container,
        'account': storage_url.split('/')[-1],
        'session': request.session,
        'acls': acls,
        'public': public,
        'base_url': base_url,
    }, context_instance=RequestContext(request))
