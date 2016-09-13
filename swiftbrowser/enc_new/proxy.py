#!/usr/bin/env python

from flask import *
from werkzeug.exceptions import HTTPException, NotFound

from enc_swiftclient_API import EncSwiftclientAPI as esc
from config import *
from swiftclient.client import ClientException

import requests,json

app = Flask(__name__)                                                            

host = '127.0.0.1'
port = 8000
host_url = 'http://%s:%d' % (host,port)

DENIED_HEADERS = ['Host']

#auth_ip = '193.204.253.147'
#auth_port = 5000
#auth_url = 'http://%s:%d' % (auth_ip,auth_port)

#def retrieve_endpointURL(name,url):
#
#    for el in info['access']['serviceCatalog']:
#        if el['name'] == name:
#            return el['endpoints'][0][url]

def sanitize_headers(headers):
    return dict((k, v) for k, v in headers.items()
                            if k not in DENIED_HEADERS)

def change_endpointURL(name, info):

    for el in info['access']['serviceCatalog']:
        if el['name'] == name:
            el['endpoints'][0]['adminURL'] = host_url
            el['endpoints'][0]['publicURL'] = host_url+el['endpoints'][0]['publicURL'][el['endpoints'][0]['publicURL'].find('/v1/')+3:]
            el['endpoints'][0]['internalURL'] = host_url+el['endpoints'][0]['internalURL'][el['endpoints'][0]['internalURL'].find('/v1/')+3:]


@app.route('/v3/auth/tokens', methods=['POST'])
def authentication():
    req = requests.post('http://193.204.253.174:5000/v3/auth/tokens', stream=True, headers=request.headers, data=request.data)
    info =  json.loads(req.content)
    change_endpointURL('swift', info)
    return Response(stream_with_context(json.dumps(info)), content_type = req.headers['content-type'])

#@app.route('/<path:path>', methods=['GET'])
#def store(path):
    #print "path", path, "args", request.url, "headers", request.headers, "data", request.data
    #headers = {}
    #headers['Host'] = retrieve_endpointURL('swift','adminURL')
    #headers['X-Auth-Token'] = request.headers['X-Auth-Token']
    #req = requests.get('%s/%s'% (STORAGE_URL,path), headers=headers, data=request.data)
    #url = 'http://'+auth_ip+':8080'+retrieve_endpointURL('swift','publicURL')[retrieve_endpointURL('swift','publicURL').find('/v1/'):]+path
    #req = requests.get(url, headers=headers, data=request.data)
    #print "headers", req.headers, "data", req.content
    #auth_token = request.headers['X-Auth-Token']
    #esc_conn = esc('admin',auth_token, auth_token, STORAGE_URL, STORAGE_URL)
    #print path, path.split('/')[1],"".join(path.split('/')[2:])
    #headers, data = esc_conn.get_object(path.split('/')[1],path.split('/')[2])
    #print data
    #return Response(response = data)
    #return Response(stream_with_context(req.iter_content()), content_type = req.headers['content-type'])

@app.route('/<auth_tenant>/<container>', methods=['POST'])
def post_container(auth_tenant,container):
    print "POST CONT", auth_tenant,container
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]

    headval = dict(sanitize_headers(request.headers))
    #readers = request.headers.get('X-Container-Read',None)
    #writers = request.headers.get('X-Container-Write',None)

    #if readers != None:
    #    acl['x-container-read'] = readers
    #if writers != None:
    #    acl['x-container-write']= writers
    
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        if headval:
            esc_conn.post_container(container,headval)
        else:
            esc_conn.put_container(container)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response(status=200)


@app.route('/<auth_tenant>/<container>', methods=['PUT'])
def put_container(auth_tenant,container):
    print "PUT CONT", auth_tenant,container
    print request.method, request.headers, request.data
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        esc_conn.put_container(container)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    return Response(status=200)


@app.route('/<auth_tenant>/<container>/<path:path>', methods=['PUT'])
def put_obj(auth_tenant,container,path):
    print auth_tenant,container,path, request.method, 
    print request.headers, request.args, request.data
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        esc_conn.put_object(container,path, request.data)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)

    return Response(status=200)


@app.route('/<auth_tenant>/<container>', methods=['HEAD'])
def head_cont(auth_tenant,container):
    print "HEAD CONT",auth_tenant,container
    auth_tenant = str(auth_tenant)
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        headers = esc_conn.head_container(container)
        print headers
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response('', headers = dict(headers))


@app.route('/<auth_tenant>/<container>', methods=['GET'])
def get_cont(auth_tenant,container):
    _type = request.args.get('format', '')
    _marker = request.args.get('marker', '')
    print "GET CONT", auth_tenant,container,_type,_marker
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        headers, data = esc_conn.get_container(container, marker=_marker)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response(stream_with_context(json.dumps(data)), headers = dict(headers))


@app.route('/<auth_tenant>/<container>/<path:path>', methods=['HEAD'])
def head_obj(auth_tenant,container,path):
    print "HEAD OBJ",auth_tenant,container,path
    print request.headers, request.data, request.args, request.method
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        headers = esc_conn.head_object(container, path)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    return Response('', headers = dict(headers))


@app.route('/<auth_tenant>/<container>/<path:path>', methods=['GET'])
def get_obj(auth_tenant,container,path):
    print "GET OBJ", auth_tenant,container,path
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        headers, data = esc_conn.get_object(container,path)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    return Response(response = data, headers = headers)

@app.route('/<auth_tenant>/<container>', methods=['DELETE'])
def delete_cont(auth_tenant,container):
    print "DEL CONT",auth_tenant,container
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        esc_conn.delete_container(container)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response(status=200)

@app.route('/<auth_tenant>/<container>/<path:path>', methods=['DELETE'])
def delete_obj(auth_tenant,container,path):
    print "DEL OBJ",auth_tenant,container,path
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        esc_conn.delete_object(container,path)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response(status=200)

@app.route('/<auth_tenant>/<container>/<path:path>', methods=['POST'])
def post_obj(auth_tenant,container,path):
    print "POST OBJ", auth_tenant,container,path
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    headval = dict(sanitize_headers(request.headers))
    
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        print headval
        esc_conn.post_object(container,path,headval)
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response(status=200)

@app.route('/<auth_tenant>', methods=['GET'])
def get_account(auth_tenant):
    print "GET ACCOUNT",auth_tenant
    auth_token = request.headers['X-Auth-Token']
    project_id = auth_tenant[auth_tenant.find('_')+1:]
    try:
        esc_conn = esc(auth_token, project_id)
    except Exception as err:
        print err
    try:
        esc_conn.get_account()
    except ClientException as exc:
        print exc.http_status
        return Response(status=exc.http_status)
    
    return Response(status=200)

if __name__ == "__main__":
    app.run(host=host, port=int(port))