from keystoneclient.auth import identity
from keystoneauth1.identity import v3
from keystoneclient import session
from barbicanclient import client as bc
from swiftclient import client as sc
from config import *
from keystoneclient.v3 import client as kc

#kc_conn = kc.Client(username="enctest1", password="enctest1", tenant_name="demo", auth_url=AUTH_URL)
#username = kc_conn.users.get('2232361c967f46aca3fe074addc7aefb')
#user = kc_conn.users.list()
#print user
#print username


auth = identity.v3.Password(username='admin', password='secretsecret',
                   project_name='demo', user_domain_name=u'Default',project_domain_name=u'Default',auth_url=AUTH_URL)
sess = session.Session(auth=auth)

# Create user
#conn = kc.Client(session=sess)
#swift_conn = sc.Connection(session=sess)

#(storage_url, auth_token) = sc.get_auth(
#                AUTH_URL, "demo:admin", "secretsecret",
#                auth_version="3")
#swift_conn = sc.Connection(preauthtoken=auth_token,preauthurl=storage_url,auth_version="3")
#swift_conn = sc.Connection(user='admin',key='secretsecret',tenant_name='demo',authurl=AUTH_URL,auth_version='3.0')
#head = swift_conn.head_container(container='aaa')
#print head
#filename = 'pub.key'
#with open(filename, 'r') as f:
#    pub = f.read()
#user = conn.users.create(name="Ciiiccio", password="Ciccio", project="Ciccio", description=pub)

barbican = bc.Client(session=sess)
a = barbican.secrets.get('http://193.204.253.185:9311/v1/secrets/38316494-6e6b-471e-9772-92b364420f0c')
print a.payload
'''
container_name = "AAA"
#Create keys container 
container = barbican.containers.create(name=container_name)   

secret1 = barbican.secrets.create(payload=u'the magic words are squeamish ossifrage')
secret1.store()

secret2 = barbican.secrets.create(payload=u'the magic words are squeamish ossifrage')
secret2.store()

container.add('New secret',secret1)
container.add('New secret1',secret2)
                            
container.store()
lis = barbican.containers.list()
print "EE"
print lis
print container.container_ref

#barbican.secrets.update(secret_ref ="http://193.204.253.190:9311/v1/secrets/d12b488c-9efd-4571-a443-b1145326f2ba", payload="new pay")
#a = "http://193.204.253.190:9311/v1/secrets/3f0e7987-4870-4ef2-9e80-28cf1c9f41f7"
#print(secret.secret_ref)
#a ="http://193.204.253.190:9311/v1/secrets/b6cfb144-760f-4517-b02b-ed91334b9d9d"

#Define container acl
users_list = ["df16986f4039409bb4f09aede3f7a76f","b931434ce7fb4b6ba5f6e19e9022101d"]
acl = barbican.acls.create(entity_ref = container.container_ref,users=users_list)
ret = acl.submit()
print acl 
#Create key
secret = barbican.secrets.create(payload=u'the magic words are squeamish ossifrage')
secret.store()

#container = barbican.containers.get(container.container_ref)
#container.delete()
container1 = barbican.containers.create(name=container_name)
secret3 = barbican.secrets.create(payload=u'the magic words are squeamish ossifrage')
secret3.store()                         
container1.add('New secret',secret1)
container1.add('New secret1',secret2)
container1.add('New secret2',secret3)
container1.store()
print container.secrets
for sec in container.secrets.keys():
    print container.secrets[sec].secret_ref
print container1
lis = barbican.containers.list()
print "EE"
print lis
print container.container_ref

#Retrieve key
secret_ref = secret.secret_ref
retrieved_secret = barbican.secrets.get(secret_ref)

#Change acl
add_users = ['43r8cn7y2149r8y298rucn98u20r8u8u']
acl_entity = barbican.acls.get(entity_ref=container.container_ref)
# add new users to existing users for 'read' operation
acl_entity.read.users.extend(add_users)
# OR
# acl_entity.get('read').users.extend(add_users)
acl_ref = acl_entity.submit()'''
