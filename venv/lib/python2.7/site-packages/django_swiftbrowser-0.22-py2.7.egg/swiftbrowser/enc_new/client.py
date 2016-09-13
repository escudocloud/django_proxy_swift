#!/usr/bin/env python

import ast, base64, json
from send_message import sender
from secret_manager import sec_manager
from Crypto.PublicKey import RSA
from swiftclient import client
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as kc
from keystoneclient.v3 import tokens
from config import *
from myLogger import *

print "NON VA BEBE"    
