__author__ = 'masunghoon'

import models

from datetime import datetime
from pymongo import MongoClient
from config import MONGODB_URI
from decorators import async

mdb = MongoClient(MONGODB_URI).wishb

@async
def logging_auth(user, action, action_type):
    if user is not None:
        user_id = user.id
        email = user.email
        username = user.username
    else:
        user_id = 'Anonymous'
        email = ""
        username = ""
    auth_log = mdb.auth_log

    log = {"user_id": user_id,
           "email": email,
           "username": username,
           "action": action,
           "action_type": action_type,
           "log_dt": datetime.now()}

    auth_log.insert(log)
    print "Authorization: " + str(user_id) + '|' + action + '|' + action_type


@async
def logging_api(user, api_name, request_type):
    if user is not None:
        user_id = user.id
        email = user.email
        username = user.username
    else:
        user_id = 'Anonymous'
        email = ""
        username = ""
    api_log = mdb.api_log

    log = {"user_id": user_id,
           "email": email,
           "username": username,
           "api_name":api_name,
           "request_type":str.upper(request_type),
           "log_dt":datetime.now()}

    api_log.insert(log)
    print "API Call: " + str(user_id) + '|' + api_name + '|' + request_type


@async
def logging_social(user, service_name, action, target, type):
    if user is not None:
        user_id = user.id
        email = user.email
        username = user.username
    else:
        user_id = 'Anonymous'
        email = ""
        username = ""
    social_log = mdb.social_log

    log = {"user_id": user_id,
           "email": email,
           "username": username,
           "service_name": service_name,
           "action": str.upper(action),
           "target": target,
           "type": str.upper(type),
           "log_dt": datetime.now()}

    social_log.insert(log)
    print "Social: " + str(user_id) + '|' + service_name + '|' + action + '|' + target
