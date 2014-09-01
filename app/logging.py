__author__ = 'masunghoon'

from datetime import datetime
from decorators import async
from pymongo import MongoClient

# from app import mdb
from config import MONGODB_URI

mdb = MongoClient(MONGODB_URI).wishb

@async
def logging_auth(uid, action, action_type):
    if uid is None:
        uid = "Anonymous"
    auth_log = mdb.auth_log

    log = {"user_id": uid,
           "action": action,
           "action_type": action_type,
           "log_dt": datetime.now()}

    auth_log.insert(log)
    # print "Authorization: " + str(user_id) + '|' + action + '|' + action_type


@async
def logging_api(uid, api_name, request_type):
    if uid is None:
        uid = "Anonymous"
    api_log = mdb.api_log

    log = {"user_id": uid,
           "api_name":api_name,
           "request_type":str.upper(request_type),
           "log_dt":datetime.now()}

    api_log.insert(log)
    # print "API Call: " + str(user_id) + '|' + api_name + '|' + request_type


@async
def logging_social(uid, service_name, action, target, type): 
    if uid is None:
        uid = "Anonymous"
    social_log = mdb.social_log

    log = {"user_id": uid,
           "service_name": service_name,
           "action": str.upper(action),
           "target": target,
           "type": str.upper(type),
           "log_dt": datetime.now()}

    social_log.insert(log)
    # print "Social: " + str(user_id) + '|' + service_name + '|' + action + '|' + target


@async
def logging_downlaod(ip_addr):
    download_log = mdb.download_log

    log = {"ip_addr": ip_addr,
           "log_dt": datetime.now()}

    download_log.insert(log)

@async
def logging_newsfeed(obj):
    print obj
    mdb.newsfeed.insert(obj)

@async
def logging_update(obj):
    mdb.update_log.insert(obj)