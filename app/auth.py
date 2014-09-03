__author__ = 'masunghoon'

import httplib, urllib
import json
from bson import json_util

from bson import ObjectId
from flask import g, request, jsonify
from app import app, mdb, httpAuth, OAuth2_facebook
from utils import check_user_app_version
from config import WISHB_SERVER_URI, FB_CLIENT_ID, FB_CLIENT_SECRET
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired

from passlib.apps import custom_app_context as pwd_context


def verify_password(stored_pw, input_pw):
    return pwd_context.verify(stored_pw, input_pw)

def hash_password(password):
    return pwd_context.encrypt(password)


##### TOKEN MANAGEMENT #########################################################
def generate_auth_token(expiration = 86400):
    s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
    return s.dumps({'id':str(g.user['_id'])})


def verify_auth_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    user = mdb.users.find_one({'_id':ObjectId(data['id'])})
    return user


# @httpAuth.verify_password
# def verify_auth(username_or_token, password):
#     # first try to authenticate by token
#     if password == "facebook":
#         fb_auth = OAuth2_facebook.get_session(token=username_or_token)
#         resp = fb_auth.get('/me')
#         if resp.status_code == 200:
#             fb_user = resp.json()
#             # birthday = fb_user['birthday'][6:10] + fb_user['birthday'][0:2] + fb_user['birthday'][3:5]
#
#             conn = httplib.HTTPSConnection("graph.facebook.com")
#             params = urllib.urlencode({'redirect_uri':WISHB_SERVER_URI,
#                                        'client_id':FB_CLIENT_ID,
#                                        'client_secret':FB_CLIENT_SECRET,
#                                        'grant_type':'fb_exchange_token',
#                                        'fb_exchange_token':username_or_token})
#             conn.request("GET","/oauth/access_token?"+ params)
#             response = conn.getresponse()
#             resp_body = response.read()
#
#             longLivedAccessToken=resp_body.split('&')[0].split('=')[1]
#
#             user = mdb.users.find_one({'email':fb_user['email']})
#             if user is None:
#                 mdb.users.insert({'email':fb_user['email'],
#                                   'username':fb_user['name'],
#                                   # 'birthday':birthday,
#                                   'unread_notices':[],
#                                   'facebook':{'id':fb_user['id'],
#                                               'access_token':longLivedAccessToken}})
#         else:
#             return False
#     elif password == 'unused':
#         user = verify_auth_token(username_or_token)
#     else:
#         # try to authenticate with username/password
#         user = mdb.users.find_one({'email':username_or_token})
#         if not user:
#             return False
#         if user['password'] == None:
#             return False
#         if not verify_password(user['password'], password):
#             return False
#
#     g.user = user
#     return True


@app.route('/auth/token')
@httpAuth.login_required
def get_auth_token():
    # check user app version & logging
    latest_app = mdb.release.find_one(sort=[('version.major', -1),('version.minor', -1),('version.tiny', -1)])
    if 'app_version' in request.args and 'os' in request.args:
        check_user_app_version(request.args['app_version'], request.args['os'])

    return jsonify({'status':'success',
                    'data':{'user':json.loads(json_util.dumps(g.user)),
                            'latest_app':{'version':str(latest_app['version']['major']) + '.' + str(latest_app['version']['minor']),
                                          'version_n':latest_app['version'],
                                          'url':latest_app['url']}},
                            'token': generate_auth_token().decode('ascii')})


@app.route('/auth/resource')
@httpAuth.login_required
def get_resource():
    # check user app version & logging
    latest_app = mdb.release.find_one(sort=[('version.major', -1),('version.minor', -1),('version.tiny', -1)])
    if 'app_version' in request.args and 'os' in request.args:
        check_user_app_version(request.args['app_version'], request.args['os'])

    return jsonify({'status':'success',
                    'data':{'user':json.loads(json_util.dumps(g.user)),
                            'latest_app':{'version':str(latest_app['version']['major']) + '.' + str(latest_app['version']['minor']),
                                          'version_n':latest_app['version'],
                                          'url':latest_app['url']}}}), 200
