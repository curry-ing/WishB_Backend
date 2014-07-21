__author__ = 'masunghoon'

import facebook
import httplib, urllib

from flask import g, jsonify, url_for
from flask.ext.httpauth import HTTPBasicAuth

from rauth.service import OAuth2Service

from app import app
from config import FB_CLIENT_ID, FB_CLIENT_SECRET, WISHB_SERVER_URI
from models import User, UserSocial

auth = HTTPBasicAuth()
graph_url = 'https://graph.facebook.com/'
fb = OAuth2Service(name='facebook',
                         authorize_url='https://www.facebook.com/dialog/oauth',
                         access_token_url=graph_url+'oauth/access_token',
                         client_id=FB_CLIENT_ID,
                         client_secret=FB_CLIENT_SECRET,
                         base_url=graph_url)

@auth.verify_password
def verify_password(username_or_token, password):
    print "auth.verify_password"
    # first try to authenticate by token
    if password == "facebook":
        auth = fb.get_session(token=username_or_token)
        resp = auth.get('/me')
        if resp.status_code == 200:
            fb_user = resp.json()
            # user = User.query.filter_by(email=fb_user.get('email')).first()
            birthday = fb_user['birthday'][6:10] + fb_user['birthday'][0:2] + fb_user['birthday'][3:5]
            user = User.get_or_create(fb_user['email'], fb_user['name'], fb_user['id'], birthday)
            conn = httplib.HTTPSConnection("graph.facebook.com")
            params = urllib.urlencode({'redirect_uri':WISHB_SERVER_URI,
                                       'client_id':FB_CLIENT_ID,
                                       'client_secret':FB_CLIENT_SECRET,
                                       'grant_type':'fb_exchange_token',
                                       'fb_exchange_token':username_or_token})
            conn.request("GET","/oauth/access_token?"+ params)
            response = conn.getresponse()
            resp_body = response.read()

            longLivedAccessToken=resp_body.split('&')[0].split('=')[1]

            UserSocial.upsert_user(user.id, 'facebook', fb_user['id'], longLivedAccessToken)
            # c.gauge(gauge'Facebook_Login', 1, delta=True)

        else:
            return False
    else:
        user = User.verify_auth_token(username_or_token)

    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(email = username_or_token).first()
        if not user:
            return False
        if user.password == None:
            return False
        if not user.verify_password(password):
            return False
        # c.gauge('Email_Login', 1, delta=True)
        # logging_auth(user.id, "login", "email")

    g.user = user
    return True

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    if g.user.profile_img_id == 0:
        if g.user.fb_id == 0:
            profile_img = None
        else:
            social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
            graph = facebook.GraphAPI(social_user.access_token)
            args = {'type':'normal'}
            profile_img = graph.get_object(g.user.fb_id+'/picture', **args)['url']
    else:
        profile_img = None if g.user.profile_img_id is None else url_for('send_pic', img_id=g.user.profile_img_id, img_type='thumb_sm', _external=True)

    token = g.user.generate_auth_token()
    return jsonify({'status':'success',
                    'data':{'user':{'id': g.user.id,
                                    'username': g.user.username,
                                    'email': g.user.email,
                                    'birthday': g.user.birthday,
                                    'title_life':g.user.title_life,
                                    'title_10':g.user.title_10,
                                    'title_20':g.user.title_20,
                                    'title_30':g.user.title_30,
                                    'title_40':g.user.title_40,
                                    'title_50':g.user.title_50,
                                    'title_60':g.user.title_60,
                                    'profile_img_url': profile_img,
                                    'confirmed_at':g.user.confirmed_at.strftime("%Y-%m-%d %H:%M:%S") if g.user.confirmed_at else None},
                            'token': token.decode('ascii')}})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    if g.user.profile_img_id == 0:
        if g.user.fb_id == 0:
            profile_img = None
        else:
            social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
            graph = facebook.GraphAPI(social_user.access_token)
            args = {'type':'normal'}
            profile_img = graph.get_object(g.user.fb_id+'/picture', **args)['url']
    else:
        profile_img = None if g.user.profile_img_id is None else url_for('send_pic', img_id=g.user.profile_img_id, img_type='thumb_sm', _external=True)

    # logging_auth(g.user.id, "login", "total")
    return jsonify({'status':'success',
                    'data':{'id': g.user.id,
                            'username': g.user.username,
                            'email': g.user.email,
                            'birthday': g.user.birthday,
                            'title_life':g.user.title_life,
                            'title_10':g.user.title_10,
                            'title_20':g.user.title_20,
                            'title_30':g.user.title_30,
                            'title_40':g.user.title_40,
                            'title_50':g.user.title_50,
                            'title_60':g.user.title_60,
                            'profile_img_url': profile_img,
                            'confirmed_at': g.user.confirmed_at.strftime("%Y-%m-%d %H:%M:%S") if g.user.confirmed_at else None }})