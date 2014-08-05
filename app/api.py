__author__ = 'masunghoon'

# Libraries
import random, datetime
import facebook
import os
import statsd
import inspect
import json
from bson import json_util

from flask import request, g, url_for
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.restful import Resource, reqparse, fields
from flask.ext.uploads import UploadSet, IMAGES, configure_uploads, patch_request_class

from hashlib import md5
from rauth.service import OAuth2Service
from sqlalchemy.sql import func
# Source
from app import db, api, app
from models import User, Bucket, Plan, File, Post, UserSocial, ROLE_ADMIN, ROLE_USER
from emails import send_awaiting_confirm_mail, send_reset_password_mail
from config import FB_CLIENT_ID, FB_CLIENT_SECRET, POSTS_PER_PAGE, MAX_UPLOAD_SIZE, WISHB_SERVER_URI, MONGODB_URI
from logging import logging_auth, logging_api, logging_social
from social import facebook_feed
from pymongo import MongoClient

from PIL import Image

photos = UploadSet('photos',IMAGES)
configure_uploads(app, photos)
patch_request_class(app, size=MAX_UPLOAD_SIZE) #File Upload Size = Up to 2MB

stsd = statsd.StatsClient('localhost', 8125)

mdb = MongoClient(MONGODB_URI).wishb

##### AUTHENTICATION #######################################

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
    # first try to authenticate by token
    if password == "facebook":
        auth = fb.get_session(token=username_or_token)
        resp = auth.get('/me')
        if resp.status_code == 200:
            fb_user = resp.json()
            # user = User.query.filter_by(email=fb_user.get('email')).first()
            birthday = fb_user['birthday'][6:10] + fb_user['birthday'][0:2] + fb_user['birthday'][3:5]
            user = User.get_or_create(fb_user['email'], fb_user['name'], fb_user['id'], birthday)
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
    g.user = user
    return True

class VerificationAPI(Resource):
    def __init__(self):
        super(VerificationAPI, self).__init__()

    def get(self,emailAddr):
        if request.authorization is not None:
            g.user = User.verify_auth_token(request.authorization['username'])
        else:
            g.user = None
        try:
            if User.email_exists(emailAddr):
                logging_api(None, self.__class__.__name__, inspect.stack()[0][3])
                return {'status':'success',
                        'data':'0',
                        'description':'Email already exists'}, 200
            else:
                logging_api(None, self.__class__.__name__, inspect.stack()[0][3])
                return {'status':'success',
                        'data':'1',
                        'description':'Available Email Address'}, 200
        except:
            return {'status':'error',
                    'description':'Something went wrong'}, 500

api.add_resource(VerificationAPI, '/api/valid_email/<emailAddr>', endpoint='verifyEmail')


class ResetPassword(Resource):
    def __init__(self):
        super(ResetPassword, self).__init__()

    # def get(self,string):
    #     u = User.query.filter_by(email = string).first()
    #     u.key = md5('RESET_PASSWORD'+str(int(random.random()*10000))).hexdigest()
    #
    #     db.session.commit()
    #     send_reset_password_mail(u)
    #
    #     return {'status':'success',
    #             'description':'Reset Password Mail Sent'}, 200



    def post(self,string):
        if request.authorization is not None:
            g.user = User.verify_auth_token(request.authorization['username'])
	    uid = g.user.id
        else:
            uid = None
        u = User.query.filter_by(email = string).first()
        if not u:
            return {'status':'error',
                    'description':'Invalid User Email'}, 400
        u.key = md5('RESET_PASSWORD'+str(int(random.random()*10000))).hexdigest()

        db.session.commit()
        send_reset_password_mail(u)

        logging_api(uid, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Reset Password Mail Sent'}, 200


    def put(self,string):
        if request.json:
            params = request.json
        elif request.form:
            params = request.form
        else:
            return {'status':'error',
                    'description':'Request Failed'}, 400

        u = User.query.filter_by(key = string).first()
        if not u:
            return {'status':'error',
                    'description':'Invalid Key'}, 400

        # if
        if 'password' not in params:
            return {'status':'error',
                    'description':'Password Missing'}, 400

        try:
            u.hash_password(params['password'])
            u.key = None
            db.session.commit()
        except:
            return {'status':'error',
                    'description':'Something went wrong'}, 500

        logging_api(None, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Password successfully reset'}, 200

api.add_resource(ResetPassword, '/api/reset_password/<string>', endpoint='resetPassword')


##### USER / USERLIST ##################################

class UserAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(UserAPI, self).__init__()

    #get specific User's Profile
    def get(self, id):
        u = User.query.filter_by(id=id).first()
        if u.profile_img_id == 0:
            if u.fb_id is None:
                profile_img = None
            else:
                social_user = UserSocial.query.filter_by(user_id=u.id).first()
                graph = facebook.GraphAPI(social_user.access_token)
                args = {'type':'normal'}
                profile_img = graph.get_object(g.user.fb_id+'/picture', **args)['url']
        else:
            profile_img = None if u.profile_img_id is None else url_for('send_pic', img_id=u.profile_img_id, img_type='thumb_sm', _external=True)

        data = {'id': u.id,
                'email': u.email,
                'username': u.username,
                'about_me': u.about_me,
                'last_seen': u.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                'birthday': u.birthday,
                'uri': "/api/user/" + str(u.id),
                'title_life': u.title_life,
                'title_10': u.title_10,
                'title_20': u.title_20,
                'title_30': u.title_30,
                'title_40': u.title_40,
                'title_50': u.title_50,
                'title_60': u.title_60,
                'profile_img_url': profile_img
        }


        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])

        return {'status':'success',
                'description':'normal',
                'data': data}, 200
                  # 'data':marshal(u, user_fields)}, 200


    #modify My User Profile
    def put(self, id):
        if request.json:
            params = request.json
        elif request.form:
            params = {}
            for key in request.form:
                params[key] = request.form[key]
        else:
            return {'status':'error','description':'Request Failed'}, 500

        u = User.query.filter_by(id=id).first()
        if u != g.user:
            return {'status':'error', 'description': 'Unauthorized'}, 401

        for key in params:
            value = None if params[key]=="" else params[key]    # Or Use (params[key],None)[params[key]==""] Sam Hang Yeonsanja

            # Nobody can change id, email, fb_id, last_seen
            if key in ['id', 'email', 'fb_id', 'last_seen']:
                return {'status':'error', 'description':'Cannot change ' + key}, 400

            # Just ROLE_ADMIN user can change 'role', 'login_fault'
            if key in ['login_fault', 'role'] and g.user.role == ROLE_USER:
                return {'status':'error', 'description':'Only Admin can change ' + key}, 401

            # Validate & hash Password
            if key == 'password':
                if len(value) < 4:
                    return {'status':'error', 'description':'Password is too short'}, 400
                u.hash_password(value)
                continue                                        # if not continue hash will be reset.

            # Birthday can only be None or 8-digit integer(between 1900/01/01 ~ currentYear's 12/31)
            elif key == 'birthday' and value is not None:
                if len(value) != 8 or \
                    int(value[0:4]) < 1900 or int(value[0:4]) > int(datetime.datetime.now().strftime("%Y")) or \
                    int(value[4:6]) < 0 or int(value[4:6]) > 12 or \
                    int(value[6:8]) < 0 or int(value[6:8]) > 31:
                        return {'status':'error',
                                'description':"Invalid value for Birthday: " + value[0:4] + '/' + value[4:6] + '/' + value [6:8]}, 400

            # Username cannot be null
            elif key == 'username':
                if value == None:
                    return {'status':'error', 'description':'Username cannot be blank'}, 400

            elif key not in ['about_me', 'title_life', 'title_10', 'title_20', 'title_30', 'title_40', 'title_50', 'title_60', 'profile_img_id']:
                return {'status':'error', 'description':'Invalid user key'}, 400

            setattr(u, key, value)

        if 'photo' in request.files:
            upload_type = 'photo'

            if len(request.files[upload_type].filename) > 64:
                return {'status':'error',
                        'description':'Filename is too long (Max 64bytes include extensions)'}, 403
            upload_files = UploadSet('photos',IMAGES)
            configure_uploads(app, upload_files)

            filename = upload_files.save(request.files[upload_type])
            basedir = os.path.abspath('app/static/uploads/photos')

            # MAKE THUMBNAIL IMAGES
            # TODO: Make Function
            img = Image.open(os.path.abspath('app/static/uploads/photos/'+filename))

            org_width = img.size[0]
            org_height = img.size[1]

            longer_side = ('width', org_width) if org_width > org_height else ('height', org_height)

            if longer_side[1] > 540:
                img.thumbnail((540, 540), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_md',filename), quality=75, optimize=True, progressive=True)


            if longer_side[1] > 128:
                img.thumbnail((128, 128), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_sm',filename), quality=75, optimize=True, progressive=True)

            splits = []

            for item in filename.split('.'):
                splits.append(item)
            extension = filename.split('.')[len(splits) -1]

            f = File(filename=filename, user_id=g.user.id, extension=extension, type=upload_type)
            db.session.add(f)
            db.session.flush()
            db.session.refresh(f)

            setattr(u, 'profile_img_id', f.id)

        try:
            db.session.commit()
        except:
            db.session.rollback()
            return {'status':'error', 'description':'Something went wrong'}, 500

        if u.profile_img_id == 0:
            if u.fb_id is None:
                profile_img = None
            else:
                social_user = UserSocial.query.filter_by(user_id=u.id).first()
                graph = facebook.GraphAPI(social_user.access_token)
                args = {'type':'normal'}
                profile_img = graph.get_object(g.user.fb_id+'/picture', **args)['url']
        else:
            profile_img = None if u.profile_img_id is None else url_for('send_pic', img_id=u.profile_img_id, img_type='thumb_md', _external=True)

        data = {'id': u.id,
                'email': u.email,
                'username': u.username,
                'about_me': u.about_me,
                'last_seen': u.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                'birthday': u.birthday,
                'uri': "/api/user/" + str(u.id),
                'title_life': u.title_life,
                'title_10': u.title_10,
                'title_20': u.title_20,
                'title_30': u.title_30,
                'title_40': u.title_40,
                'title_50': u.title_50,
                'title_60': u.title_60,
                'profile_img_url': profile_img}

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'normal',
                'data': data}, 201

    #delete a User
    def delete(self, id):
        u = User.query.filter_by(id=id).first()
        if u != g.user:
            return {'status':'error', 'description':'Unauthorized'}, 401
        else:
            try:
                # db.session.delete(u)
                # db.session.commit()
                logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
                return {'status':'success'}, 201
            except:
                return {'status':'error', 'description':'Something went wrong'}, 500


class UserListAPI(Resource):
    def __init__(self):
        super(UserListAPI, self).__init__()

    @auth.login_required
    def get(self):
        u = User.query.all()
        data = []

        for i in u:
            data.append({'id': i.id,
                        'email': i.email,
                        'username': i.username,
                        'about_me': i.about_me,
                        'last_seen': i.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                        'birthday': i.birthday,
                        'uri': "/api/user/" + str(i.id),
                        'profile_img_url': None if i.profile_img_id is None else url_for('send_pic',img_id=i.profile_img_id,img_type='thumb_sm', _external=True)})

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'data': data}, 200

    def post(self):
        if request.json:
            params = request.json
        elif request.form:
            params = request.form
        else:
            return {'status':'error',
                    'description':'Request Failed!'}, 400

        # Check Requirements <Email, Password>
        if not 'email' in params:
            return {'status':'error',
                    'description':'Email Address input error!'}, 400
        elif not 'password' in params:
            return {'status':'error',
                    'description':'Password Missing'}, 400

        # Check email address is unique
        if User.email_exists(params['email']):
            return {'status':'error',
                    'description':'Already registered Email address'}, 400

        # Make username based on email address when it was not submitted.
        if not 'username' in params or params['username'] == "" or params['username'] == None:
            username = params['email'].split('@')[0]
            username = User.make_valid_username(username)
            # username = User.make_unique_username(username)
        else:
            username = params['username']
            if User.username_exists(username):
                return {'status':'error',
                        'description':'Username already exists.'}, 400

        # Check User Birthday
        if not 'birthday' in params or params['birthday']=="":
            birthday = None
        else:
            birthday = params['birthday']

        u = User(email=params['email'],
                 username=username,
                 fb_id=None,
                 birthday=birthday)

        # Password Hashing
        u.hash_password(params['password'])

        u.key = md5('ACTIVATION'+str(int(random.random()*10000))).hexdigest()

        # Database Insert/Commit
        try:
            db.session.add(u)
            db.session.commit()
        except:
            return {'status':'error',
                    'description':'Something went wrong.'}, 500



        send_awaiting_confirm_mail(u)
        g.user = u
        token = g.user.generate_auth_token()

        logging_auth(g.user.id, "register", "email")
        stsd.gauge('User_Registration', 1, delta=True)

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'data':{'user':{'id': g.user.id,
                                'username': g.user.username,
                                'email': g.user.email,
                                'birthday': g.user.birthday,
                                'confirmed_at':g.user.confirmed_at.strftime("%Y-%m-%d %H:%M:%S") if g.user.confirmed_at else None},
                        'token': token.decode('ascii')}}, 201



api.add_resource(UserAPI, '/api/user/<int:id>', endpoint='user')
api.add_resource(UserListAPI, '/api/users', endpoint='users')


##### about BUCKET / BUCKETLIST ####################################

### Single Bucket #######
class BucketAPI(Resource):
    # decorators = [auth.login_required]

    def __init__(self):
        super(BucketAPI, self).__init__()

    def get(self, id):
        if request.authorization is not None:
	    try:
                g.user = User.verify_auth_token(request.authorization['username'])
   		uid = g.user.id
 	    except:
	        uid = None
        else:
	    uid = None
        b = Bucket.query.filter(Bucket.id==id, Bucket.status!='9').first()
        if b == None:
            return {'status':'error', 'description':'No data found'}, 204

        if b.fb_feed_id is not None:
            social_user = UserSocial.query.filter_by(user_id=b.user_id).first()
            graph = facebook.GraphAPI(social_user.access_token)
            fb_likes = graph.get_object(b.fb_feed_id+'/likes')
            fb_comments = graph.get_object(b.fb_feed_id+'/comments')

        data={
            'id': b.id,
            'user_id': b.user_id,
            'title': b.title,
            'description': b.description,
            'level': b.level,
            'status': b.status,
            'private': b.private,
            'parent_id': b.parent_id,
            'reg_dt': b.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
            'deadline': b.deadline.strftime("%Y-%m-%d"),
            'scope': b.scope,
            'range': b.range,
            'rpt_type': b.rpt_type,
            'rpt_cndt': b.rpt_cndt,
            'lst_mod_dt': None if b.lst_mod_dt is None else b.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
            # 'cvr_img_url_old': None if b.cvr_img_id is None else photos.url(File.query.filter_by(id=b.cvr_img_id).first().name),
            'cvr_img_url': None if b.cvr_img_id is None else url_for('send_pic',img_id=b.cvr_img_id,img_type='thumb_md',_external=True),
            'fb_feed_id': None if b.fb_feed_id is None else b.fb_feed_id,
            'fb_likes': None if b.fb_feed_id is None else fb_likes['data'],
            'fb_comments': None if b.fb_feed_id is None else fb_comments['data']
        }

        logging_api(uid, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'GET Success',
                'data':data}, 200

    @auth.login_required
    def put(self, id):
        if request.json:
            params = request.json
        elif request.form:
            params = {}
            for key in request.form:
                params[key] = request.form[key]
        else:
            return {'status':'error','description':'Request Failed'}, 500

        b = Bucket.query.filter_by(id=id).first()
        if b.user_id != g.user.id:
            return {'status':'error','description':'Unauthorized'}, 401

        for key in params:
            value = None if params[key]=="" else params[key]

            # Editable Fields
            if key not in ['title','status','private','deadline','description','parent_id','scope','range','rpt_type','rpt_cndt','cvr_img_id','fb_share']:
                return {'status':'error','description':'Invalid key: '+key}, 403

            # Nobody can modify id, user_id, reg_dt
            # if key in ['id','user_id','reg_dt']:
            #     return {'status':'error','description':'Cannot change '+key}, 403

            # Just ROLE_ADMIN user can change 'language', 'level'
            if key in ['language','level'] and g.user.role == ROLE_USER:
                return {'status':'error','description':'Only Admin can change' + key}, 401

            # When modify user's parent_id adjusts its level
            if key == 'parent_id':
                if value == None:
                    params['level'] = '0'
                else:
                    pb = Bucket.query.filter_by(id=int(value)).first() # pb = parent bucket
                    if pb == None:
                        return {'status':'error','description':'Parent does not exists'}, 400
                    else:
                        params['level'] = str(int(pb.level)+1)

            # Set other key's validation
            if key == 'title' and len(value) > 128:
                return {'status':'error','description':'Title length must be under 128'}, 400

            if key == 'description' and len(value) > 512:
                return {'status':'error','description':'Description too long (512)'}, 400

            if key == 'deadline':
                value = datetime.datetime.strptime(value,'%Y-%m-%d')

            if key == 'scope' and value not in ['DECADE','YEARLY','MONTHLY']:
                return {'status':'error','description':'Invalid scope value'}, 400

            if key == 'rpt_type' and value not in ['WKRP','WEEK','MNTH']:
                return {'status':'error','description':'Invalid repeat-type value'}, 400

            if key == 'rpt_cndt':
                dayOfWeek = datetime.date.today().weekday()

                if params['rpt_type'] == 'WKRP':
                    if b.rpt_type == 'WKRP':
                        if b.rpt_cndt[dayOfWeek] != value[dayOfWeek]:
                            if value[dayOfWeek] == '1':
                                p = Plan.query.filter_by(bucket_id=id, date=datetime.date.today().strftime("%Y%m%d")).first()
                                if p is None:
                                    p = Plan(date=datetime.date.today().strftime("%Y%m%d"),
                                             user_id=b.user_id,
                                             bucket_id=id,
                                             status=0,
                                             lst_mod_dt=datetime.datetime.now())
                                    db.session.add(p)
                                else:
                                    p.lst_mod_dt = datetime.datetime.now()
                            else:
                                try:
                                    p = Plan.query.filter_by(date=datetime.date.today().strftime("%Y%m%d"),bucket_id=id).first()
                                    db.session.delete(p)
                                except:
                                    pass
                    else:
                        p = Plan.query.filter_by(bucket_id=id, date=datetime.date.today().strftime("%Y%m%d")).first()
                        if p is None:
                            p = Plan(date=datetime.date.today().strftime("%Y%m%d"),
                                     user_id=b.user_id,
                                     bucket_id=id,
                                     status=0,
                                     lst_mod_dt=datetime.datetime.now())
                            db.session.add(p)
                        else:
                            p.lst_mod_dt = datetime.datetime.now()
                else:
                    if b.rpt_type == 'WKRP' and b.rpt_cndt[dayOfWeek] == '1':
                        try:
                            p = Plan.query.filter_by(date=datetime.date.today().strftime("%Y%m%d"),bucket_id=id).first()
                            db.session.delete(p)
                        except:
                            pass


            setattr(b, key, value)

        if 'photo' in request.files:
            upload_type = 'photo'

            if len(request.files[upload_type].filename) > 64:
                return {'status':'error',
                        'description':'Filename is too long (Max 64bytes include extensions)'}, 403
            upload_files = UploadSet('photos',IMAGES)
            configure_uploads(app, upload_files)

            filename = upload_files.save(request.files[upload_type])
            basedir = os.path.abspath('app/static/uploads/photos')

            # MAKE THUMBNAIL IMAGES
            # TODO: Make Function
            img = Image.open(os.path.abspath('app/static/uploads/photos/'+filename))

            org_width = img.size[0]
            org_height = img.size[1]

            longer_side = ('width', org_width) if org_width > org_height else ('height', org_height)

            if longer_side[1] > 540:
                img.thumbnail((540, 540), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_md',filename), quality=75, optimize=True, progressive=True)


            if longer_side[1] > 256:
                img.thumbnail((256,256), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_sm',filename), quality=50, optimize=True, progressive=True)

            splits = []

            for item in filename.split('.'):
                splits.append(item)
            extension = filename.split('.')[len(splits) -1]

            f = File(filename=filename, user_id=g.user.id, extension=extension, type=upload_type)
            db.session.add(f)
            db.session.flush()
            db.session.refresh(f)

            setattr(b, 'cvr_img_id', f.id)

        if 'fb_share' in params:
            try:

                if params['fb_share'] in [True,'true'] and b.fb_feed_id is None:
                    feed={}
                    feed['message']= g.user.username.encode('utf-8') + " are dreaming " + params['title'].encode('utf-8') + " on WishB. "
                    feed['link']=WISHB_SERVER_URI + "wish/" + str(b.id)
                    feed['caption']="Wish B."
                    feed['description']="" if b.description is None else b.description.encode('utf-8')
                    feed['name']=b.title.encode('utf-8')
                    if 'photo' in request.files or b.cvr_img_id is not None:
                        feed['picture']= None if b.cvr_img_id is None else url_for('send_pic', img_id=b.cvr_img_id, img_type='origin', _external=True)

            	    facebook_feed(feed, g.user.id, 'bucket', b.id)
                    logging_social(g.user.id, 'Facebook', 'share', 'bucket', inspect.stack()[0][3])
                elif params['fb_share'] in [False, 'false']:
                    if b.fb_feed_id is not None:
                        social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
                        graph = facebook.GraphAPI(social_user.access_token)
                        graph.delete_object(b.fb_feed_id)

                        logging_social(g.user.id, 'Facebook', 'delete', 'bucket', inspect.stack()[0][3])
                        setattr(b, 'fb_feed_id', None)
            except:
                pass

        try:
            b.lst_mod_dt = datetime.datetime.now()
            db.session.commit()
        except:
            db.session.rollback()
            return {'status':'error', 'description':'Something went wrong'}, 500

        data={'id': b.id,
              'user_id': b.user_id,
              'title': b.title,
              'description': b.description,
              'level': b.level,
              'status': b.status,
              'private': b.private,
              'parent_id': b.parent_id,
              'reg_dt': b.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
              'deadline': b.deadline.strftime("%Y-%m-%d"),
              'scope': b.scope,
              'range': b.range,
              'rpt_type': b.rpt_type,
              'rpt_cndt': b.rpt_cndt,
              'lst_mod_dt': None if b.lst_mod_dt is None else b.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
              'cvr_img_url': None if b.cvr_img_id is None else url_for('send_pic',img_id=b.cvr_img_id,img_type='thumb_md', _external=True)}

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Bucket put success.',
                'data':data}, 200

    @auth.login_required
    def delete(self, id):
        b = Bucket.query.filter_by(id=id).first()

        # Only bucket's owner can delete action.
        if b.user_id != g.user.id:
            return {'status':'error', 'description':'Unauthorized'}, 401

        try:
            b.status = '9'
            b.lst_mod_dt = datetime.datetime.now()

            p = Plan.query.filter_by(date=datetime.date.today().strftime("%Y%m%d"),bucket_id=id).first()
            if p is not None:
                db.session.delete(p)

            if b.fb_feed_id is not None:
                social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
                graph = facebook.GraphAPI(social_user.access_token)
                resp = graph.delete_object(b.fb_feed_id)

            db.session.commit()
            logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
            return {'status':'success'}, 200
        except:
            return {'status':'error',
                    'description':'delete failed'}, 403


### User Bucket List ######
class UserBucketAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(UserBucketAPI, self).__init__()

    def get(self, id):
        u = User.query.filter_by(id=id).first()
        if not g.user.is_following(u):
            if g.user == u:
                pass
            else:
                return {'status':'error', 'description':'User unauthorized'}, 401

        data = []
        if g.user == u:
            b = Bucket.query.filter(Bucket.user_id==u.id,
                                    Bucket.status!='9',
                                    Bucket.level=='0').all()
        else:
            b = Bucket.query.filter(Bucket.user_id==u.id,
                                    Bucket.status!='9',
                                    Bucket.level=='0',
                                    Bucket.private=='0').all()

        if len(b) == 0:
            return {'status':'error', 'description':'No data Found'}, 204

        if u.fb_id is not None:
            social_user = UserSocial.query.filter_by(user_id=u.id).first()
            graph = facebook.GraphAPI(social_user.access_token)

        for i in b:
            # if u.fb_id is not None and i.fb_feed_id is not None:
            #     fb_likes = graph.get_object(i.fb_feed_id+'/likes')
            #     fb_comments = graph.get_object(i.fb_feed_id+'/comments')
            data.append({
                'id': i.id,
                'user_id': i.user_id,
                'title': i.title,
                'description': i.description,
                'level': i.level,
                'status': i.status,
                'private': i.private,
                'parent_id': i.parent_id,
                'reg_dt': i.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'deadline': None if i.deadline is None else i.deadline.strftime("%Y-%m-%d"),
                'scope': i.scope,
                'range': i.range,
                'rpt_type': i.rpt_type,
                'rpt_cndt': i.rpt_cndt,
                'lst_mod_dt': None if i.lst_mod_dt is None else i.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
                # 'cvr_img_url_old': None if i.cvr_img_id is None else photos.url(File.query.filter_by(id=i.cvr_img_id).first().name),
                'cvr_img_url': None if i.cvr_img_id is None else url_for('send_pic',img_id=i.cvr_img_id,img_type='thumb_md', _external=True),
                'fb_feed_id': None if i.fb_feed_id is None else i.fb_feed_id,
                # 'fb_likes': None if i.fb_feed_id is None else fb_likes['data'],
                # 'fb_comments': None if i.fb_feed_id is None else fb_comments['data']
            })

        stsd.gauge('BucketList_API_Call', 1, delta=True)

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'normal',
                'data':data}, 200

    def post(self, id):
        u = User.query.filter_by(id=id).first()
        if u.id != g.user.id:
            return {'status':'error',
                    'description':'Unauthorized'}, 401

        if request.json:
            params = request.json
        elif request.form:
            params = {}
            for key in request.form:
                params[key] = request.form[key]
        else:
            return {'status':'error','description':'Request Failed'}, 400


        # Replace blank value to None(null) in params
        for key in params:
            params[key] = None if params[key] == "" else params[key]

            if key in ['id', 'user_id', 'reg_dt', 'language']:
                return {'status':'error', 'description': key + ' cannot be entered manually.'}, 400

        # Bucket Title & Deadline required
        if not 'title' in params or params['title'] == None:
            return {'status':'error', 'description':'Bucket title required'}, 400

        if not 'deadline' in params or params['deadline'] == None:
            return {'status':'error', 'description':'Bucket deadline required'}, 400

        # Check ParentID is Valid & set level based on ParentID
        if not 'parent_id' in params or params['parent_id'] == None:
            level = 0
        else:
            b = Bucket.query.filter_by(id=params['parent_id']).first()
            if b is None:
                return {'status':'error', 'description':'Invalid ParentID'}, 400
            elif b.user_id != g.user.id:
                return {'status':'error', 'description':'Cannot make sub_bucket with other user\'s Bucket'}, 400
            else:
                level = int(b.level) + 1

        if 'rpt_type' in params:
            if params['rpt_type'] not in ['WKRP','WEEK','MNTH']:
                return {'status':'error',
                        'description':'Invalid repeat-type value'}, 400

        if 'rpt_cndt' in params:
            dayOfWeek = datetime.date.today().weekday()
            if params['rpt_type'] == 'WKRP':
                if params['rpt_cndt'][dayOfWeek] == '1':
                    p = Plan(date=datetime.date.today().strftime("%Y%m%d"),
                             user_id=g.user.id,
                             bucket_id=None,
                             status=0,
                             lst_mod_dt=datetime.datetime.now())
                    db.session.add(p)

        if 'photo' in request.files:
            upload_type = 'photo'

            if len(request.files[upload_type].filename) > 64:
                return {'status':'error','description':'Filename is too long (Max 64bytes include extensions)'}, 403
            upload_files = UploadSet('photos',IMAGES)
            configure_uploads(app, upload_files)

            basedir = os.path.abspath('app/static/uploads/photos')
            filename = upload_files.save(request.files[upload_type])

            # MAKE THUMBNAIL IMAGES
            # TODO: Make Function
            img = Image.open(os.path.abspath('app/static/uploads/photos/'+filename))

            org_width = img.size[0]
            org_height = img.size[1]

            longer_side = ('width', org_width) if org_width > org_height else ('height', org_height)

            if longer_side[1] > 540:
                img.thumbnail((540, 540), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_md',filename), quality=75, optimize=True, progressive=True)


            if longer_side[1] > 256:
                img.thumbnail((256,256), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_sm',filename), quality=50, optimize=True, progressive=True)

            splits = []

            for item in filename.split('.'):
                splits.append(item)
            extension = filename.split('.')[len(splits) -1]

            f = File(filename=filename, user_id=g.user.id, extension=extension, type=upload_type)
            db.session.add(f)
            db.session.flush()
            db.session.refresh(f)


        bkt = Bucket(title=params['title'],
                     user_id=g.user.id,
                     level=str(level),
                     status= params['status'] if 'status' in params else '0',
                     private=params['private'] if 'private' in params else False,
                     reg_dt=datetime.datetime.now(),
                     lst_mod_dt=datetime.datetime.now(),
                     deadline=datetime.datetime.strptime(params['deadline'],'%Y-%m-%d').date() if 'deadline' in params \
                                                                                                             else None,
                                                                                      # else datetime.datetime.now(),
                     description=params['description'] if 'description' in params else None,
                     parent_id=params['parent_id'] if 'parent_id' in params else None,
                     scope=params['scope'] if 'scope' in params else 'DECADE',
                     range=params['range'] if 'range' in params else None,
                     rpt_type=params['rpt_type'] if 'rpt_type' in params else None,
                     rpt_cndt=params['rpt_cndt'] if 'rpt_cndt' in params else None,
                     cvr_img_id=f.id if 'photo' in request.files else None)
                     # cvr_img_id=f.id if 'cvr_img' in params and params['cvr_img'] == 'true' else None)
        db.session.add(bkt)
        db.session.flush()
        db.session.refresh(bkt)

        if 'rpt_cndt' in params:
            if params['rpt_type'] == 'WKRP' and params['rpt_cndt'][dayOfWeek] == '1':
                p.bucket_id = bkt.id

        if 'fb_share' in params and params['fb_share'] in [True,'true']:
            # social_user = UserSocial.query.filter_by(user_id=u.id).first()
            # graph = facebook.GraphAPI(social_user.access_token)
            # resp = graph.put_object("me","wish_ballon:dream",
            #                         wish={'og:url':WISHB_SERVER_URI,
            #                               'og:title':'TEST_TITLE' })

            feed = {}
            feed['message']= g.user.username.encode('utf-8') + " is Dreaming " + params['title'].encode('utf-8') + " on Wish B."
            feed['link']=WISHB_SERVER_URI + "wish/" + str(bkt.id)
            feed['caption']="Wish B"
            feed['description']="" if bkt.description is None else bkt.description.encode('utf-8')
            feed['name']=bkt.title.encode('utf-8')
            if 'photo' in request.files:
                feed['picture']=url_for('send_pic', img_id=bkt.cvr_img_id, img_type='origin', _external=True)

 	    db.session.flush()
            facebook_feed(feed, id, 'bucket', bkt.id)
            logging_social(g.user.id, 'Facebook', 'share', 'bucket', inspect.stack()[0][3])
            # bkt.fb_feed_id = resp['id']

        db.session.commit()
        data={
            'id': bkt.id,
            'user_id': bkt.user_id,
            'title': bkt.title,
            'description': bkt.description,
            'level': bkt.level,
            'status': bkt.status,
            'private': bkt.private,
            'parent_id': bkt.parent_id,
            'reg_dt': bkt.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
            'deadline': bkt.deadline.strftime("%Y-%m-%d"),
            'scope': bkt.scope,
            'range': bkt.range,
            'rpt_type': bkt.rpt_type,
            'rpt_cndt': bkt.rpt_cndt,
            'lst_mod_dt': None if bkt.lst_mod_dt is None else bkt.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
            # 'cvr_img_url_old': None if bkt.cvr_img_id is None else photos.url(File.query.filter_by(id=bkt.cvr_img_id).first().name),
            'cvr_img_url': None if bkt.cvr_img_id is None else url_for('send_pic',img_id=bkt.cvr_img_id,img_type='thumb_md', _external=True),
            'fb_feed_id':None if bkt.fb_feed_id is None else bkt.fb_feed_id
        }

        try:
            stsd.gauge('BucketAdd_API_Call', 1, delta=True)
        except:
            pass

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Bucket posted successfully.',
                'data':data}, 201


api.add_resource(BucketAPI, '/api/bucket/<int:id>', endpoint='bucket')
api.add_resource(UserBucketAPI, '/api/buckets/user/<int:id>', endpoint='buckets')




##### TODAY ##################################################

class TodayListAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(TodayListAPI, self).__init__()

    def get(self,user_id):

        data = []
        page_result = None
        u = User.query.filter_by(id = user_id).first()
        if u is None:
            return {'status':'error',
                    'description':'User does not Exists'}, 400

        if u.id != g.user.id:
            return {'status':'error',
                    'description':'Unauthorized'}, 401

        if 'page' in request.args:
            page = int(request.args['page'])
            total_cnt = db.session.query(Plan, Bucket).filter(Plan.bucket_id==Bucket.id, Plan.user_id==user_id).count()
            result = db.session.query(Plan, Bucket) \
                               .filter(Plan.bucket_id==Bucket.id, Plan.user_id==user_id) \
                               .order_by(Plan.date.desc(), Plan.id.asc())[POSTS_PER_PAGE*(page-1):POSTS_PER_PAGE*page]
        elif 'fdate' in request.args or 'tdate' in request.args:
            result = db.session.query(Plan, Bucket).filter(Plan.bucket_id==Bucket.id,
                                                           Plan.user_id==user_id,
                                                           Plan.date>=request.args['fdate'] if 'fdate' in request.args else '19000101',
                                                           Plan.date<=request.args['tdate'] if 'tdate' in request.args else datetime.datetime.now().strftime('%Y%m%d')).all()
        else:
            return {'status':'error',
                    'description':'PAGE or FDATE, TDATE must be set'}, 400

        for p, b in (result if page_result is None else page_result):
            data.append({
                'id': p.id,
                'date': p.date,
                'bucket_id': p.bucket_id,
                'user_id': p.user_id,
                'title': b.title,
                'status': b.status,
                'private': b.private,
                'deadline': b.deadline.strftime("%Y-%m-%d"),
                'scope': b.scope,
                'range': b.range,
                'rpt_type': b.rpt_type,
                'rpt_cndt': b.rpt_cndt,
                'cvr_img_url': None if b.cvr_img_id is None else url_for('send_pic',img_id=b.cvr_img_id,img_type='thumb_md', _external=True)
                # None if b.cvr_img_id is None else photos.url(File.query.filter_by(id=b.cvr_img_id).first().name)
            })

        if len(data) == 0:
            return {'status':'success',
                    'description':'No Plans returned'}, 204

        try:
            stsd.gauge('Today_API_GET', 1, delta=True)
        except:
            pass

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Get Today list succeed. (Count: '+str(len(data))+')',
                'data':{
                    'total_cnt':len(result) if request.args['page'] is None else total_cnt,
                    'page_cnt':None if request.args['page'] is None else POSTS_PER_PAGE,
                    'page':None if request.args['page'] is None else request.args['page'],
                    'page_data':data}}, 200


class TodayExistsAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(TodayExistsAPI, self).__init__()

    def get(self, user_id):
        u = User.query.filter_by(id = user_id).first()
        if u is None:
            return {'status':'error',
                    'description':'User does not Exists'}, 400

        if u.id != g.user.id:
            return {'status':'error',
                    'description':'Unauthorized'}, 401

        result = db.session.query(Plan.date).filter(Plan.user_id==user_id).distinct(Plan.date).all()

        if len(result) == 0:
            return {'status':'success','description':'No data Found'}, 204
        else:
            data = []
            for i in range(len(result)):
                data.append(result[i][0])

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {"status":"success",
                "description":"count: "+ str(len(result)),
                "data":data}, 200


class TodayAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(TodayAPI, self).__init__()

    def put(self, id):
        if request.json:
            params = request.json
        elif request.form:
            params = request.form
        else:
            return {'status':'error', 'description':'Request Failed!'}

        p = Plan.query.filter_by(id=id).first()
        if p.user_id != g.user.id:
            return {'status':'error', 'description':'Unauthorized'}, 401

        try:
            for item in params:
                if item:
                    setattr(p, item, params.get(item))
            db.session.commit()
        except:
            return {'status':'error', 'description':'failed'}, 401

        try:
            stsd.gauge('Today_API_PUT', 1, delta=True)
        except:
            pass

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'succeed'}, 200

api.add_resource(TodayListAPI, '/api/user/<user_id>/today', endpoint='todayList')
api.add_resource(TodayExistsAPI, '/api/user/<user_id>/today/exists', endpoint='todayExists')
api.add_resource(TodayAPI, '/api/today/<id>', endpoint='today')


##### FILE UPLOADS ##############################################

class UploadFiles(Resource):
    decorators = [auth.login_required]
    def __init__(self):
        super(UploadFiles, self).__init__()

    def post(self):
        if 'photo' in request.files:
            upload_type = 'photo'

            upload_files = UploadSet('photos',IMAGES)
            configure_uploads(app, upload_files)

            filename = upload_files.save(request.files[upload_type])
            splits = []
            for item in filename.split('.'):
                splits.append(item)
            extension = filename.split('.')[len(splits) - 1]
        else:
            return {'status':'error',
                    'description':'No attached Files'}, 400

        f = File(filename=filename, user_id=g.user.id, extension=extension, type=upload_type)
        try:
            db.session.add(f)
            db.session.commit()
        except:
            return {'status':'error',
                    'description':'Something went wrong'}, 500

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Upload Succeeded',
                'data':{'id':f.id,
                        'url':upload_files.url(f.name)}}, 201


api.add_resource(UploadFiles, '/api/file', endpoint='uploadFiles')


##### TIMELINE / Single Post #################################################

class BucketTimeline(Resource):
    # decorators = [auth.login_required]

    def __init__(self):
        super(BucketTimeline, self).__init__()

    def get(self, bucket_id):
        if request.authorization is not None:
            g.user = User.verify_auth_token(request.authorization['username'])
            uid = g.user.id
        else:
            uid = None
        b = Bucket.query.filter_by(id=bucket_id).first()
        if b is None:
            return {'status':'error',
                    'description':'There\'s no bucket with id: '+ str(id)}, 204

        u = User.query.filter_by(id=b.user_id).first()
        # if not g.user.is_following(u):
        #     if g.user == u:
        #         pass
        #     else:
        #         return {'status':'error', 'description':'User unauthorized'}, 401

        # post = Post.query.filter_by(bucket_id=bucket_id).all()
        if 'date' in request.args:
            result = db.session.query(Post).filter(Post.bucket_id==bucket_id, Post.date==request.args['date']).order_by(Post.content_dt.desc()).all()
        elif 'page' in request.args:
            page = int(request.args['page'])
            total_cnt = db.session.query(Post).filter(Post.bucket_id==bucket_id).count()
            result = db.session.query(Post).filter(Post.bucket_id==bucket_id).order_by(Post.content_dt.desc(),Post.id.desc())[POSTS_PER_PAGE*(page-1):POSTS_PER_PAGE*page]
        else:
            result = db.session.query(Post).filter(Post.bucket_id==bucket_id).order_by(Post.content_dt.desc(),Post.id.desc()).all()

        if result is None:
            return {'status':'success',
                    'description':'No posts'}, 204
        data = {}
        timelineData = []
        for i in result:
            timelineData.append({'id':i.id,
                    'user_id':i.user_id,
                    'date':i.date,
                    'content_dt':i.content_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    'bucket_id':i.bucket_id,
                    'text':None if i.text is None else i.text,
                    'img_url':None if i.img_id is None else url_for('send_pic',img_id=i.img_id,img_type='thumb_md', _external=True),
                    'urls':[{'url1':None if i.url1 is None else i.url1},
                            {'url2':None if i.url2 is None else i.url2},
                            {'url3':None if i.url3 is None else i.url3},],
                    'reg_dt':i.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    'lst_mod_dt': None if i.lst_mod_dt is None else i.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    'fb_feed_id': None if i.fb_feed_id is None else i.fb_feed_id})

        data['count'] = len(result)
        data['timelineData'] = timelineData

        try:
            stsd.gauge('Timeline_API_GET', 1, delta=True)
        except:
            pass

        logging_api(uid, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description': str(len(result)) + ' posts were returned.',
                'data':data}, 200

    @auth.login_required
    def post(self, bucket_id):
        b = Bucket.query.filter_by(id=bucket_id).first()
        if b is None:
            return {'status':'error',
                    'description':'There\'s no bucket with id: '+id}, 403

        if g.user.id != b.user_id:
            return {'status':'error',
                    'description':'Unauthorized'}, 401

        if request.json:
            params = request.json
        elif request.form:
            params = {}
            for key in request.form:
                params[key] = request.form[key]
        else:
            return {'status':'error','description':'Request Failed'}, 400

        # Replace blank value to None(null) in params
        for key in params:
            params[key] = None if params[key] == "" else params[key]

            if key in ['id', 'user_id', 'bucket_id', 'language', 'body', 'timestamp', 'reg_dt', 'lst_mod_dt']:
                return {'status':'error', 'description': key + ' cannot be entered manually.'}, 401

        contents = []

        if 'text' in params and params['text'] is not None:
            contents.append('text')

        if 'url1' in params and params['url1'] is not None:
            contents.append('url1')

        if 'url2' in params and params['url2'] is not None:
            contents.append('url2')

        if 'url3' in params and params['url3'] is not None:
            contents.append('url3')

        if 'photo' in request.files:
            upload_type = 'photo'

            if len(request.files[upload_type].filename) > 64:
                return {'status':'error',
                        'description':'Filename is too long (Max 64bytes include extensions)'}, 403
            upload_files = UploadSet('photos',IMAGES)
            configure_uploads(app, upload_files)

            basedir = os.path.abspath('app/static/uploads/photos')
            filename = upload_files.save(request.files[upload_type])
            # MAKE THUMBNAIL IMAGES
            # TODO: Make Function
            img = Image.open(os.path.abspath('app/static/uploads/photos/'+filename))

            org_width = img.size[0]
            org_height = img.size[1]

            longer_side = ('width', org_width) if org_width > org_height else ('height', org_height)

            if longer_side[1] > 540:
                img.thumbnail((540, 540), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_md',filename), quality=75, optimize=True, progressive=True)


            if longer_side[1] > 256:
                img.thumbnail((256,256), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_sm',filename), quality=50, optimize=True, progressive=True)

            splits = []

            for item in filename.split('.'):
                splits.append(item)
            extension = filename.split('.')[len(splits) -1]

            f = File(filename=filename, user_id=g.user.id, extension=extension, type=upload_type)
            db.session.add(f)
            db.session.flush()
            db.session.refresh(f)
        else:
            if len(contents) == 0:
                return {'status':'error',
                        'description':'Nothing to Post'}, 403

        p = Plan.query.filter_by(bucket_id=b.id).first()

        if p is None:
            plan = Plan(date=datetime.datetime.now().strftime('%Y%m%d'),
                        user_id=g.user.id,
                        bucket_id=b.id,
                        status=0,
                        lst_mod_dt=datetime.datetime.now())
            db.session.add(plan)

        post = Post(body=None,
                    date=params['content_dt'].split()[0].split('-')[0] + \
                         params['content_dt'].split()[0].split('-')[1] + \
                         params['content_dt'].split()[0].split('-')[2]   \
                         if 'content_dt' in params else datetime.datetime.now().strftime('%Y%m%d'),
                    content_dt=datetime.datetime.strptime(params['content_dt'],'%Y-%m-%d %H:%M:%S') if 'content_dt' in params else datetime.datetime.now(),
                    user_id=b.user_id,
                    language=None,
                    bucket_id=bucket_id,
                    text=params['text'] if 'text' in params else None,
                    img_id=f.id if 'photo' in request.files else None,
                    url1=params['url1'] if 'url1' in params else None,
                    url2=params['url2'] if 'url2' in params else None,
                    url3=params['url3'] if 'url3' in params else None,
                    reg_dt=datetime.datetime.now(),
                    lst_mod_dt=datetime.datetime.now())


        db.session.add(post)
        db.session.flush()
        db.session.refresh(post)

        if 'fb_share' in params and params['fb_share'] in ['true',True]:
            feed={}
            feed['message'] = g.user.username.encode('utf-8') + " get closer to dream '" + b.title.encode('utf-8') + "' on Wish B"
            feed['link']= WISHB_SERVER_URI + "wish/" + str(b.id)
            feed['caption']=b.title.encode('utf8')
            feed['description']="" if post.text is None else post.text.encode('utf-8')
            feed['name']="Wish B"
            if 'photo' in request.files:
                feed['picture']=url_for('send_pic', img_id=post.img_id, img_type='origin', _external=True)
            elif b.cvr_img_id is not None:
                feed['picture']=url_for('send_pic', img_id=b.cvr_img_id, img_type='origin', _external=True)

            facebook_feed(feed, g.user.id, 'timeline', post.id)
            logging_social(g.user.id, "Facebook", "Share", "Timeline", inspect.stack()[0][3])

        db.session.commit()

        data = {'id':post.id,
                'user_id':post.user_id,
                'bucket_id':post.bucket_id,
                'date':post.date,
                'text':None if post.text is None else post.text,
                'content_dt':post.content_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'img_url':None if post.img_id is None else url_for('send_pic',img_id=post.img_id,img_type='thumb_md', _external=True),
                'urls':[{'url1':None if post.url1 is None else post.url1},
                        {'url2':None if post.url2 is None else post.url2},
                        {'url3':None if post.url3 is None else post.url3},],
                'reg_dt':post.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'lst_mod_dt': None if post.lst_mod_dt is None else post.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'fb_feed_id': None if post.fb_feed_id is None else post.fb_feed_id}

        try:
            stsd.gauge('Timeline_API_POST', 1, delta=True)
        except:
            pass

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Successfully posted.',
                'data':data}, 201


class TimelineContent(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(TimelineContent, self).__init__()


    def get(self,content_id):
        post = Post.query.filter_by(id=content_id).first()
        if post is None:
            return {'status':'success',
                    'description':'There\'s no content with id: '+ str(id)}, 204

        u = User.query.filter_by(id=post.user_id).first()
        if not g.user.is_following(u):
            if g.user == u:
                pass
            else:
                return {'status':'error', 'description':'User unauthorized'}, 401

        data = {'id':post.id,
                'user_id':post.user_id,
                'date':post.date,
                'content_dt':post.content_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'bucket_id':post.bucket_id,
                'text':None if post.text is None else post.text,
                'img_url':None if post.img_id is None else url_for('send_pic',img_id=post.img_id,img_type='thumb_md', _external=True),
                'urls':[{'url1':None if post.url1 is None else post.url1},
                        {'url2':None if post.url2 is None else post.url2},
                        {'url3':None if post.url3 is None else post.url3},],
                'reg_dt':post.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'lst_mod_dt': None if post.lst_mod_dt is None else post.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'fb_feed_id': None if post.fb_feed_id is None else post.fb_feed_id}

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'success',
                'data':data}, 200


    def put(self,content_id):
        if request.json:
            params = request.json
        elif request.form:
            params = {}
            for key in request.form:
                params[key] = request.form[key]
        else:
            return {'status':'error','description':'Request Failed'}, 500

        post =  Post.query.filter_by(id=content_id).first()
        if post.user_id != g.user.id:
            return {'status':'error',
                    'description':'Unauthorized'}, 401

        for key in params:
            value = None if params[key] == "" else params[key]

            # Editable Fields
            if key not in ['text','url1','url2','url3','img_id','fb_share','content_dt']:
                return {'status':'error',
                        'description':key + ' field is not editable'}, 403

            # Just ROLE_ADMIN user can change 'language', 'level'
            if key in ['language'] and g.user.role == ROLE_USER:
                return {'status':'error','description':'Only Admin can change' + key}, 401

            # Set Key validataion
            # TODO: Make long url to shortened url
            if key in ['url1','url2','url3'] and len(value) > 512:
                return {'status':'error',
                        'description': key + ' is too long. (max 256 bytes)'}

            if key in ['content_dt']:
                value = datetime.datetime.strptime(params['content_dt'],'%Y-%m-%d %H:%M:%S')
                content_dt_val = params['content_dt'].split()[0].split('-')
                setattr(post, 'date', content_dt_val[0] + content_dt_val[1] + content_dt_val[2])

            setattr(post, key, value)

        if 'photo' in request.files:
            upload_type = 'photo'

            if len(request.files[upload_type].filename) > 64:
                return {'status':'error',
                        'description':'Filename is too long (Max 64bytes include extensions)'}, 403
            upload_files = UploadSet('photos',IMAGES)
            configure_uploads(app, upload_files)

            basedir = os.path.abspath('app/static/uploads/photos')
            filename = upload_files.save(request.files[upload_type])

            # MAKE THUMBNAIL IMAGES
            # TODO: Make Function
            img = Image.open(os.path.abspath('app/static/uploads/photos/'+filename))

            org_width = img.size[0]
            org_height = img.size[1]

            longer_side = ('width', org_width) if org_width > org_height else ('height', org_height)

            if longer_side[1] > 540:
                img.thumbnail((540, 540), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_md',filename), quality=75, optimize=True, progressive=True)


            if longer_side[1] > 256:
                img.thumbnail((256,256), Image.ANTIALIAS)
                img.save(os.path.join(basedir,'thumb_sm',filename), quality=50, optimize=True, progressive=True)


            splits = []

            for item in filename.split('.'):
                splits.append(item)
            extension = filename.split('.')[len(splits) -1]

            f = File(filename=filename, user_id=g.user.id, extension=extension, type=upload_type)
            db.session.add(f)
            db.session.flush()
            db.session.refresh(f)

            setattr(post, 'img_id', f.id)

        if 'fb_share' in params:
            social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
            graph = facebook.GraphAPI(social_user.access_token)

            if params['fb_share'] in [True,'true'] and post.fb_feed_id is None:
                b = Bucket.query.filter_by(id=post.bucket_id).first()
                feed = {}
                feed['message'] = g.user.username.encode('utf-8') + " get closer to dream '" + b.title.encode('utf-8') + "' on Wish B"
                feed['link']=WISHB_SERVER_URI + "wish/" + str(b.id)
                feed['caption']=b.title.encode('utf8')
                feed['description']="" if post.text is None else post.text.encode('utf-8')
                feed['name']="Wish B"
                if post.img_id is not None:
                    feed['picture']=url_for('send_pic', img_id=post.img_id, img_type='origin', _external=True)
                elif b.cvr_img_id is not None:
                    feed['picture']=url_for('send_pic', img_id=b.cvr_img_id, img_type='origin', _external=True)

                facebook_feed(feed, g.user.id, 'timeline', post.id)
                logging_social(g.user.id, 'Facebook', 'share', 'timeline', inspect.stack()[0][3])

            elif params['fb_share'] in [False, 'false']:
                if post.fb_feed_id is not None:
                    graph.delete_object(post.fb_feed_id)
                    logging_social(g.user.id, 'Facebook', 'delete', 'timeline', inspect.stack()[0][3])
                    setattr(post, 'fb_feed_id', None)

        try:
            post.lst_mod_dt = datetime.datetime.now()
            db.session.commit()
        except:
            db.session.rollback()
            return {'status':'error',
                    'description':'DB write error'}, 500

        data = {'id':post.id,
                'user_id':post.user_id,
                'date':post.date,
                'content_dt':post.content_dt.strftime('%Y-%m-%d %H:%M:%S'),
                'bucket_id':post.bucket_id,
                'text':None if post.text is None else post.text,
                'img_url':None if post.img_id is None else url_for('send_pic',img_id=post.img_id,img_type='thumb_md', _external=True),
                'urls':[{'url1':None if post.url1 is None else post.url1},
                        {'url2':None if post.url2 is None else post.url2},
                        {'url3':None if post.url3 is None else post.url3},],
                'reg_dt':post.reg_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'lst_mod_dt': None if post.lst_mod_dt is None else post.lst_mod_dt.strftime("%Y-%m-%d %H:%M:%S"),
                'fb_feed_id': None if post.fb_feed_id is None else post.fb_feed_id}

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'Post PUT success',
                'data':data}, 201


    def delete(self,content_id):
        post = Post.query.filter_by(id=content_id).first()

        if post.user_id != g.user.id:
            return {'status':'error',
                    'description':'Unauthorized'}, 401

        try:
            db.session.delete(post)
            if post.fb_feed_id is not None:
                social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
                graph = facebook.GraphAPI(social_user.access_token)
                graph.delete_object(post.fb_feed_id)

            db.session.commit()
        except:
            db.session.rollback()
            return {'status':'error',
                    'description':'DB delete failed'}, 403

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description':'DELETE success'}, 201


class TimelineExists(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        super(TimelineExists, self).__init__()

    def get(self, bucket_id):
        b = Bucket.query.filter_by(id=bucket_id).first()
        if b is None:
            return {'status':'error',
                    'description':'Bucket ' + bucket_id + ' does not exists.'}, 204

        u = User.query.filter_by(id=b.user_id).first()
        if u.id != g.user.id and b.private != '0':
            return {'status':'error',
                    'description':'Private Bucket'}, 401

        result = db.session.query(Post.date).filter(Post.bucket_id==bucket_id).distinct(Post.date).all()

        data = {}
        if len(result) == 0:
            return {'status':'error',
                    'description':'No rows returned'}, 204
        else:
            dateList = []
            for i in range(len(result)):
                dateList.append(result[i][0])

        data['count'] = len(result)
        data['minDate'] = db.session.query(func.min(Post.date).label("min_date")).filter(Post.bucket_id==bucket_id).first().min_date
        data['maxDate'] = db.session.query(func.max(Post.date).label("max_date")).filter(Post.bucket_id==bucket_id).first().max_date
        data['dateList'] = dateList

        logging_api(g.user.id, self.__class__.__name__, inspect.stack()[0][3])
        return {'status':'success',
                'description': 'Data successfully returned.',
                'data':data}, 200


api.add_resource(BucketTimeline, '/api/bucket/<bucket_id>/timeline', endpoint='bucketTimeline')
api.add_resource(TimelineContent, '/api/content/<content_id>', endpoint='timelineContent')
api.add_resource(TimelineExists, '/api/bucket/<bucket_id>/timeline/exists', endpoint='timelineExists')


class Report(Resource):

    def __init__(self):
        super(Report, self).__init__()

    def get(self):
        mdb = MongoClient(MONGODB_URI).wishb
        data = []

        if not 'type' in request.args or request.args['type'] == None:
            return {'status':'error', 'description': 'Report [TYPE] is required'}, 400
        elif request.args['type'] not in ['inquiry', 'crash']:
            return {'status':'error', 'description': 'Report type is not valid.'}, 400

        if 'page' in request.args:
            for result in mdb.report.find({'type':request.args['type']})\
                                  .sort("_id", -1).skip(POSTS_PER_PAGE*int(request.args['page'])).limit(POSTS_PER_PAGE):
                data.append(json.loads(json_util.dumps(result)))
        else:
            return {'status':'error', 'description':'PAGE NUMBER required'}, 400

        return {'status':'success', 'data':data}, 200


    def post(self):
        if request.json:
            params = request.json
        elif request.form:
            params = request.form
        else:
            return {'status':'error',
                    'description':'Request Failed!'}, 400

        for key in params:
            params[key] = None if params[key] == "" else params[key]

        if not 'type' in params or params['type'] == None:
            return {'status':'error', 'description': 'Report [TYPE] is required'}, 400
        elif params['type'] not in ['inquiry', 'crash']:
            return {'status':'error', 'description': 'Report type is not valid.'}, 400

        if not 'subject' in params or params['subject'] == None:
            return {'status':'error', 'description': 'content of [SUBJECT] is required'}, 400

        if not 'email' in params or params['email'] == None:
            try:
                params['email'] = g.user.email
            except:
                params['email'] = 'AnonymousUser'


        data = params
        data['reg_dt'] = datetime.datetime.now()

        try:
            print data
            mdb = MongoClient(MONGODB_URI).wishb
            mdb.report.insert(data)
        except:
            print data
            return {'status':'error', 'description':'something went wrong'}, 500

        return {'status':'success', 'data':json.loads(json_util.dumps(data))}, 200


api.add_resource(Report, '/api/report', endpoint='report')
