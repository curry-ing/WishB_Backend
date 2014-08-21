from hashlib import md5
from passlib.apps import custom_app_context as pwd_context
from app import app

from sqlalchemy import select, and_, or_
from datetime import datetime

from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import UserMixin, RoleMixin
import flask.ext.whooshalchemy as whooshalchemy
import re

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired

from logging import logging_auth

db = SQLAlchemy(app)

ROLE_USER = 0
ROLE_ADMIN = 1

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), index = True, unique = True)
    password = db.Column(db.String(128))
    username = db.Column(db.String(64))
    posts = db.relationship('Post', backref = 'author', lazy = 'dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.now())
    birthday = db.Column(db.String(8))
    login_fault = db.Column(db.SmallInteger, default=0)         # if bigger than 5 = blocked
    fb_id = db.Column(db.String(128))
    active = db.Column(db.Boolean(), default=0)
    confirmed_at = db.Column(db.DateTime())
    key = db.Column(db.String(128))
    is_admin = db.Column(db.SmallInteger, default=ROLE_ADMIN)
    title_life = db.Column(db.String(128))
    title_10 = db.Column(db.String(128))
    title_20 = db.Column(db.String(128))
    title_30 = db.Column(db.String(128))
    title_40 = db.Column(db.String(128))
    title_50 = db.Column(db.String(128))
    title_60 = db.Column(db.String(128))
    profile_img_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    # last_read_notice = db.Column(db.String(128))
    followed = db.relationship('User',
        secondary = followers, 
        primaryjoin = (followers.c.follower_id == id), 
        secondaryjoin = (followers.c.followed_id == id), 
        backref = db.backref('followers', lazy = 'dynamic'), 
        lazy = 'dynamic')

    def __init__(self, email, username, fb_id, birthday):
        self.email = email
        self.fb_id = fb_id
        self.username = username
        self.birthday = birthday

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def make_valid_username(username):
        return re.sub('[^a-zA-Z0-9_\.]','', username)
    
    @staticmethod
    def make_unique_username(username):
        if User.query.filter_by(username = username).first() == None:
            return username
        version = 2
        while True:
            new_username = username + str(version)
            if User.query.filter_by(username = new_username).first() == None:
                break
            version += 1
        return new_username

    @staticmethod
    def email_exists(email):
        return User.query.filter_by(email=email).count() > 0

    @staticmethod
    def username_exists(username):
        return User.query.filter_by(username=username).count() > 0
        
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def avatar(self, size=128):
        return 'http://s.gravatar.com/avatar/' + md5(self.email).hexdigest() + '?d=mm&s=' + str(size)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return self

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return self

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def is_me(self, user):
        return self.filter()

    def followed_posts(self):
        return Post.query.outerjoin(followers, (followers.c.followed_id == Post.user_id)).filter(or_(followers.c.follower_id == self.id, Post.user_id == self.id)).order_by(Post.timestamp.desc())

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def generate_auth_token(self, expiration = 86400):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id':self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user

    @staticmethod
    def get_or_create(email, username, fb_id, birthday):
        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(email=email, username=username, fb_id=fb_id, birthday=birthday)
            user.profile_img_id = 0
            db.session.add(user)
            db.session.commit()
            logging_auth(user.id, "register", "social_fb")
        else:
            if user.fb_id is None or user.fb_id == "":
                user.fb_id = fb_id
                db.session.commit()
            if user.birthday is None or user.birthday == "":
                user.birthday = birthday
                db.session.commit()
            logging_auth(user.id, "login", "social_fb")
        return user


class Post(db.Model):
    __searchable__ = ['body']

    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(140))
    date = db.Column(db.String(8))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    language = db.Column(db.String(5))
    bucket_id = db.Column(db.Integer, db.ForeignKey('bucket.id'))
    text = db.Column(db.String(20480))
    img_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    url1 = db.Column(db.String(256))
    url2 = db.Column(db.String(256))
    url3 = db.Column(db.String(256))
    reg_dt = db.Column(db.DateTime)
    lst_mod_dt = db.Column(db.DateTime)
    content_dt = db.Column(db.DateTime)
    fb_feed_id = db.Column(db.String(128))

    def __repr__(self):
        return '<Post %r>' % self.body


class Bucket(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(128))
    description = db.Column(db.String(512))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    level = db.Column(db.SmallInteger, default=0)
    status = db.Column(db.SmallInteger, default=0)         # live:0 ,done:1, deleted:9
    private = db.Column(db.SmallInteger, default=0)      # private:1, public:0
    deadline = db.Column(db.DateTime)
    language = db.Column(db.String(5))
    parent_id = db.Column(db.Integer, default=0)
    scope = db.Column(db.String(8))
    range = db.Column(db.String(11))
    rpt_type = db.Column(db.String(4))                  # Repeat Type
    rpt_cndt = db.Column(db.String(8))                  # Repeat Condition
    reg_dt = db.Column(db.DateTime)                     # Registered Datetime
    lst_mod_dt = db.Column(db.DateTime)                 # Last Modified Datetime
    cvr_img_id = db.Column(db.Integer(11))
    fb_feed_id = db.Column(db.String(128))

    def __repr__(self):
        return '<Bucket %r>' % self.title


class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(8))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    bucket_id = db.Column(db.Integer, db.ForeignKey('bucket.id'))
    status = db.Column(db.Integer(1))
    lst_mod_dt = db.Column(db.DateTime)

    def __repr__(self):
        return '<Plan %r>' % self.id

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(16)) # IMAGE, VIDEO, AUDIO, FILE
    name = db.Column(db.String(256))
    extension = db.Column(db.String(4))
    user_id = db.Column(db.Integer)
    uploaded_dt = db.Column(db.DateTime, default=datetime.now())

    def __repr__(self):
        return '<Photo %r>' % self.name

    def __init__(self, filename, extension, user_id, type):
        self.name = filename
        self.user_id = user_id
        self.extension = extension
        self.type = type


class UserSocial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    provider = db.Column(db.String(32))
    uid = db.Column(db.String(256))
    access_token = db.Column(db.String(512))

    def __init__(self, user_id, provider, uid, access_token):
        self.user_id = user_id
        self.provider = provider
        self.uid = uid
        self.access_token = access_token

    @staticmethod
    def upsert_user(user_id, provider, uid, access_token):
        us = UserSocial.query.filter_by(user_id=user_id, provider=provider).first()
        if us is None:
            us = UserSocial(user_id, provider, uid, access_token)
            db.session.add(us)
            db.session.commit()
        else:
            us.access_token = access_token
            db.session.commit()


whooshalchemy.whoosh_index(app, Post)


