__author__ = 'massinet'

import facebook

from flask import g
from app import app, db
from models import User, UserSocial

social_user = UserSocial.query.filter_by(user_id=g.user.id).first()

graph = facebook.GraphAPI(social_user.access_token)


