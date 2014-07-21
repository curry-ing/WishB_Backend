__author__ = 'massinet'

import facebook
import time

from flask import g
from decorators import async
from app import app, db
from models import User, UserSocial, Bucket, Post

@async
def facebook_feed(feed, user_id, obj_type, obj_id):
    social_user = UserSocial.query.filter_by(user_id=user_id).first()
    graph = facebook.GraphAPI(social_user.access_token)

    if 'picture' not in feed:
        resp = graph.put_object("me","feed",
                                message=feed['message'],
                                link=feed['link'],
                                caption=feed['caption'],
                                description=feed['description'],
                                name=feed['name'])
    else:
        resp = graph.put_object("me","feed",
                                message=feed['message'],
                                link=feed['link'],
                                picture=feed['picture'],
                                caption=feed['caption'],
                                description=feed['description'],
                                name=feed['name'])

    time.sleep(5)
    db.session.commit()

    if obj_type == 'bucket':
        obj = Bucket.query.filter_by(id=obj_id).first()
    elif obj_type == 'timeline':
        obj = Post.query.filter_by(id=obj_id).first()
    obj.fb_feed_id = resp['id']
    db.session.commit()

