__author__ = 'massinet'

import facebook
import time

from flask import g, url_for
from decorators import async
from app import app, db, mdb
from models import User, UserSocial, Bucket, Post
from config import WISHB_SERVER_URI

from bson.objectid import ObjectId


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


@async
def fb_add_bucket(bucket_id):
    social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
    graph = facebook.GraphAPI(social_user.access_token)
    try:
        bucket = mdb.buckets.find_one({'_id':ObjectId(bucket_id)})
        if 'bkt_img_id' in bucket:
            fb_feed = graph.put_object('me', 'feed',
                                       message = 'API v2 test',
                                       link = WISHB_SERVER_URI + 'wish/' + bucket_id,
                                       description = '' if bucket['description'] is None else bucket['description'].encode('utf-8'),
                                       picture = url_for('send_pic', img_id=bucket['bkt_img_id'], img_type='origin', _external=True),
                                       name = bucket['title'].encode('utf-8'))
        else:
            fb_feed = graph.put_object('me', 'feed',
                                       message = 'API v2 test',
                                       link = WISHB_SERVER_URI + 'wish/' + bucket_id,
                                       description = '' if bucket['description'] is None else bucket['description'].encode('utf-8'),
                                       name = bucket['title'].encode('utf-8'))

        mdb.buckets.update({'_id':ObjectId(bucket_id)}, {'$set':{'fb_feed_id':fb_feed['id']}}, upsert=True)
        return True
    except:
        return False


