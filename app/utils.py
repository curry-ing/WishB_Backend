__author__ = 'masunghoon'
import re
import os
import datetime

from app import mdb
from flask import g
from logging import logging_update

from PIL import Image
from bson import ObjectId
from decorators import async
from werkzeug.utils import secure_filename
from passlib.apps import custom_app_context as pwd_context

def check_req_params(request):
    if request.json:
        params = request.json
        print "1"
    elif request.form:
        params = request.form
        print "2"
    else:
        print "3"
        return False
        # return jsonify({'status': 'error', 'description': 'Request Failed!'}), 400
    return params


def is_email(email):
    pattern = '[\.\w]{1,}[@]\w+[.]\w+'
    if re.match(pattern, email):
        return True
    else:
        return False


def hash_password(password):
    return pwd_context.encrypt(password)


def upload_photo(req_file):
    basedir = os.path.abspath('app/static/uploads/photos')
    filename, extension = os.path.splitext(req_file.filename)
    filename = secure_filename(filename)
    fileFullname = filename + '.' + extension

    try:
        req_file.save(os.path.join(basedir, 'origin', fileFullname))
        file = {'type':'photo',
                'name':filename,
                'extension':extension,
                'user':{'id':g.user.id,
                        'username':g.user.username,
                        'email':g.user.email},
                'uploaded_dt':datetime.datetime.now()}
        make_thumbnails(fileFullname)
        return mdb.files.insert(file)
    except:
        return False

@async
def make_thumbnails(filename):
    basedir = os.path.abspath('app/static/uploads/photos')
    img = Image.open(os.path.abspath('app/static/uploads/photos/' + filename))

    org_width = img.size[0]
    org_height = img.size[1]

    longer_side = ('width', org_width) if org_width > org_height else ('height', org_height)

    if longer_side[1] > 540:
        img.thumbnail((540, 540), Image.ANTIALIAS)
        img.save(os.path.join(basedir, 'thumb_md', filename), quality=75, optimize=True, progressive=True)

    if longer_side[1] > 256:
        img.thumbnail((256, 256), Image.ANTIALIAS)
        img.save(os.path.join(basedir, 'thumb_sm', filename), quality=50, optimize=True, progressive=True)


@async
def check_user_app_version(version, os):
    prev_app_version = "undefined" if g.user.app_version is None else g.user.app_version
    curr_app_version = version
    if curr_app_version != prev_app_version:
        mdb.users.update({'_id':ObjectId(g.user.id)}, {'$set':{'app_version':curr_app_version}}, upsert=False)
        obj = {"user":{"id":g.user.id,
                       "username":g.user.username,
                       "email":g.user.email},
               "os":os,
               "previous_ver":prev_app_version,
               "updated_ver":curr_app_version,
               "update_date":datetime.now()
               }
        logging_update(obj)

