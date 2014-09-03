import re
import json
import random
import datetime

from bson import json_util, ObjectId
from flask import jsonify, request, url_for

from app import mdb, httpAuth
from app.mod_api import mod_api
from app.utils import is_email, hash_password, upload_photo

from hashlib import md5

##### /users - Userlist ###########################################
@mod_api.route('/users', methods=['GET'])
def get_users():
    data = []
    for result in mdb.users.find():
        data.append(json.loads(json_util.dumps(result)))
    return jsonify({'status':'success', 'data':data}), 200


@mod_api.route('/users', methods=['POST'])
def post_user():
    if request.json:
        params = request.json
    elif request.form:
        params = request.form
    else:
        return jsonify({'status': 'error', 'description': 'Request Parameter Missing!'}), 400

    # Check Requirements <Email, Password>
    if not 'email' in params:
        return jsonify({'status': 'error', 'description': 'Email Address Missing!'}), 400
    elif not 'password' in params:
        return jsonify({'status': 'error', 'description': 'Password Missing!'}), 400

    if mdb.users.find({'email':params['email']}).count() > 0:
        return jsonify({'status':'error', 'description':'Email Already Exists'}), 400

    if not is_email(params['email']):
        return jsonify({'status':'error', 'description':'Invalid Email Address'}), 400

    # Make username based on email address when it was not submitted.
    if not 'username' in params or params['username'] == "" or params['username'] == None:
        username = params['email'].split('@')[0]
        username = re.sub('[^a-zA-Z0-9_\.]','', username)
    else:
        username = params['username']

    # Check User Birthday
    if not 'birthday' in params or params['birthday'] == "":
        birthday = None
    else:
        birthday = params['birthday']

    # TODO: Check must-read notices & insert to unread_notices

    try:
        user_id = mdb.users.insert({'email':params['email'],
                      'password':hash_password(params['password']),
                      'username':username,
                      'birthday':birthday,
                      'key':{'activate':md5('ACTIVATION'+str(int(random.random()*10000))).hexdigest()},
                      'unread_notices':[]})
    except:
        return jsonify({'status':'error', 'description':'Database Error'}),500

    # TODO: Send Awaiting Email
    # TODO: Logging

    return jsonify({'status':'success',
                    'data':json.loads(json_util.dumps(mdb.users.find_one({'_id':user_id})))}), 201


##### /user - Specific User #########################################
@mod_api.route('/user/<id>', methods=['GET'])
def get_user(id):
    try:
        user = mdb.users.find_one({'_id':ObjectId(id)})
    except:
        return jsonify({'status':'error', 'description':'User ID is invalid'}), 400

    # TODO: Logging
    return jsonify({'status':'success','data':json.loads(json_util.dumps(user))})


@mod_api.route('/user/<id>', methods=['PUT'])
def put_user(id):
    if request.json:
        params = request.json
    elif request.form:
        params = {}
        for key in request.form:
            params[key] = request.form[key]
    else:
        return jsonify({'status': 'error', 'description': 'Request Parameter Missing!'}), 400

    data = {}
    for key in params:
        value = None if params[key] == "" else params[key]

        if key in ['id','email','fb_id','last_seen']:
            return jsonify({'status':'error', 'description': key + 'cannot be changed by user'}), 403

        if key == 'password':
            if len(value) < 6:
                return jsonify({'status':'error', 'description':'Password too short'}), 403
            data['password'] = hash_password(params['password'])

        # Birthday can only be None or 8-digit integer(between 1900/01/01 ~ currentYear's 12/31)
        if key == 'birthday' and value is not None:
            if len(value) != 8 or \
                int(value[0:4]) < 1900 or int(value[0:4]) > int(datetime.datetime.now().strftime("%Y")) or \
                int(value[4:6]) < 0 or int(value[4:6]) > 12 or int(value[6:8]) < 0 or int(value[6:8]) > 31:
                return jsonify({'status': 'error',
                                'description': "Invalid value for Birthday: " + value[0:4] + '/' + value[4:6] + '/' + value[6:8]}), 400
        else:
            data['birthday'] = params['birthday']

        # Username cannot be null
        if key == 'username' and value == None:
            return jsonify({'status':'error', 'description':'Username cannot be blank'}), 403
        else:
            data['username'] = params['username']


    if 'photo' in request.files:
        data['profile_img']['id'] = upload_photo(request.files['photo'])
        data['profile_img']['url'] = url_for('send_pic', img_id=data['profile_img']['id'], img_size='thumb_sm', _external=True)

    mdb.users.update({'_id':ObjectId(id)}, {'$set':data}, upsert=True)

    return jsonify({'status':'success', 'data':'data'}), 201

