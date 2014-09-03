import json
import datetime

from bson import json_util, ObjectId
from flask import g, jsonify, request

from app import mdb
from app.mod_api import mod_api
from app.utils import upload_photo

from app.mod_api.newsfeed import nf_add_bucket

from app.social import fb_add_bucket

### Single Bucket #######
@mod_api.route('/buckets', methods=['GET'])
def get_bucketlist():
    data = []
    buckets = mdb.buckets.find()

    for bucket in buckets:
        data.appends(json.loads(json_util.dumps(bucket)))

    return jsonify({'status':'success', 'data':data})


@mod_api.route('/buckets', methods=['POST'])
def add_bucket():
    if request.json:
        params = request.json
    elif request.form:
        params = request.form
    else:
        return jsonify({'status': 'error', 'description': 'Request Parameter Missing!'}), 403

    # Replace blank value to None(null) in params
    data = {}
    for key in params:
        if key in ['_id', 'user_id', 'reg_dt', 'language']:
            return jsonify({'status':'error', 'description':key+' cannot be entered manually.'}), 403

        data[key] = None if params[key] == "" else params[key]

    # Bucket Title & Deadline required
    if not 'title' in params or params['title'] == None:
        return jsonify({'status':'error', 'description':'Bucket title required'}), 403

    if not 'deadline' in params or params['deadline'] == None:
        return jsonify({'status':'error', 'description':'Bucket deadline required'}), 403

    if 'rpt_type' in params and params['rpt_type'] not in ['WKRP', 'WEEK', 'MNTH']:
        return jsonify({'status':'error', 'description':'Invalid repeat-type value'}), 403

    if 'photo' in request.files:
        data['bkt_img_id'] = upload_photo(request.files['photo'])

    data['user'] = {'id': g.user.id,
                    'name': g.user.username,
                    'email': g.user.email,
                    'user_img_id': g.user.profile_img_id}

    bucket_id = mdb.buckets.insert(data)

    # After uploads successfully
    if 'rpt_cndt' in params:
        dayOfWeek = datetime.date.today().weekday()
        if params['rpt_type'] == 'WKRP' and params['rpt_cndt'][dayOfWeek] == '1':
            today = {'date':datetime.date.today().strftime('%Y%m%d'),
                     'user':{'id':g.user.id,
                             'name':g.user.username,
                             'email':g.user.email},
                     'bucket':{'id':bucket_id,
                               'title':data['title'],
                               'deadline':data['deadline']},
                     'status':0,
                     'lst_mod_dt':datetime.datetime.now()}
            mdb.todays.insert(today)

    if 'fb_share' in params and params['fb_share'] in [True, 'true']:
        fb_add_bucket(bucket_id)

    if params['private'] != 1:
        nf_add_bucket(bucket_id)

    return jsonify({'status':'success', 'data':data})

