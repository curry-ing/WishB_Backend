__author__ = 'masunghoon'

import json
import datetime

from bson import json_util, ObjectId
from flask import g, jsonify, request

from app import mdb
from app.mod_api import mod_api
from app.utils import upload_photo

def nf_add_bucket(bucket_id):
    bucket = mdb.buckets.find_one({'_id':ObjectId(bucket_id)})