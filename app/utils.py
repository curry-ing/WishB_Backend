__author__ = 'masunghoon'
import re
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