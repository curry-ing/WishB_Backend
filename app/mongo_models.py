__author__ = 'masunghoon'

from app import mdb

class User():
    def email_exists(email):
        return mdb.user.find({'email':email}).count() > 0