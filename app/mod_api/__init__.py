__author__ = 'masunghoon'
from config import MONGODB_URI
from flask import Blueprint

mod_api = Blueprint('apiv2', __name__, url_prefix='/apiv2')


