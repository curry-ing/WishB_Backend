import sys

from sqlalchemy import create_engine

from flask import Flask, g
from flask.ext import login
from flask.ext.mail import Mail
from flask.ext.babel import Babel
from flask.ext.restful import Api
from flask.ext.security import Security, SQLAlchemyUserDatastore

from sqlalchemy.ext.declarative import declarative_base

from werkzeug.contrib.fixers import ProxyFix

sys.path.append('../..')

app = Flask(__name__)
app.config.from_object('config')

app.wsgi_app = ProxyFix(app.wsgi_app)

from config import ADMINS, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, LANGUAGES, SECRET_KEY, MONGODB_URI
from app.models import db, Role, User
from app.momentjs import momentjs

# RESTful API
api = Api(app)

# DB
db.metadata.bind = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], convert_unicode=True)
Base = declarative_base()

# Login Manager
lm = login.LoginManager()
lm.login_message = ''
lm.init_app(app)
lm.login_view = 'login'

# Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# moment.js
app.jinja_env.globals['momentjs'] = momentjs

# Mailing
mail = Mail(app)

# I18n and L10n
babel = Babel(app)

# Debugging
if not app.debug:
    import logging
    from logging.handlers import SMTPHandler
    credentials = None
    if MAIL_USERNAME or MAIL_PASSWORD:
        credentials = (MAIL_USERNAME, MAIL_PASSWORD)
    mail_handler = SMTPHandler((MAIL_SERVER, MAIL_PORT), 'no-reply@' + MAIL_SERVER, ADMINS, 'dream failure', credentials)
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)

    from logging.handlers import RotatingFileHandler
    file_handler = RotatingFileHandler('tmp/dream.log', 'a', 1 * 1024 * 1024, 10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('dream startup')


from app import models
from app import views
from app.forms import SearchForm

@lm.user_loader
def load_user(userid):
    try:
        return models.User.query.get(int(userid))
    except (TypeError, ValueError):
        pass


@app.teardown_appcontext
def commit_on_success(error=None):
    if error is None:
        db.session.commit()


@app.teardown_request
def shutdown_session(exception=None):
    db.session.remove()


@app.context_processor
def inject_user():
    try:
        return {'user': g.user}
    except AttributeError:
        return {'user': None}


# app.context_processor(backends)

# @security.context_processor
# def security_context_processor():
#     return dict(hello="world")
