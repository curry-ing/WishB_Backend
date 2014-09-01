from flask import render_template, redirect, flash, url_for, request, g, session, jsonify, abort, send_from_directory
from flask.ext.login import login_required, logout_user, login_user, current_user
from flask.ext.babel import gettext
from flask.ext.sqlalchemy import get_debug_queries
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.uploads import UploadSet, IMAGES, configure_uploads
from rauth.service import OAuth2Service

from app import app, db, babel, mdb
from forms import LoginForm, EditForm, PostForm, SearchForm, RegisterForm
from models import User, Post, Bucket, File, UserSocial
from emails import follower_notification
from translate import microsoft_translate
from logging import logging_auth, logging_downlaod, logging_update
from guess_language import guessLanguage

from config import POSTS_PER_PAGE, MAX_SEARCH_RESULTS, LANGUAGES, DATABASE_QUERY_TIMEOUT, FB_CLIENT_ID, FB_CLIENT_SECRET, WISHB_SERVER_URI, MONGODB_URI

from datetime import datetime

import os
import api
import httplib, urllib
import facebook
import statsd

now = datetime.utcnow()
auth = HTTPBasicAuth()

graph_url = 'https://graph.facebook.com/'
fb = OAuth2Service(name='facebook',
                         authorize_url='https://www.facebook.com/dialog/oauth',
                         access_token_url=graph_url+'oauth/access_token',
                         client_id=FB_CLIENT_ID,
                         client_secret=FB_CLIENT_SECRET,
                         base_url=graph_url);



c = statsd.StatsClient('localhost',8125)

@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(LANGUAGES.keys())


##### VIEW ##################################################
@app.route('/')
@app.route('/index')
def index():
    # return render_template('404.html'), 404
    # c.gauge('Access_Index', 1, delta = True)
    return render_template('index.html', title='index')
    # return redirect("http://www.wishb.net", 302)


@app.route('/login_new')
def login():
    return render_template('login.html', title='Login')


@app.route('/logout_new')
def logout():
    logout_user()
    g.user = None
    return render_template('index.html', title='Index', action='logout')


@app.route('/register')
def register():
    return render_template('register.html', title='Register')


@app.route('/mokcha/<id>')
def mokcha(id):
    bkt = Bucket.query.filter_by(id=id).first()
    user = User.query.filter_by(id=bkt.user_id).first()
    return render_template('mokcha.html',id=id, title=bkt.title, user=user)


@app.route('/wish/<id>')
def wish(id):
    bkt = Bucket.query.filter_by(id=id).first()
    user = User.query.filter_by(id=bkt.user_id).first()
    return render_template('mokcha.html',id=id, title=bkt.title, user=user)


@app.route('/inquiry')
def inquiry():
    return render_template('inquiry.html')

@app.route('/inquiry/write')
def inquiry_write():
    return render_template('inquiry_write.html')

@app.route('/notice')
def notice_list():
    return render_template('notice_list.html')

@app.route('/notice/write')
def notice():
    return render_template('notice_write.html')

##### SEARCHING #############################################
@app.route('/search', methods=['POST'])
@auth.login_required
def search():
    if not g.search_form.validate_on_submit():
        return redirect(url_for('index'))
    return redirect(url_for('search_results', query=g.search_form.search.data))


@app.route('/search_results/<query>')
@auth.login_required
def search_results(query):
    results = Post.query.whoosh_search(query, MAX_SEARCH_RESULTS).all()
    return render_template('search_results.html', query=query, results=results)


##### TRANSLATION #############################################
@app.route('/translate', methods=['POST'])
@auth.login_required
def translate():
    return jsonify({
        'text': microsoft_translate(
            request.form['text'],
            request.form['sourceLang'],
            request.form['destLang'])})


@app.before_request
def global_user():
    g.user = current_user
    if g.user.is_authenticated():
        g.user.last_seen = datetime.utcnow()
        db.session.add(g.user)
        db.session.commit()
        g.search_form = SearchForm()
    g.locale = get_locale()


@app.after_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= DATABASE_QUERY_TIMEOUT:
            app.logger.warning("SLOW QUERY: %s\nParameters: %s\nDuration: %fs\nContext: %s\n" % (
                query.statement, query.parameters, query.duration, query.context))
    return response


##### ERROR HANDLING ########################################
@app.errorhandler(404)
def internal_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


##### Authentication #######################################
@app.route('/api/token')
@auth.login_required
def get_auth_token():
    fb_token = None
    if g.user.profile_img_id == 0:
        if g.user.fb_id == 0:
            profile_img = None
        else:
            social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
            graph = facebook.GraphAPI(social_user.access_token)
            args = {'type':'normal'}
            profile_img = graph.get_object(g.user.fb_id+'/picture', **args)['url']
            fb_token = social_user.access_token
    else:
        profile_img = None if g.user.profile_img_id is None else url_for('send_pic', img_id=g.user.profile_img_id, img_type='thumb_sm', _external=True)
        if g.user.fb_id is not None and g.user.fb_id != 0:
            fb_token = UserSocial.query.filter_by(user_id=g.user.id).first().access_token

    # check user app version & logging
    latest_app = mdb.release.find_one(sort=[("version", -1)])
    latest_notice = mdb.notice.find_one(sort=[("_id", -1)])
    prev_app_version = "undefined" if g.user.app_version is None else g.user.app_version
    curr_app_version = None if 'app_version' not in request.args else request.args['app_version']
    if curr_app_version is not None and curr_app_version != prev_app_version:
        u = User.query.filter_by(id=g.user.id).first()
        u.app_version = curr_app_version
        db.session.commit()
        
        obj = {"user":{"id":g.user.id,
                       "username":g.user.username,
                       "email":g.user.email},
               "os":"android",
               "previous_ver":prev_app_version,
               "updated_ver":curr_app_version,
               "update_date":datetime.now()
               }
        logging_update(obj)

    # generating Token for user
    token = g.user.generate_auth_token()

    return jsonify({'status':'success',
                    'data':{'user':{'id': g.user.id,
                                    'username': g.user.username,
                                    'email': g.user.email,
                                    'birthday': g.user.birthday,
                                    'title_life':g.user.title_life,
                                    'title_10':g.user.title_10,
                                    'title_20':g.user.title_20,
                                    'title_30':g.user.title_30,
                                    'title_40':g.user.title_40,
                                    'title_50':g.user.title_50,
                                    'title_60':g.user.title_60,
                                    'profile_img_url': profile_img,
                                    'fb_id':None if g.user.fb_id is None else g.user.fb_id,
                                    'fb_token':fb_token,
                                    'is_admin':g.user.is_admin,
                                    'latest_app':{'version':latest_app['version'],
                                                  'url':latest_app['url']},
                                    'latest_notice':str(latest_notice['_id']),
                                    'confirmed_at':g.user.confirmed_at.strftime("%Y-%m-%d %H:%M:%S") if g.user.confirmed_at else None},
                            'token': token.decode('ascii')}})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    fb_token = None
    if g.user.profile_img_id == 0:
        if g.user.fb_id == 0:
            profile_img = None
        else:
            social_user = UserSocial.query.filter_by(user_id=g.user.id).first()
            graph = facebook.GraphAPI(social_user.access_token)
            args = {'type':'normal'}
            profile_img = graph.get_object(g.user.fb_id+'/picture', **args)['url']
            fb_token = social_user.access_token
    else:
        profile_img = None if g.user.profile_img_id is None else url_for('send_pic', img_id=g.user.profile_img_id, img_type='thumb_sm', _external=True)
        if g.user.fb_id is not None and g.user.fb_id != 0:
            fb_token = UserSocial.query.filter_by(user_id=g.user.id).first().access_token

    logging_auth(g.user.id, "login", "total")
    latest_app = mdb.release.find_one(sort=[("version", -1)])
    latest_notice = mdb.notice.find_one(sort=[("_id", -1)])
    if request.args['app_version'] != g.user.app_version:
        u = User.query.filter_by(id=g.user.id).first()
        u.app_version = request.args['app_version']
        db.session.commit()

    return jsonify({'status':'success',
                    'data':{'id': g.user.id,
                            'username': g.user.username,
                            'email': g.user.email,
                            'birthday': g.user.birthday,
                            'title_life':g.user.title_life,
                            'title_10':g.user.title_10,
                            'title_20':g.user.title_20,
                            'title_30':g.user.title_30,
                            'title_40':g.user.title_40,
                            'title_50':g.user.title_50,
                            'title_60':g.user.title_60,
                            'profile_img_url': profile_img,
                            'fb_id':None if g.user.fb_id is None else g.user.fb_id,
                            'fb_token':fb_token,
                            'is_admin':g.user.is_admin,
                            'latest_app':{'version':latest_app['version'],
                                          'url':latest_app['url']},
                            'latest_notice':str(latest_notice['_id']),
                            'confirmed_at': g.user.confirmed_at.strftime("%Y-%m-%d %H:%M:%S") if g.user.confirmed_at else None }})


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    if password == "facebook":
        auth = fb.get_session(token=username_or_token)
        resp = auth.get('/me')
        if resp.status_code == 200:
            fb_user = resp.json()
            # user = User.query.filter_by(email=fb_user.get('email')).first()
            birthday = fb_user['birthday'][6:10] + fb_user['birthday'][0:2] + fb_user['birthday'][3:5]
            user = User.get_or_create(fb_user['email'], fb_user['name'], fb_user['id'], birthday)
            conn = httplib.HTTPSConnection("graph.facebook.com")
            params = urllib.urlencode({'redirect_uri':WISHB_SERVER_URI,
                                       'client_id':FB_CLIENT_ID,
                                       'client_secret':FB_CLIENT_SECRET,
                                       'grant_type':'fb_exchange_token',
                                       'fb_exchange_token':username_or_token})
            conn.request("GET","/oauth/access_token?"+ params)
            response = conn.getresponse()
            resp_body = response.read()

            longLivedAccessToken=resp_body.split('&')[0].split('=')[1]

            UserSocial.upsert_user(user.id, 'facebook', fb_user['id'], longLivedAccessToken)
            c.gauge('Facebook_Login', 1, delta=True)

        else:
            return False
    else:
        user = User.verify_auth_token(username_or_token)

    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(email = username_or_token).first()
        if not user:
            return False
        if user.password == None:
            return False
        if not user.verify_password(password):
            return False
        c.gauge('Email_Login', 1, delta=True)
        logging_auth(user.id, "login", "email")

    g.user = user
    return True


@app.route('/api/login/facebook', methods=['GET'])
def login_fb():
    redirect_uri = url_for('authorized', _external=True)
    params = {'redirect_uri': redirect_uri, 'scope': 'email, user_birthday'}
    return redirect(fb.get_authorize_url(**params))


@app.route('/facebook/authorized')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        return jsonify({'status':'error',
                        'description':'Authentication failed'})

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)
    data = dict(code=request.args['code'], redirect_uri=redirect_uri)

    auth = fb.get_auth_session(data=data)

    # the "me" response
    me = auth.get('me').json()
    birthday = me['birthday'][6:10] + me['birthday'][0:2] + me['birthday'][3:5]
    u = User.get_or_create(me['email'], me['username'], me['id'], birthday)

    return jsonify({'user':{'id':u.id,
                            'username':u.username,
                            'email':u.email,
                            'birthday':u.birthday,
                            'title_life':u.title_life},
                            # 'confirmed_at':u.confirmed_at.strftime("%Y-%m-%d %H:%M:%S") if g.user.confirmed_at else None},
                    'access_token':auth.access_token})


@app.route('/activate_user/<key>')
def activate_user(key):
    # unsigned_user_id = decryption(user_id.replace('_','/'))
    u = User.query.filter_by(key=key).first()
    if not u:
        return jsonify({'status':'error',
                        'description':'key Error'}),401
    else:
        if u.confirmed_at == None or u.confirmed_at == "":
            try:
                u.confirmed_at = datetime.now()
                u.key = None
                db.session.commit()
            except:
                return jsonify({'status':'error',
                                'description':'Something went wrong'}),500

            return jsonify({'status':'success',
                            'description':'User Activated'}),200
        else:
            return jsonify({'status':'warning',
                            'description':'Already activated user'}),200


@app.route('/reset_passwd/<key>', methods=['GET'])
def reset_passwd(key):
    u = User.query.filter_by(key=key).first()
    if not u:
        return render_template('500.html'), 500

    return render_template('reset_passwd.html',title='RESET PASSWORD',key=key)


##### FILE UPLOADS ############################################
photos = UploadSet('photos',IMAGES)
configure_uploads(app, photos)

@app.route('/upload', methods=['GET','POST'])
@auth.login_required
def upload():
    if request.method == 'POST' and 'photo' in request.files:
        filename = photos.save(request.files['photo'])
        extension = filename.split('.')[1]
        f = File(filename=filename, user_id=g.user.id, extension=extension, type='photo')
        db.session.add(f)
        db.session.commit()
        # flash("Photo saved.")
        return redirect(url_for('show', id=f.id))

    return render_template('upload_file.html')


@app.route('/image/<img_id>.<img_type>')
def send_pic(img_id,img_type):
    img = File.query.filter_by(id = img_id).first()

    basedir = os.path.abspath('app/static/uploads/photos')
    filename = img.name

    if img_type == 'origin':
        path = basedir
    elif img_type == 'thumb_md':
        if (os.path.isfile(os.path.join(basedir, img_type, filename))):
            path = os.path.join(basedir, img_type)
        else :
            path = basedir
    elif img_type == 'thumb_sm':
        if (os.path.isfile(os.path.join(basedir, img_type, filename))):
            path = os.path.join(basedir, img_type)
        else :
            path = basedir
    else :
        abort(404)


    return send_from_directory(path, filename)

@app.route('/file/<filename>.<extension>')
def send_file(filename, extension):
    logging_downlaod(request.remote_addr)

    if filename == 'wishb_apk':
        if extension == 'latest':
            apk = mdb.release.find_one(sort=[("version", -1)])
        else:
            apk = mdb.release.find_one({"version":extension})
        return redirect(apk['url'], 302)
    else:
        basedir = os.path.abspath('app/static/uploads/files')
        file = filename + '.' + extension

    return send_from_directory(basedir, file)


# @app.route('/photo/<id>')
# def show(id):
#     f = File.query.filter_by(id = id).first()
#     if f is None:
#         abort(404)
#     url = photos.url(f.name)
#     return render_template('show.html', url=url, photo=f)


##### DO NOT USE ANYMORE ############################################
@app.route('/userprofile/<username>')
@app.route('/userprofile/<username>/<int:page>')
@auth.login_required
def userprofile(username, page=1):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(gettext('User %(username)s not found.', username=username))
        return redirect(url_for('index'))
    posts = user.posts.paginate(page, POSTS_PER_PAGE, False)
    return render_template('user.html', user=user, posts=posts)


@app.route('/edit', methods=['GET', 'POST'])
@auth.login_required
def edit():
    form = EditForm(g.user.username)
    if form.validate_on_submit():
        g.user.username = form.username.data
        g.user.about_me = form.about_me.data
        db.session.add(g.user)
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit'))
    else:
        form.username.data = g.user.username
        form.about_me.data = g.user.about_me
    return render_template('edit.html', form=form)


@app.route('/follow/<username>')
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User ' + username + ' not found.')
        return redirect(url_for('index'))
    if user == g.user:
        flash('You can\'t follow yourself!')
        return redirect(url_for('user', username=username))
    u = g.user.follow(user)
    if u is None:
        flash('Cannot follow ' + username + '.')
        return redirect(url_for('user', username=username))
    db.session.add(u)
    db.session.commit()
    flash('You are now following ' + username + '!')
    follower_notification(user, g.user)
    return redirect(url_for('userprofile', username=g.user.username))


@app.route('/unfollow/<username>')
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User ' + username + ' not found.')
        return redirect(url_for('index'))
    if g.user == user:
        flash('You can\'t unfollow yourself!')
        return redirect(url_for('user', username=username))
    u = g.user.unfollow(user)
    if u is None:
        flash('Cannot unfollow ' + username + '.')
        return redirect(url_for('user', username=username))
    db.session.add(u)
    db.session.commit()
    flash('You have stopped following ' + username + '.')
    return redirect(url_for('userprofile', username=g.user.username))



# @app.route('/index', methods=['GET', 'POST'])
# @app.route('/index/<int:page>', methods=['GET', 'POST'])
# @auth.login_required
# def index(page=1):
#     form = PostForm()
#     if form.validate_on_submit():
#         language = guessLanguage(form.post.data)
#         if language == 'UNKNOWN' or len(language) > 5:
#             language = ''
#         post = Post(body=form.post.data, timestamp=datetime.utcnow(), author=g.user, language=language)
#         db.session.add(post)
#         db.session.commit()
#         flash('Your post is now live!')
#         return redirect(url_for('index'))
#     posts = g.user.followed_posts().paginate(page, POSTS_PER_PAGE, False)
#     return render_template("index.html", title='Home', form=form, posts=posts)


# @app.route('/delete/<int:id>')
# @auth.login_required
# def delete(id):
#     post = Post.query.get(id)
#     if post is None:
#         flash('Post not found.')
#         return redirect(url_for('index'))
#     if post.author.id != g.user.id:
#         flash('You cannot delete this post.')
#         return redirect(url_for('index'))
#     db.session.delete(post)
#     db.session.commit()
#     flash('Your post has been deleted.')
#     return redirect(url_for('index'))


# @app.route('/register_old', methods=['GET', 'POST'])
# def register_old():
#     if g.user is not None and g.user.is_authenticated():
#         return redirect(url_for('index'))
#     form = RegisterForm()
#     if form.validate_on_submit():
#         u = User(email=form.email.data,
#                  username=form.username.data,
#                  password=generate_password_hash(form.password.data))
#         db.session.add(u)
#         db.session.commit()
#         return redirect(url_for('index'))
#     return render_template('register.html', title='Register', form=form)


# def login_old():
#     if g.user is not None and g.user.is_authenticated():
#         return redirect(url_for('index'))
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if not check_password_hash(user.password, form.password.data):
#             if user.login_fault < 5:
#                 user.login_fault += 1
#                 db.session.commit()
#                 print user.login_fault
#                 return redirect(url_for('login'))
#             else:
#                 print "ID " + user.email + " Blocked!!"
#                 return redirect(url_for('login'))
#                 #         if login_error_cnt > 5:
#                 #             print login_error_cnt
#                 #             user.is_blocked = 1
#                 #             return redirect(url_for('index'))
#         else:
#             session_user = db.session.query(User).filter_by(email=form.email.data).first()
#             login_user(session_user)
#             user.login_fault = 0
#             db.session.commit()
#             flash('You were logged in')
#             return redirect(url_for('index'))
#     return render_template('login_old.html', title='Login', form=form)

