from flask import render_template, url_for
from flask.ext.mail import Message
from app import app, mail
from decorators import async
from config import ADMINS

@async    
def send_async_email(msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender = sender, recipients = recipients)
    msg.body = text_body
    msg.html = html_body
    send_async_email(msg)

    
def follower_notification(followed, follower):
    send_email("[Dream Proj.] %s is now following you!" % follower.username,
        ADMINS[0],
        [followed.email],
        render_template("follower_email.txt",  user = followed, follower = follower),
        render_template("follower_email.html",  user = followed, follower = follower))


def send_awaiting_confirm_mail(user):
    # Send the awaiting for confirmation mail to the user.
    subject = "We're waiting for your confirmation!!"
    msg = Message(subject=subject, sender=ADMINS[0], recipients=[user.email])
    confirmation_url = url_for('activate_user', key=user.key, _external=True)
    msg.body = "Dear %s, click here to confirm: %s" % (user.username, confirmation_url)
    send_async_email(msg)


def send_reset_password_mail(user):
    subject = "Reset Password!!"
    msg = Message(subject=subject, sender=ADMINS[0], recipients=[user.email])
    url = url_for('reset_passwd', key=user.key, _external=True)
    msg.body = 'Dear %s, Reset your password via: %s' % (user.username, url)
    send_async_email(msg)