from flask.ext.wtf import Form, TextField, BooleanField, TextAreaField, PasswordField
from flask.ext.wtf import Required, Length
from models import User

class LoginForm(Form):
    email = TextField('email', validators = [Required()])
    password = PasswordField('password', validators = [Required()])
    
    def validate(self):
        if not Form.validate(self):
            return False
        if '@' not in self.email.data:
            self.email.errors.append('Invalid E-mail address')
            return False
        user = User.query.filter_by(email = self.email.data).first()
        if user == None:
            self.email.errors.append('Unregistered Email')
            return False
        return True
    
#     def get_user(self):
#         return db.session.query(User).filter_by(email=self.email.data).first()


class OidLoginForm(Form):
    openid = TextField('openid', validators = [Required()])
    remember_me = BooleanField('remember_me', default = False)

    
class RegisterForm(Form):
    email = TextField('email', validators = [Required()])
    username = TextField('username', validators = [Length(min=0, max=64)])
    password = PasswordField('password', validators = [Required()])
    validate_pwd = PasswordField('validate_pwd', validators = [Required()])
    
    def validate(self):
        if not Form.validate(self):
            return False
        user = User.query.filter_by(email = self.email.data).first()
        if user != None:
            self.email.errors.append('This email is aleady in user.')
            return False
        if '@' not in self.email.data:
            self.email.errors.append('Invalid E-mail address')
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user != None:
            self.username.errors.append('This username is aleady in use.')
            return False
        if self.password.data != self.validate_pwd.data:
            self.validate_pwd.errors.append('Password does not match.')
            return False
        return True
    
class EditForm(Form):
    username = TextField('username', validators = [Required()])
    about_me = TextAreaField('about_me', validators = [Length(min = 0, max = 140)])

    def __init__(self, original_username, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.original_username = original_username
        
    def validate(self):
        if not Form.validate(self):
            return False
        if self.username.data == self.original_username:
            return True
        if self.username.data != User.make_valid_username(self.username.data):
            self.username.errorsappend('This username has invalid characters. Please use letters, numbers, dots and undersocres only.')
            return False
        user = User.query.filter_by(username = self.username.data).first()
        if user != None:
            self.username.errors.append('This username is aleady in use. Please choose another one.')
            return False
        return True
        
class PostForm(Form):
    post = TextField('post', validators=[Required()])

class SearchForm(Form):
    search = TextField('search', validators = [Required()])
