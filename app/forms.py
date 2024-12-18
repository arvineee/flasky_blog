from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField, PasswordField,FileField,TextAreaField,BooleanField,EmailField
from wtforms.validators import DataRequired,Email,EqualTo,Length
from flask_ckeditor import CKEditorField

class RegisterForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired()])
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired(),Length(min=6)])
    password1 = PasswordField('Confirm Password',validators=[EqualTo('password')])
    submit =SubmitField('Submit')


class LoginForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit =SubmitField('Submit')



class PostForm(FlaskForm):
    title = StringField('Title',validators=[DataRequired()])
    desc = CKEditorField('Content form') 
    image = FileField('Content Image')
    submit =SubmitField('Submit')

class AdminActionForm(FlaskForm):
    warning_message = TextAreaField("Warning Message", validators=[Length(max=500)])
    is_banned = BooleanField("Ban User")
    submit = SubmitField("Submit Action")

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
