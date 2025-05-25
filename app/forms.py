from flask_wtf import FlaskForm
from wtforms import (StringField, SubmitField, PasswordField, FileField, 
                    TextAreaField, BooleanField, EmailField, SelectField)
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_ckeditor import CKEditorField

# Predefined choices for categories
CATEGORIES = [
    ('politics', 'Politics'),
    ('economics', 'Economics'),
    ('technology', 'Technology'),
    ('global', 'Global Affairs')
]

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], 
                          render_kw={"placeholder": "Enter unique username"})
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    password1 = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Create Account')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class PostForm(FlaskForm):
    title = StringField('Post Title', validators=[
        DataRequired(),
        Length(max=120, message="Title cannot exceed 120 characters")
    ])
    category = SelectField('Category', choices=CATEGORIES, 
                          validators=[DataRequired()])
    desc = CKEditorField('Content', validators=[DataRequired()])
    image = FileField('Featured Image', render_kw={
        "accept": "image/*",
        "help": "Upload JPEG, PNG or GIF (max 5MB)"
    })
    submit = SubmitField('Publish Post')

class AdminActionForm(FlaskForm):
    warning_message = TextAreaField("Administrative Message", 
                                  validators=[Length(max=500)])
    is_banned = BooleanField("Ban this account")
    submit = SubmitField("Apply Action")

class CommentForm(FlaskForm):
    comment = TextAreaField('Share your thoughts', validators=[
        DataRequired(),
        Length(max=1000, message="Comment cannot exceed 1000 characters")
    ])
    submit = SubmitField('Post Comment')

class ContactForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[
        DataRequired(),
        Length(max=2000, message="Message cannot exceed 2000 characters")
    ])
    submit = SubmitField('Send Message')

class ResetPasswordRequestForm(FlaskForm):
    email = EmailField('Registered Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Minimum 8 characters required")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Update Password')

class AnnouncementForm(FlaskForm):
    title = StringField('Announcement Title', validators=[
        DataRequired(),
        Length(max=100, message="Title cannot exceed 100 characters")
    ])
    content = TextAreaField('Announcement Content', validators=[
        DataRequired(),
        Length(max=500, message="Content cannot exceed 500 characters")
    ])
    submit = SubmitField('Publish Announcement')

class SubscribeForm(FlaskForm):
    email = EmailField('Email Address', validators=[
        DataRequired(), 
        Email(message="Enter valid email address")
    ])
    submit = SubmitField('Subscribe')

class VideoForm(FlaskForm):
    title = StringField("Video Title", validators=[
        DataRequired(),
        Length(max=100, message="Title cannot exceed 100 characters")
    ])
    description = TextAreaField("Video Description", validators=[
        DataRequired(),
        Length(max=500, message="Description cannot exceed 500 characters")
    ])
    video = FileField("Video File", validators=[DataRequired()], render_kw={
        "accept": "video/mp4,video/webm",
        "help": "MP4 or WebM format (max 50MB)"
    })
    submit = SubmitField("Upload Video")
