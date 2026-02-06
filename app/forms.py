from flask_wtf import FlaskForm
from wtforms import (StringField, SubmitField, PasswordField, FileField, 
                    TextAreaField, BooleanField, EmailField, SelectField, FloatField)
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
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    desc = CKEditorField('Content', validators=[DataRequired()])
    image = FileField('Featured Image', render_kw={"accept": "image/*"})
    video = FileField('Video (Optional)', render_kw={"accept": "video/mp4,video/webm"})  # NEW: Video upload field
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
    title = StringField(
        'Title',
        validators=[DataRequired(), Length(max=100, message="Title cannot exceed 100 characters")]
    )
    message = TextAreaField(
        'Message',
        validators=[DataRequired(), Length(max=500, message="Message cannot exceed 500 characters")]
    )
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

class AdsTxtForm(FlaskForm):
    content = TextAreaField('Ads.txt Content', validators=[DataRequired()])
    submit = SubmitField('Update Ads.txt')

class NewsletterForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Newsletter')

class CategoryForm(FlaskForm):
    name = StringField(
        'Category Name', 
        validators=[
            DataRequired(), 
            Length(max=100, message="Category name cannot exceed 100 characters")
        ]
    )
    parent_id = SelectField(
        'Parent Category', 
        coerce=int, 
        choices=[], 
        validate_choice=False
    )
    submit = SubmitField('Submit')
    
    def __init__(self, *args, **kwargs):
        from app.models import Category
        super(CategoryForm, self).__init__(*args, **kwargs)
        self.parent_id.choices = [(0, 'None')] + [
            (c.id, c.name) for c in Category.query.filter_by(parent_id=None).all()
        ]

class AdForm(FlaskForm):
    title = StringField('Ad Title', validators=[
        DataRequired(),
        Length(max=100, message="Title cannot exceed 100 characters")
    ])
    content = TextAreaField('Ad Content/Code', validators=[
        DataRequired(),
        Length(max=2000, message="Content cannot exceed 2000 characters")
    ])
    advertiser_name = StringField('Advertiser Name', validators=[
        DataRequired(),
        Length(max=100)
    ])
    advertiser_email = EmailField('Advertiser Email', validators=[
        DataRequired(),
        Email()
    ])
    advertiser_website = StringField('Website URL', validators=[
        Optional(),
        Length(max=200)
    ])
    placement = SelectField('Ad Placement', choices=[
        ('sidebar', 'Sidebar'),
        ('header', 'Header/Banner'),
        ('inline', 'Inline Content'),
        ('footer', 'Footer')
    ], default='sidebar')
    price = FloatField('Price ($)', validators=[Optional()])
    start_date = StringField('Start Date (YYYY-MM-DD)', validators=[Optional()])
    end_date = StringField('End Date (YYYY-MM-DD)', validators=[Optional()])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Ad')

class CaptchaForm(FlaskForm):
    submit = SubmitField()


