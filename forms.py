from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64, message="Username must be between 3 and 64 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(message="Invalid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Register')
    
    def validate_password(self, password):
        # Check if password has at least one number and one letter
        if not re.search(r'[A-Za-z]', password.data) or not re.search(r'[0-9]', password.data):
            raise ValidationError("Password must contain at least one letter and one number")

class CaptureSettingsForm(FlaskForm):
    interface = SelectField('Network Interface', validators=[DataRequired()])
    filter = StringField('Capture Filter (BPF syntax)')
    packet_limit = StringField('Packet Limit (leave empty for unlimited)')
    submit = SubmitField('Start Capture')
