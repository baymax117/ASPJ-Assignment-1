from flask_wtf import FlaskForm
#from wtforms import Form, StringField, validators, RadioField, TextAreaField, SelectField
#from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, length
#from Database import User



class CreateUserForm(FlaskForm):
    userName = StringField('Username', validators=[DataRequired(), length(min=1, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email(), length(min=1, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), length(min=8, max=150)])
    confirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Password does not match")])
    submit = SubmitField('Sign up!')

    def validate_username(self, userName):
        user = User.query.filter_by(username=userName.data).first()
        if user is not None:
            raise ValidationError('Username taken!')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Use a different Email address')


# class CreateUserForm(FlaskForm):
#     userName = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])
#     email = StringField('Email', [validators.Length(min=1, max=150), validators.DataRequired()])
#     password = StringField('Password', [validators.Length(min=8, max=150), validators.DataRequired()])
#     confirmPassword = StringField('Confirm Password', [validators.Length(min=8, max=150), validators.DataRequired()])

# class UserLogin(Form):
#     userName = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])
#     password = StringField('Password', [validators.Length(min=8, max=150), validators.DataRequired()])