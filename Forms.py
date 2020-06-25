from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField
from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, Length, NumberRange


class UserLoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=70)])
    remember_me = BooleanField('Remember Me')
    # submit = SubmitField('Sign In')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(max=60)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=150)])
    confirmPassword = PasswordField('Confirm Password',
                                    validators=[InputRequired(), EqualTo('password', message="Password does not match")])
    # confirmPassword = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    # submit = SubmitField('Sign up!')


class PaymentForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=1, max=150)])
    email = StringField('Email', validators=[InputRequired(), Length(min=1, max=150)])
    address = StringField('Address', validators=[InputRequired(), Length(min=1, max=150)])
    country = StringField('Country', validators=[InputRequired(), Length(min=1, max=150)])
    city = StringField('City', validators=[InputRequired(), Length(min=1, max=150)])
    zip = IntegerField('Zip', validators=[InputRequired(), NumberRange(min=100000, max=999999)])
    cardName = StringField('Name on card', validators=[InputRequired(), Length(min=1, max=150)])
    cardNum = IntegerField('Credit card number', validators=[InputRequired()])
    expmonth = SelectField('Exp month', validators=[InputRequired()],
                           choices=[('January', 'January'), ('February', 'February'), ('March', 'March'),
                                    ('April', 'April'), ('May', 'May'), ('June', 'June'), ('July', 'July'),
                                    ('August', 'August'), ('September', 'September'), ('October', 'October'),
                                    ('November', 'November'), ('December', 'December')])
    expyear = IntegerField('Exp year', validators=[InputRequired(), NumberRange(min=2020, max=3000)])
    cvv = IntegerField('CVV', validators=[InputRequired(), NumberRange(min=0, max=999)])
    # rmb = BooleanField('')