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
    email = StringField('Email', validators=[InputRequired(), Length(min=9, max=150), Email(message='Please enter valid email')])
    address = StringField('Address', validators=[InputRequired(), Length(min= 1,max=150)])
    country = StringField('Country', validators=[InputRequired(), Length(min=1, max=150)])
    city = StringField('City', validators=[InputRequired(), Length(min=1, max=150)])
    zip = IntegerField('Zip', validators=[InputRequired(), NumberRange(min=100000, max=999999)])
    cardName = StringField('Name on card', validators=[InputRequired(), Length(min=1, max=150)])
    cardNum = IntegerField('Credit card number', validators=[InputRequired(), NumberRange(max=9999)])
    expmonth = SelectField(label='Card Expiry', validators=[InputRequired()],
                           choices=[('January', '01'), ('February', '02'), ('March', '03'),
                                    ('April', '04'), ('May', '05'), ('June', '06'), ('July', '07'),
                                    ('August', '08'), ('September', '09'), ('October', '10'),
                                    ('November', '11'), ('December', '12')])
    expyear = SelectField(validators=[InputRequired()], choices=[('2025', '25'), ('2016', '24'), ('2023', '23'),
                                                               ('2022', '22'), ('2021', '21'), ('2020', '20')])
    cvv = IntegerField('CVV', validators=[InputRequired(), NumberRange(max=999)])
    # rmb = BooleanField('')