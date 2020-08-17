from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField
from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, Length, NumberRange


def validate_name(form, field):
    for char in field.data:
        if not char.isdigit() and not char.isalpha() and not char == '_':
            raise ValidationError("The username can only contain Alphanumeric and underscore(_).")


class UserLoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=50), validate_name])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=50)])
    remember_me = BooleanField('Remember Me')
    # submit = SubmitField('Sign In')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=50), validate_name])
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(max=60)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=50)])
    confirmPassword = PasswordField('Confirm Password',
                                    validators=[InputRequired(), EqualTo('password', message="Password does not match")])

    security_questions = SelectField(label="Security question (in case you forgot your password)", validators=[InputRequired()],
                                     choices=[('Mother\'s middle name', 'Mother\'s middle name'),
                                              ('Your\'s pet name', 'Your\'s pet name'),
                                              ('Your favourite food','Your favourite food')])
    security_questions_answer = StringField('Your secret answer', validators=[InputRequired()])

    # confirmPassword = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    # submit = SubmitField('Sign up!')


class ForgetPasswordForm_Email(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(max=60)])


class ForgetPasswordForm_Security(FlaskForm):
    security_questions = SelectField(label="Security question", validators=[InputRequired()],
                                     choices=[('Mother\'s middle name', 'Mother\'s middle name'),
                                              ('Your\'s pet name', 'Your\'s pet name'),
                                              ('Your favourite food','Your favourite food')])

    security_questions_answer = StringField('Answer', validators=[InputRequired()])


class ForgetPasswordForm(FlaskForm):
    #security_questions = StringField(label="Security question")
    security_questions = SelectField(label="Security question (if you want to reset, select new questions)",
                                     validators=[InputRequired()],
                                     choices=[('Mother\'s middle name', 'Mother\'s middle name'),
                                              ('Your\'s pet name', 'Your\'s pet name'),
                                              ('Your favourite food', 'Your favourite food')])

    security_questions_answer = StringField('Your secret answer (if you want to reset, input new answer, if not key in original answer)', validators=[InputRequired()])

    newpassword = PasswordField('new password', validators=[InputRequired(), Length(min=8, max=150)])
    newconfirmPassword = PasswordField('Confirm Password',
                                    validators=[InputRequired(), EqualTo('newpassword', message="Password does not match")])


class PaymentForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=1, max=150)])
    email = StringField('Email', validators=[InputRequired(), Length(min=9, max=150), Email(message='Please enter valid email')])
    address = StringField('Address', validators=[InputRequired(), Length(min= 1,max=150)])
    country = StringField('Country', validators=[InputRequired(), Length(min=1, max=150)])
    city = StringField('City', validators=[InputRequired(), Length(min=1, max=150)])
    zip = IntegerField('Zip', validators=[InputRequired(), NumberRange(min=100000, max=999999)])
    cardName = StringField('Name on card', validators=[InputRequired(), Length(min=1, max=150)])
    cardNum = IntegerField('Credit card number', validators=[InputRequired(), NumberRange(min=3000000000000000, max=6999999999999999)])
    expmonth = SelectField(label='Card Expiry', validators=[InputRequired()],
                           choices=[('January', '01'), ('February', '02'), ('March', '03'),
                                    ('April', '04'), ('May', '05'), ('June', '06'), ('July', '07'),
                                    ('August', '08'), ('September', '09'), ('October', '10'),
                                    ('November', '11'), ('December', '12')])
    expyear = SelectField(validators=[InputRequired()], choices=[('2025', '25'), ('2016', '24'), ('2023', '23'),
                                                               ('2022', '22'), ('2021', '21'), ('2020', '20')])
    cvv = IntegerField('CVV', validators=[InputRequired(), NumberRange(max=999)])
    # rmb = BooleanField('')
