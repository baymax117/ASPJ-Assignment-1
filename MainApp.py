from flask import Flask, render_template , redirect, flash, url_for, request, g, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField
from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, Length ,NumberRange
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager , logout_user, current_user, login_user, UserMixin
from uuid import uuid4
# from Database import User
# from signupForm import CreateUserForm
from sqlalchemy import Column, Integer, String, Float, Boolean
from werkzeug.security import generate_password_hash , check_password_hash
import os


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'shop.db')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
# SECRET_KEY = os.environ.get('SECRET_KEY') or "asp-project-security"
app.config['SECRET_KEY'] = "asp-project-security"

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model):
    __tablename__ = 'users'

    user_id = Column(Integer, primary_key=True)
    username = Column(String(64))
    email = Column(String(120), index=True, unique=True)
    password = Column(String(128))

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def get_id(self):
        return self.user_id

    def is_anonymous(self):
        return False


class Payment(db.Model):
    __tablename__ = 'cards'
    name = Column(String(150))
    email = Column(String(120), unique=True)
    address = Column(String(150))
    country = Column(String(56))
    city = Column(String(150))
    zip = Column(Integer)
    cardname = Column(String(150))
    cardnum = Column(Integer, primary_key=True)
    expmonth = Column(String(9))
    expyear = Column(Integer)
    cvv = Column(Integer)



@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class UserLoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=70)])
    remember_me = BooleanField('Remember Me')
    #submit = SubmitField('Sign In')



class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid Email"), Length(max=60)])
    password = PasswordField('Password', validators=[InputRequired()])
    # confirmPassword = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    # submit = SubmitField('Sign up!')


class PaymentForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=1, max=150)])
    email = StringField('Email', validators=[InputRequired(),Length(min=1, max=150)])
    address = StringField('Address', validators=[InputRequired(),Length(min=1, max=150)])
    country = StringField('Country', validators=[InputRequired(),Length(min=1, max=150)])
    city = StringField('City', validators=[InputRequired(),Length(min=1, max=150)])
    zip = IntegerField('Zip', validators=[InputRequired(), NumberRange(min=100000, max=999999)])
    cardName = StringField('Name on card', validators=[InputRequired(),Length(min=1, max=150)])
    cardNum = IntegerField('Credit card number', validators=[InputRequired()])
    expmonth = SelectField('Exp month', validators=[InputRequired()], choices=[('January', 'January'), ('February', 'February'), ('March', 'March'), ('April', 'April'), ('May', 'May'), ('June', 'June'), ('July', 'July'), ('August', 'August'), ('September', 'September'), ('October', 'October'), ('November', 'November'), ('December', 'December')])
    expyear = IntegerField('Exp year', validators=[InputRequired(),NumberRange(min=2020, max=3000)])
    cvv = IntegerField('CVV', validators=[InputRequired(),NumberRange(min=0, max=999)])
    #rmb = BooleanField('')





#Add  @login_required to protect against anonymous users to view a function,
#Put below @app.route, will prevent them from accessing this function



@app.route('/')

@app.route('/home', methods=['GET', 'POST'])
def home():
    # if request.method == 'POST':
    #     session.pop('user', None)
    #
    #     if request.form['password'] == 'password':
    #         session['user'] = request.form['username']
    #         return redirect(url_for('protected_testing'))
    return render_template('home.html')

@app.route('/protected_testing')
def protected():
    print("Hello 1")
    if g.user:
        print("Hello good")
        return render_template('protected_testing.html', user=session['user'])
    print("Hello 111111111111")
    return redirect(url_for('home'))



@app.before_request
def before_request():
    g.user = None

    if 'user' in session:
        g.user = session['user']


@app.route('/dropsession')
def dropsession():
    session.pop('user', None)
    return redirect(url_for("home"))
    #return render_template('home.html')

#-----------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    if request.method == 'POST':
        session.pop('user', None)


    form = UserLoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # if user is None or not user.check_password(form.password.data):
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember_me.data)
                db.session.add(user)
                db.session.commit()
                session['user'] = request.form['username']
                print("Login sucessful")

                return redirect(url_for('protected'))
        flash("Invalid username or password, please try again!")
        return redirect(url_for('protected'))

    return render_template('login.html', form=form, title="Login in")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = CreateUserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        newuser = User(username=form.username.data, email=form.email.data, password=hashed_password)
        # newuser.set_password(form.password.data)
        db.session.add(newuser)
        db.session.commit()
        flash("You have successfully signed up!")
        return redirect(url_for('login'))
    return render_template('sign up.html', title="Sign Up", form=form)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    form = PaymentForm()
    return render_template('payment.html', title='Payment', form=form)


def db_create():
    db.create_all()
    print('Database created.')


def db_drop():
    db.drop_all()
    print('Database dropped.')


def db_seed():
    john = User(user_id=1,
                username='JohnDoe',
                email='johnD@email.com',
                password='abcd1234')

    mary = User(user_id=2,
                username='MaryJane',
                email='maryJ@email.com',
                password='abcd1234')

    peter = User(user_id=3,
                 username='Spidey',
                 email='pparker@email.com',
                 password='abcd1234')

    db.session.add(john)
    db.session.add(mary)
    db.session.add(peter)
    db.session.commit()
    print('database seeded')


# run db_create to initialize the database
# db_create()

# run db_seed to create sample data in the database
# db_seed()


# run db_drop to reset the database
# db_drop()


# @app.cli.command('db_create')
# def database_create():
#     db_create()
#
# @app.cli.command('db_drop')
# def database_drop():
#     db_drop()
#
# @app.cli.command('db_seed')
# def database_seed():
#     db_seed()


# database_create()



if __name__ == "__main__":
    app.run()
