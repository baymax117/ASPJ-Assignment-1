from flask import Flask, render_template, redirect, flash, url_for, request, g, session
from Forms import UserLoginForm, CreateUserForm, PaymentForm
from flask_login import LoginManager, logout_user, current_user, login_user, UserMixin
from functools import wraps
from sqlalchemy.sql import text
from uuid import uuid4
from Database import *
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'shop.db')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
# SECRET_KEY = os.environ.get('SECRET_KEY') or "asp-project-security"
app.config['SECRET_KEY'] = "asp-project-security"

db.app = app
db.init_app(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

def login_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if current_user.is_authenticated == False:
              print("YO MAN")
              # return login_manager.unauthorized()
              return "Forbidden access", 402
            print("Next option")
            if (current_user.urole != role):
                print("YO MAN 2")
                # return login_manager.unauthorized()
                return "Forbidden access", 402
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# Add  @login_required and state the specific role 'admin' to protect against anonymous users to view a function,
# Put below @app.route, will prevent them from accessing this function


@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    # if request.method == 'POST':
    #     session.pop('user', None)
    #
    #     if request.form['password'] == 'password':
    #         session['user'] = request.form['username']
    #         return redirect(url_for('protected_testing'))
    statement = text('SELECT * FROM products')
    results = db.engine.execute(statement)
    products = []
    # products -> 0: name | 1: price | 2: image
    for row in results:
        products.append([row[1], row[3], row[6]])
    length = len(products)
    return render_template('home.html', products=products, length=length)




@app.route('/protected_testing')
def protected():
    print("Inside Protected")
    if g.user:
        print("Login good")
        return render_template('protected_testing.html', user=session['user'])
    print("Login Bad")
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
    # return render_template('home.html')


# -----------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    # if request.method == 'POST':
    #     session.pop('user', None)

    form = UserLoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # if user is None or not user.check_password(form.password.data):
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember_me.data)
                user.activate_is_authenticated()
                print(user.is_authenticated)
                print("hey",current_user.is_authenticated)
                db.session.add(user)
                db.session.commit()
                session['user'] = request.form['username']
                print("Login sucessful")

                return redirect(url_for('protected'))
        flash("Invalid username or password, please try again!")
        return redirect(url_for('login'))

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
        exists = db.session.query(User.id).filter_by(email=form.email.data).scalar()
        exists2 = db.session.query(User.id).filter_by(username=form.username.data).scalar()
        if exists is None and exists2 is None:
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            newuser = User(username=form.username.data, email=form.email.data, password=hashed_password, urole='admin', is_active=True, is_authenticated=False)
            # Role.create('customer')

            # newuser.roles.append(Role(name='customer', id=2))
            # newuser.set_password(form.password.data)
            db.session.add(newuser)
            db.session.commit()
            flash("You have successfully signed up!")
            return redirect(url_for('login'))

        flash("Email exists!!")
        return redirect(url_for('signup'))
    return render_template('sign up.html', title="Sign Up", form=form)


@app.route('/payment', methods=['GET', 'POST'])
def payment():
    form = PaymentForm()
    return render_template('payment.html', title='Payment', form=form)


@app.route('/admin_test', methods=['GET', 'POST'])
@login_required('admin')
def admin_test():
    return render_template('admin_page.html'), 200


# run db_create to initialize the database
# db_create(db)

# run db_seed to create sample data in the database
# db_seed(db)

# run db_drop to reset the database
# db_drop(db)

# update the js file
# update_js()




# database_create()


if __name__ == "__main__":
    app.run(debug=True)
