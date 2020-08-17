from flask import Flask, render_template, redirect, flash, url_for, request, g, session, jsonify
from Forms import UserLoginForm, CreateUserForm, ForgetPasswordForm_Email, ForgetPasswordForm, \
    ForgetPasswordForm_Security, PaymentForm
from flask_login import LoginManager, logout_user, current_user, login_user
from Database import db, User, UserSchema, Product, Payment, Cart, db_create, db_drop, db_seed, update_js
from flask_jwt_extended import JWTManager
import os
from login_logger import create_log, update_log, get_log, send_log, check_log, timeout, time_clear, multi_fail_log
from api.Cart import cart_api
from api.Reviews import review_api
from api.User_infotest import user_info_api
from api.Login_first import login_api
from api.User_info_admin import admin_api
from api.update_profile import update_profile_api
import uuid
import hashlib
import bcrypt
from flask_wtf import CsrfProtect
from flask_caching import Cache

cache = Cache()
app = Flask(__name__)
csrf = CsrfProtect(app)
app.register_blueprint(cart_api, url_prefix='/api/Cart')
app.register_blueprint(review_api, url_prefix='/api/Reviews')
app.register_blueprint(update_profile_api, url_prefix='/api/update_profile')

app.register_blueprint(login_api, url_prefix='/api/api_login')
app.register_blueprint(user_info_api, url_prefix='/api/User_info')
app.register_blueprint(admin_api, url_prefix='/api/admin_functions')

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'shop.db')
app.config['JWT_SECRET_KEY'] = 'asp-project-security-api'
app.config['WTF_CSRF_ENABLED'] = True

# app.config['CACHE_TYPE'] = 'simple'

app.config["Cache-Control"] = "no-cache, no-store"
app.config["Pragma"] = "no-cache"
app.config['server'] = 'www.cbshop.com'
app.config['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
# app.config['SESSION_COOKIE_SECURE'] = True
app.config["CACHE_TYPE"] = "null"
app.config['X-Frame-Options'] = 'SAMEORIGIN'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['X-Content-Type-Options'] = 'nosniff'


app.config['SECRET_KEY'] = "asp-project-security"
cache.init_app(app)
csrf.init_app(app)



db.app = app
db.init_app(app)

jwtt = JWTManager(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
user_schema = UserSchema()  # expect 1 record back
users_schema = UserSchema(many=True)  # expect multiple record back

# SESSION_COOKIE_SECURE = True


@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']


@app.after_request
def after_request(r):
    r.headers["Cache-Control"] = "no-cache, no-store"
    r.headers["Pragma"] = "no-cache"
    r.headers['server'] = 'www.cbshop.com'
    r.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    r.headers['X-Frame-Options'] = 'SAMEORIGIN'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    return r


@app.route('/dropsession')
def dropsession():
    session.pop('user', None)
    return redirect(url_for("home"))


# -----------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_cart_size(user):
    if user.is_anonymous:
        return None, 0
    else:
        q = Cart.query.filter_by(id=user.id).all()
        return user, len(q)


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    user, cart_no = get_cart_size(current_user)
    product_list = Product.query.all()
    products = []
    # products -> 0: name | 1: price | 2: image
    for product in product_list:
        products.append([product.product_name, product.product_price, product.product_image])
    return render_template('home.html', products=products, length=len(products), user=user, cart_no=cart_no)


@app.route('/search', methods=['GET', 'POST'])
def search():
    user, cart_no = get_cart_size(current_user)
    if request.args.get('q') == '':
        return redirect(url_for('home'))
    else:
        query = request.args.get('q')
        product_list = Product.query.filter(Product.product_name.like('%{}%'.format(query))).all()
        products = []
        # products -> 0: name | 1: price | 2: image
        for product in product_list:
            products.append([product.product_name, product.product_price, product.product_image])
        return render_template('home_search.html', products=products, length=len(products), query=query, user=user,
                               cart_no=cart_no)


@app.route('/getallusersrecords', methods=['GET'])
def getallusersrecords():
    users_list = User.query.all()
    result = users_schema.dump(users_list)
    return jsonify(result)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()
    if form.validate_on_submit():
        if 'timeout' in session:
            if not time_clear(session['timeout']):
                flash("Too many unsuccessful attempts, please try again later!")
                return redirect(url_for('login'))
            else:
                session.pop('attempts')
                session.pop('timeout')
        if 'attempts' not in session:
            session['attempts'] = 1
        if session['attempts'] >= 5 and 'timeout' not in session:
            session['timeout'] = timeout()
            multi_fail_log(request.remote_addr)
            flash("Too many unsuccessful attempts, please try again later!")
            return redirect(url_for('login'))

        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.checkpw(form.password.data.encode(), user.password):
                login_user(user, remember=form.remember_me.data)
                user.activate_is_authenticated()
                db.session.add(user)
                db.session.commit()
                session['user'] = request.form['username']
                # successful attempt
                session.pop('attempts')
                update_log(create_log(request.form['username'], request.remote_addr, 'pass'))
                return redirect(url_for('home'))

        # failed attempt
        update_log(create_log(request.form['username'], request.remote_addr, 'fail'))
        session['attempts'] += 1
        flash("Invalid username or password, please try again!")
        return redirect(url_for('login'))

    return render_template('login.html', form=form, title="Login in", user=None)


@app.route('/logout')
def logout():
    if current_user.is_anonymous:
        return redirect(url_for('login'))
    user = current_user
    user.deactivate_is_authenticated()
    db.session.add(user)
    db.session.commit()
    logout_user()
    return redirect(url_for("home"))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = CreateUserForm()
    if form.validate_on_submit():
        # email
        hashed_email_data = hashlib.sha256(form.email.data.encode()).hexdigest()
        exists = False
        user_list = User.query.filter_by(email=hashed_email_data).all()
        if len(user_list) >= 1:
            exists = True

        # check username
        exists2 = False
        user_list = User.query.filter_by(username=form.username.data).all()
        if len(user_list) >= 1:
            exists2 = True
        if not exists and not exists2:
            # bcrypt
            hashed_password = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt(rounds=16))
            hashed_security_Q = bcrypt.hashpw(form.security_questions.data.encode(), bcrypt.gensalt())
            hashed_security_ans = bcrypt.hashpw(form.security_questions_answer.data.encode(), bcrypt.gensalt(rounds=16))
            # bcrypt
            newuser = User(public_id=str(uuid.uuid4()), username=form.username.data, email=hashed_email_data,
                           password=hashed_password,
                           security_questions=hashed_security_Q,
                           security_questions_answer=hashed_security_ans,
                           is_active=True, is_authenticated=False, is_admin=False)
            db.session.add(newuser)
            db.session.commit()
            flash("You have successfully signed up!")
            return redirect(url_for('login'))

        if exists:
            flash("Email exists!")
        if exists2:
            flash("Username is taken!")
        return redirect(url_for('signup'))
    return render_template('sign up.html', title="Sign Up", form=form)


@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form1 = ForgetPasswordForm_Email()
    if form1.validate_on_submit():

        # ---sha algorithm---
        hashed_email_data = hashlib.sha256(form1.email.data.encode()).hexdigest()
        email_exist = db.session.query(User.id).filter_by(email=hashed_email_data).scalar()
        # ---sha algorithm---
        if email_exist is not None:
            user = User.query.filter_by(email=hashed_email_data).first()
            form11 = ForgetPasswordForm_Security()
            if form11.validate_on_submit():
                if bcrypt.checkpw(form11.security_questions.data.encode(), user.security_questions):
                    if bcrypt.checkpw(form11.security_questions_answer.data.encode(), user.security_questions_answer):
                        form2 = ForgetPasswordForm()
                        if form2.validate_on_submit():
                            update_user = User.query.filter_by(email=hashed_email_data).first()
                            hashed_password = bcrypt.hashpw(form2.newpassword.data.encode(), bcrypt.gensalt(rounds=16))
                            hashed_security_questions = bcrypt.hashpw(form11.security_questions.data.encode(), bcrypt.gensalt())
                            hashed_security_answer = bcrypt.hashpw(form11.security_questions_answer.data.encode(), bcrypt.gensalt(rounds=16))
                            update_user.password = hashed_password
                            update_user.security_questions = hashed_security_questions
                            update_user.security_questions_answer = hashed_security_answer
                            db.session.commit()
                            flash("You have successfully reset your password")
                            return redirect(url_for('login'))
                        return render_template('forgot_password.html', title='Reset Password', form1=form1,
                                               form11=form11, form2=form2)
                    else:
                        flash("Incorrect security questions answer")
                        return redirect(url_for('forgotpassword'))
                else:
                    flash("Incorrect security questions answer")
                    return redirect(url_for('forgotpassword'))
            return render_template('forgot_password.html', title='Reset Password', form1=form1, form11=form11)

        else:
            flash('Email does not exist')
            return redirect(url_for('forgotpassword'))
    return render_template('forgot_password.html', title='Reset Password', form1=form1)


@app.route('/profile', methods=['GET'])
def profile():
    if current_user.id is None:
        return redirect(url_for('/'))
    else:
        return render_template('profile.html', user=current_user)


@app.route('/orders', methods=['GET'])
def orders():
    user_id = request.args.get('user_id')
    order_id = request.args.get('order_id')
    if user_id is None or order_id is None:
        return redirect(url_for('/'))
    return render_template('order.html')


@app.route('/cart')
def cart():
    cart_list = []
    total_price = 0
    user, cart_no = get_cart_size(current_user)
    user_cart = Cart.query.filter_by(id=user.id).all()
    for item in user_cart:
        product = Product.query.filter_by(product_id=item.product_id).first()
        # [product_name, image, price, quantity]
        cart_list.append([product.product_name, product.product_image, item.quantity, product.product_price, product.product_id])
    for item in cart_list:
        total_price += item[3]
    return render_template('cart.html', user=user, cart_no=cart_no, cart_list=cart_list, total=total_price)


@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if current_user.is_anonymous:
        user = None
    else:
        user = current_user
    cardlist = []
    form = PaymentForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            cards = Payment.query.filter_by(id=current_user.id).all()
            for card in cards:
                cardlist.append(card.card_num)
            user_card_exist = db.session.query(Payment).filter_by(id=current_user.id).first()
            if user_card_exist:
                result = False
                for cardnum in cardlist:
                    if bcrypt.checkpw(str(form.cardNum.data).encode(), cardnum):
                        result = True
                        break
                    else:
                        continue
                if result:
                    while True:
                        product = Cart.query.filter_by(cart_id=current_user.id).first()
                        if product is None:
                            break
                        else:
                            db.session.delete(product)
                            db.session.commit()
                    return redirect(url_for('home'))
                else:

                    hashed_email_data = hashlib.sha256(form.email.data.encode()).hexdigest()
                    hashed_cardname = bcrypt.hashpw(form.cardName.data.encode(), bcrypt.gensalt())
                    hashed_cardnum = bcrypt.hashpw(str(form.cardNum.data).encode(), bcrypt.gensalt(rounds=16))
                    hashed_expmonth = bcrypt.hashpw(form.expmonth.data.encode(), bcrypt.gensalt())
                    hashed_expyear = bcrypt.hashpw(form.expyear.data.encode(), bcrypt.gensalt())
                    hashed_cvv = bcrypt.hashpw(str(form.cvv.data).encode(), bcrypt.gensalt(rounds=16))

                    card = Payment(name=form.name.data,
                                   email=hashed_email_data,
                                   address=form.address.data,
                                   country=form.country.data,
                                   city=form.city.data,
                                   zip=form.zip.data,
                                   cardname=hashed_cardname,
                                   cardnum=hashed_cardnum,
                                   expmonth=hashed_expmonth,
                                   expyear=hashed_expyear,
                                   cvv=hashed_cvv,
                                   id=user.get_id())

                    db.session.add(card)
                    db.session.commit()
                    while True:
                        product = Cart.query.filter_by(cart_id=current_user.id).first()
                        if product is None:
                            break
                        else:
                            db.session.delete(product)
                            db.session.commit()
                    return redirect(url_for('home'))

            hashed_email_data = hashlib.sha256(form.email.data.encode()).hexdigest()
            hashed_cardname = bcrypt.hashpw(form.cardName.data.encode(), bcrypt.gensalt())
            hashed_cardnum = bcrypt.hashpw(str(form.cardNum.data).encode(), bcrypt.gensalt(rounds=16))
            hashed_expmonth = bcrypt.hashpw(form.expmonth.data.encode(), bcrypt.gensalt())
            hashed_expyear = bcrypt.hashpw(form.expyear.data.encode(), bcrypt.gensalt())
            hashed_cvv = bcrypt.hashpw(str(form.cvv.data).encode(), bcrypt.gensalt(rounds=16))

            card = Payment(name=form.name.data,
                           email=hashed_email_data,
                           address=form.address.data,
                           country=form.country.data,
                           city=form.city.data,
                           zip=form.zip.data,
                           cardname=hashed_cardname,
                           cardnum=hashed_cardnum,
                           expmonth=hashed_expmonth,
                           expyear=hashed_expyear,
                           cvv=hashed_cvv,
                           id=user.get_id())

            db.session.add(card)
            db.session.commit()
            while True:
                product = Cart.query.filter_by(cart_id=current_user.id).first()
                if product is None:
                    break
                else:
                    db.session.delete(product)
                    db.session.commit()
            return redirect(url_for('home'))

    return render_template('payment.html', title='Payment', form=form, user=user)


@app.route('/admin_page', methods=['GET', 'POST'])
def admin_page():
    if current_user.is_admin:
        if request.method == 'POST':
            date = request.form.get('date')
            date = date.split('-')
            date = '{}-{}-{}'.format(date[2], date[1], date[0])
            # check if the date exists
            if check_log(date):
                send_log(date)
                flash('access log for {} has been sent.'.format(date))
            else:
                flash('There is no access logs for {}'.format(date))
            return redirect(url_for('admin_page'))
        else:
            log_list = get_log()
            return render_template('admin_page.html', user=current_user, logs=log_list), 200
    else:
        return redirect(url_for("home"))


@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    invalid = False
    if request.referrer.endswith('update_profile'):
        invalid = True
    if current_user.is_anonymous:
        return redirect(url_for("home"))
    else:
        return render_template('update_profile.html', user=current_user, error=invalid)


def reset_database():
    # run db_drop to reset the database
    db_drop(db)

    # run db_create to initialize the database
    db_create(db)

    # run db_seed to create sample data in the database
    db_seed(db)

    # update the js file
    update_js()


# Uncomment this function to reset the database
# reset_database()


if __name__ == "__main__":
    app.run()
