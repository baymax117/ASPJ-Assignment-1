from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship
import json
from flask_marshmallow import Marshmallow
import base64
import onetimepass
import os

db = SQLAlchemy()
ma = Marshmallow()
key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='


def db_create(database):
    database.create_all()
    print('Database created.')


def db_drop(database):
    database.drop_all()
    print('Database dropped.')


def db_seed(database):
    surgical_masks = Product(product_id=1,
                             product_name='Surgical Mask 20pcs',
                             product_type='Protective Clothing and Equipment',
                             product_price=10.00,
                             product_description='Surgical face mask to protect yourself when going out.',
                             product_stock=100,
                             product_image="Surgical Mask.png")

    cloth_masks = Product(product_id=2,
                          product_name='Black Cloth Mask',
                          product_type='Protective Clothing and Equipment',
                          product_price=5.50,
                          product_description='Reusable cloth mask to keep you protected when going out.',
                          product_stock=80,
                          product_image="Black Cloth Mask.png")

    face_shield = Product(product_id=3,
                          product_name='Plastic Face Shield',
                          product_type='Protective Clothing and Equipment',
                          product_price=5.90,
                          product_description='Reusable face shield to keep you protected when going out.',
                          product_stock=85,
                          product_image="Plastic Face Shield.png")

    small_hand_sanitiser = Product(product_id=4,
                                   product_name='Hand Sanitiser 50ml',
                                   product_type='Hand Wash and Sanitisers',
                                   product_price=3.50,
                                   product_description='Small bottle of hand sanitiser to keep your hands clean while outside.',
                                   product_stock=100,
                                   product_image='Hand Sanitiser 50ml.png')

    medium_hand_sanitiser = Product(product_id=5,
                                    product_name='Hand Sanitiser 150ml',
                                    product_type='Hand Wash and Sanitisers',
                                    product_price=9.50,
                                    product_description='Medium bottle of hand sanitiser to keep your hands clean while outside for a little longer.',
                                    product_stock=90,
                                    product_image='Hand Sanitiser 150ml.png')

    large_hand_sanitiser = Product(product_id=6,
                                   product_name='Hand Sanitiser 500ml',
                                   product_type='Hand Wash and Sanitisers',
                                   product_price=30.00,
                                   product_description='Large bottle of hand sanitiser to keep your hands clean while at home.',
                                   product_stock=70,
                                   product_image='Hand Sanitiser 500ml.png')

    toilet_paper_2py = Product(product_id=7,
                               product_name='Toilet Paper 2ply 10pcs',
                               product_type='Paper and Tissue',
                               product_price=6.50,
                               product_description='2 ply toilet paper for your toilet business.',
                               product_stock=20,
                               product_image='Toilet Paper 2ply 10pcs.png')

    toilet_paper_3py = Product(product_id=8,
                               product_name='Toilet Paper 3ply 10pcs',
                               product_type='Paper and Tissue',
                               product_price=8.50,
                               product_description='3 ply toilet paper for your toilet business.',
                               product_stock=20.00,
                               product_image='Toilet Paper 2ply 10pcs.png')

    toilet_paper_4py = Product(product_id=9,
                               product_name='Toilet Paper 4ply 10pcs',
                               product_type='Paper and Tissue',
                               product_price=10.50,
                               product_description='4 ply toilet paper for your toilet business.',
                               product_stock=20.00,
                               product_image='Toilet Paper 2ply 10pcs.png')

    database.session.add(surgical_masks)
    database.session.add(cloth_masks)
    database.session.add(face_shield)
    database.session.add(small_hand_sanitiser)
    database.session.add(medium_hand_sanitiser)
    database.session.add(large_hand_sanitiser)
    database.session.add(toilet_paper_2py)
    database.session.add(toilet_paper_3py)
    database.session.add(toilet_paper_4py)

    database.session.commit()
    print('database seeded')


class Product(db.Model):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True)
    product_name = Column(String)
    product_type = Column(String)
    product_price = Column(Float)
    product_description = Column(String)
    product_stock = Column(Integer)
    product_image = Column(String)
    product_reviews = relationship("Reviews")


class User(db.Model):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    public_id = Column(String(50), unique=True)
    # username = Column(EncryptedType(Unicode, key, AesEngine, 'pkcs5' ))
    # username =  Column(EncryptedType(String, key), nullable=True)
    username = Column(String(100))
    email = Column(String(120), index=True, unique=True)
    password = Column(String(128))
    security_questions = Column(String(128))
    security_questions_answer = Column(String(128))
    is_authenticated = Column(Boolean, default=False)
    is_active = Column(Boolean, default=False)
    is_anonymous = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    user_reviews = relationship("Reviews")
    cart = relationship("Cart")

    otp_secret = Column(String(16))

    def __init__(self, public_id ,username, password, email, security_questions, security_questions_answer, is_active,
                 is_authenticated, is_admin):
        """Initial the user columns."""
        self.public_id = public_id
        self.username = username
        self.password = password
        self.email = email
        self.security_questions = security_questions
        self.security_questions_answer = security_questions_answer
        self.is_active = is_active
        self.is_authenticated = is_authenticated
        self.is_admin = is_admin
        # generate a random secret
        self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    def is_authenticate(self):
        return self.is_authenticated

    def activate_is_authenticated(self):
        self.is_authenticated = True

    def deactivate_is_authenticated(self):
        self.is_authenticated = False

    def get_id(self):
        return self.id

    def activate_user(self):
        self.is_active = True

    def get_username(self):
        return self.username

    def get_admin(self):
        return self.is_admin

    # for 2FA purposes
    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo'.format(self.get_username(), self.otp_secret)

    # for 2FA purposes
    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


class UserSchema(ma.Schema):
    class Meta:
        fields = ('public_id', 'username')
        """user Schema for api use."""


class Payment(db.Model):
    __tablename__ = 'cards'
    name = Column(String(150))
    email = Column(String(120))
    address = Column(String(150))
    country = Column(String(56))
    city = Column(String(150))
    zip = Column(Integer)
    cardname = Column(String(150))
    cardnum = Column(String(150), primary_key=True) #change to string
    expmonth = Column(String(9))
    expyear = Column(Integer)
    cvv = Column(Integer)
    id = Column(Integer, ForeignKey('users'))
    # rememberinfo = Column(Boolean, default=False)


class Reviews(db.Model):
    __tablename__ = 'reviews'
    review_id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey("products"))
    id = Column(Integer, ForeignKey("users"))
    review = Column(String)


class Cart(db.Model):
    __tablename__ = 'carts'
    cart_id = Column(Integer, primary_key=True)
    product_id = Column(Integer, primary_key=True)
    quantity = Column(Integer)
    id = Column(Integer, ForeignKey("users"))


# class Order(db.Model):
#     __tablename__ = 'orders'
#     order_id = Column(Integer, primary_key=True)
#     card_num = Column(Integer, ForeignKey("cards"))
#     id = Column(Integer, ForeignKey("users"))


class OrderItems(db.Model):
    __tablename__ = 'order_items'
    datetime = Column(Integer, primary_key=True)
    cart_id = Column(Integer, primary_key=True)
    product_id = Column(Integer)
    quantity = Column(Integer)


# to update the js file for the shop
def update_js():
    data = []
    products = Product.query.all()
    for product in products:
        data.append([product.product_id, product.product_name, product.product_type, product.product_price, product.product_description, product.product_image])
    data1 = json.dumps(data)

    reviews = Reviews.query.all()
    data = []
    for review in reviews:
        user = User.query.filter_by(id=review.id).first()
        data.append([review.product_id, user.username, review.review])
    data2 = json.dumps(data)
    print(data2)

    js = open("C:/Flask/static/js/Shop.js", 'w')
    js.write("function createList(){\nvar data = " + "{data}".format(
        data=data1) + ";\nreturn data;\n}\n" + "function createReview(){\nvar reviews = " + "{data}".format(
        data=data2) + ";\nreturn reviews;\n}")
    print('js updated')
    js.close()
