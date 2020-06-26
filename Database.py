from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, sql, Boolean, ForeignKey
from sqlalchemy.orm import relationship
import json
from flask_marshmallow import Marshmallow

db = SQLAlchemy()
ma = Marshmallow()


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

    john = User(
        username='JohnDoe',
        email='johnD@email.com',
        password='abcd1234',
        urole='Admin',
        is_authenticated=False,
        is_active=False)

    mary = User(
        username='MaryJane',
        email='maryJ@email.com',
        password='abcd1234',
        urole='customer',
        is_authenticated=False,
        is_active=False)

    peter = User(
        username='Spidey',
        email='pparker@email.com',
        password='abcd1234',
        urole='customer',
        is_authenticated=False,
        is_active=False)

    database.session.add(john)
    database.session.add(mary)
    database.session.add(peter)

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
    username = Column(String(64))
    email = Column(String(120), index=True, unique=True)
    password = Column(String(128))
    is_authenticated = Column(Boolean, default=False)
    is_active = Column(Boolean, default=False)
    urole = Column(String(80))
    user_reviews = relationship("Reviews")

    def __init__(self, username, password, email, is_active, is_authenticated, urole):
        self.username = username
        self.password = password
        self.email = email
        self.is_active = is_active
        self.is_authenticated = is_authenticated
        self.urole = urole

    def is_authenticate(self):
        return self.is_authenticated

    def activate_is_authenticated(self):
        self.is_authenticated = True

    def deactivate_is_authenticated(self):
        self.is_authenticated = False

    def get_id(self):
        return self.id

    def is_acive(self):
        return self.is_active

    def activate_user(self):
        self.is_active = True

    def get_username(self):
        return self.username

    def get_urole(self):
        return self.urole


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'email', 'password', 'is_authenticated', 'is_active', 'urole')


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


class Reviews(db.Model):
    __tablename__ = 'reviews'
    review_id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey("products"))
    id = Column(Integer, ForeignKey("users"))
    review = Column(String)


# to update the js file for the shop
def update_js():
    statement = sql.text('SELECT * FROM products')
    result = db.engine.execute(statement)
    data = []
    for row in result:
        data.append([row[0], row[1], row[2], row[3], row[4], row[6]])
    data1 = json.dumps(data)
    print(data1)

    statement = sql.text('SELECT * FROM reviews')
    result = db.engine.execute(statement)
    data = []
    for row in result:
        search_statement = sql.text('SELECT username FROM users WHERE id = ' + str(row[2]))
        username = db.engine.execute(search_statement)
        data.append([row[1], username.fetchone()[0], row[3]])
    data2 = json.dumps(data)
    print(data2)

    js = open("static/js/Shop.js", 'w')
    js.write("function CreateList(){ var data = " + "{data}".format(data=data1) + ";return data}" + "function CreateReview(){var reviews = " + "{data}".format(data=data2) + "; return reviews}")
    print('js updated')
    js.close()
