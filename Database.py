from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float


db = SQLAlchemy()


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
                          product_stock=80)

    face_shield = Product(product_id=3,
                          product_name='Plastic Face Shield',
                          product_type='Protective Clothing and Equipment',
                          product_price=5.90,
                          product_description='Reusable face shield to keep you protected when going out.',
                          product_stock=85)

    small_hand_sanitiser = Product(product_id=4,
                                   product_name='Hand Sanitiser 50ml',
                                   product_type='Hand Wash and Sanitisers',
                                   product_price=3.50,
                                   product_description='Small bottle of hand sanitiser to keep your hands clean while outside.',
                                   product_stock=100)

    medium_hand_sanitiser = Product(product_id=5,
                                    product_name='Hand Sanitiser 150ml',
                                    product_type='Hand Wash and Sanitisers',
                                    product_price=9.50,
                                    product_description='Medium bottle of hand sanitiser to keep your hands clean while outside for a little longer.',
                                    product_stock=90)

    large_hand_sanitiser = Product(product_id=6,
                                   product_name='Hand Sanitiser 500ml',
                                   product_type='Hand Wash and Sanitisers',
                                   product_price=30.00,
                                   product_description='Large bottle of hand sanitiser to keep your hands clean while at home.',
                                   product_stock=70)

    toilet_paper_2py = Product(product_id=7,
                               product_name='Toilet Paper 2ply 10pcs',
                               product_type='Paper and Tissue',
                               product_price=6.50,
                               product_description='2 ply toilet paper for your toilet business.',
                               product_stock=20)

    toilet_paper_3py = Product(product_id=8,
                               product_name='Toilet Paper 3ply 10pcs',
                               product_type='Paper and Tissue',
                               product_price=8.50,
                               product_stock=20.00,
                               product_description='3 ply toilet paper for your toilet business.')

    toilet_paper_4py = Product(product_id=9,
                               product_name='Toilet Paper 4ply 10pcs',
                               product_type='Paper and Tissue',
                               product_price=10.50,
                               product_stock=20.00,
                               product_description='4 ply toilet paper for your toilet business.')

    database.session.add(surgical_masks)
    database.session.add(cloth_masks)
    database.session.add(face_shield)
    database.session.add(small_hand_sanitiser)
    database.session.add(medium_hand_sanitiser)
    database.session.add(large_hand_sanitiser)
    database.session.add(toilet_paper_2py)
    database.session.add(toilet_paper_3py)
    database.session.add(toilet_paper_4py)

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

# run db_create to initialize the database
# db_create()

# run db_seed to create sample data in the database
# db_seed()

# run db_drop to reset the database
# db_drop()
