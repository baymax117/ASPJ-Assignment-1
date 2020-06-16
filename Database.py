from MainApp import db
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float


def db_create():
    db.create_all()
    print('Database created.')


def db_drop():
    db.drop_all()
    print('Database dropped.')


def db_seed():
    surgical_masks = Product(product_id=1,
                             product_name='Surgical Mask 20px',
                             product_type='Protective Clothing and Equipment',
                             product_price=10.00,
                             product_description='Surgical face mask to protect yourself when going out.',
                             product_stock=100)

    cloth_masks = Product(product_id=2,
                          product_name='Black Cloth Mask',
                          product_type='Protective Clothing and Equipment',
                          product_price=5.50,
                          product_description='Reusable cloth mask to keep you protected when going out.',
                          product_stock=80)

    small_hand_sanitiser = Product(product_id=3,
                                   product_name='Hand Sanitiser 50ml',
                                   product_type='Hand Wash and Sanitisers',
                                   product_price=3.50,
                                   product_description='Small bottle of hand sanitiser to keep your hands clean while outside.',
                                   product_stock=100)

    db.session.add(surgical_masks)
    db.session.add(cloth_masks)
    db.session.add(small_hand_sanitiser)

    john = User(user_id=1,
                username='JohnDoe',
                email='johnD@email.com',
                password='abcd1234')

    db.session.add(john)
    db.session.commit()
    print('database seeded')


class Product(db.Model):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True)
    product_name = Column(String)
    product_type = Column(String)
    product_price = Column(Float)
    product_description = Column(String)
    product_stock = Column(Integer)


class User(db.Model):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    username = Column(String)
    email = Column(String)
    password = Column(String)





