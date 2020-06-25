from flask import Blueprint

cart_api = Blueprint('cart_api', __name__)


@cart_api.route('/greet')
def greet():
    return "Hello"


@cart_api.route('/add_cart')
def cart():
    return "Add Cart"