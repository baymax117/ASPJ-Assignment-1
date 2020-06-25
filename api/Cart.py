from flask import Blueprint

cart_api = Blueprint('cart_api', __name__)


@cart_api.route('/greet')
def greet():
    return "Hello"