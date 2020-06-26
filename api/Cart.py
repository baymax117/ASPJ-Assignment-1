from flask import Blueprint, request

cart_api = Blueprint('cart_api', __name__)


@cart_api.route('/greet/<int:product_id>', methods=['POST', 'GET'])
def greet():
    if request.method == 'POST':
        return request.form['comment']
    return "Hello"


@cart_api.route('/add_cart')
def cart():
    return "Add Cart"