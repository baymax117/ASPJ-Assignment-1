from flask import Blueprint, request, jsonify
from Database import *
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

user_login_toinfotest_api = Blueprint('user_login_toinfotest_api', __name__)


@user_login_toinfotest_api.route('/logintocheck', methods=['POST'])
def logintocheck():
    if request.is_json:
        username = request.json['username']
        password = request.json['password']
    else:
        username = request.form['username']
        password = request.form['password']

    user = User.query.filter_by(username=username, password=password).first()
    if user:
        access_token = create_access_token(identity=username)
        return jsonify(message="Login successfully", access_token=access_token)
    else:
        return jsonify(message="Incorrect username or password"),401