from flask import Flask, Blueprint, request, jsonify, make_response, current_app
from Database import *
# from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
import bcrypt
from werkzeug.exceptions import BadRequest


login_api = Blueprint('login_api', __name__)
# app.config['SECRET_KEY'] = "asp-project-security"
# app = Flask(__name__)



@login_api.route('/apilogin')
def api_login():
    if BadRequest:
        raise BadRequest()

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    # if check_password_hash(user.password, auth.password):
    if bcrypt.checkpw(auth.password.encode(), user.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, current_app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

#Full link: /api/api_login/apilogin


# user_login_toinfotest_api = Blueprint('user_login_toinfotest_api', __name__)

# @user_login_toinfotest_api.route('/logintocheck', methods=['POST'])
# def logintocheck():
#     if request.is_json:
#         username = request.json['username']
#         password = request.json['password']
#     else:
#         username = request.form['username']
#         password = request.form['password']
#
#
#     user = User.query.filter_by(username=username, password=password).first()
#     print(user)
#     if user:
#         access_token = create_access_token(identity=username)
#         return jsonify(message="Login successfully", access_token=access_token)
#     else:
#         return jsonify(message="Incorrect username or password"),401



