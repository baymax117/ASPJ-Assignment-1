from flask import Blueprint, request, jsonify, current_app
from Database import *
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from functools import wraps
import jwt
from werkzeug.exceptions import BadRequest


user_schema = UserSchema()  #expect 1 record back
users_schema = UserSchema(many=True) #expect multiple record back

user_info_api = Blueprint('user_info_api', __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@user_info_api.route('/enquireuserinfo/<public_id>', methods=['GET'])
@token_required
def get_user_info(current_user, public_id):
    if BadRequest:
        raise BadRequest()

    user = User.query.filter_by(public_id = public_id).first()

    if current_user.public_id != public_id:
        return jsonify({'Message' : 'Acess Denied'})

    if user:
        result = user_schema.dump(user)
        return jsonify(result)
    else:
        return jsonify(message="User does not exist"), 404


#Full link: /api/User_info/enquireuserinfo/



# from flask_login import LoginManager, logout_user, current_user, login_user, UserMixin

# def login_required(role):
#     def wrapper(fn):
#         @wraps(fn)
#         def decorated_view(*args, **kwargs):
#             if current_user.is_authenticated == False:
#               print("YO MAN")
#               # return login_manager.unauthorized()
#               return "Forbidden access", 402
#             print("Next option")
#             if (current_user.urole != role):
#                 print("YO MAN 2")
#                 # return login_manager.unauthorized()
#                 return "Forbidden access", 402
#             return fn(*args, **kwargs)
#         return decorated_view
#     return wrapper



# user_schema = UserSchema()  #expect 1 record back
# users_schema = UserSchema(many=True) #expect multiple record back
#
#
# user_infotest_api = Blueprint('user_infotest_api', __name__)

# @user_infotest_api.route('/checkuserinfo/<int:user_id>', methods=['GET'])
# @jwt_required
# # @login_required('customer')
# def checkuserinfo(user_id: int):
#     user = User.query.filter_by(id=user_id).first()
#     if user:
#         result = user_schema.dump(user)
#         return jsonify(result)
#     else:
#         return jsonify(message="User does not exist"), 404



