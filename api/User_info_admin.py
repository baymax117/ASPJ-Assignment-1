from flask import Blueprint, request, jsonify
from Database import *
from flask_jwt_extended import JWTManager, jwt_required, create_access_token


from functools import wraps
from flask_login import LoginManager, logout_user, current_user, login_user, UserMixin

def login_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if current_user.is_authenticated == False:
              print("YO MAN")
              # return login_manager.unauthorized()
              return "Forbidden access", 402
            print("Next option")
            if (current_user.urole != role):
                print("YO MAN 2")
                # return login_manager.unauthorized()
                return "Forbidden access", 402
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

user_schema = UserSchema()  #expect 1 record back
users_schema = UserSchema(many=True) #expect multiple record back

user_info_admin_api = Blueprint('user_info_admin_api', __name__)

@user_info_admin_api.route('/checkalluserinfo', methods=['GET'])
@jwt_required
@login_required('admin')
def checkalluserinfo():
    users_list = User.query.all()
    result = users_schema.dump(users_list)
    return jsonify(data=result)