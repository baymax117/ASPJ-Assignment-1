from flask import Blueprint, request, jsonify, current_app
from Database import UserSchema, User
from functools import wraps
import jwt


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
        except jwt.DecodeError:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@user_info_api.route('/enquireuserinfo/<public_id>', methods=['GET'])
@token_required
def get_user_info(current_user, public_id):


    user = User.query.filter_by(public_id = public_id).first()
    print(user)

    if current_user.public_id != public_id:
        return jsonify({'Message' : 'Acess Denied'})

    if user:
        result = user_schema.dump(user)
        return jsonify(result)
    else:
        return jsonify(message="User does not exist"), 404


#Full link: /api/User_info/enquireuserinfo/



