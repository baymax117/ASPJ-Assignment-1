from flask import Blueprint, request, redirect, url_for
from flask_login import current_user
from Database import User
from sqlalchemy.sql import text
from Database import db, update_js

update_profile_api = Blueprint('update_profile_api', __name__)


@update_profile_api.route('/update/<username>', methods=['GET', 'POST'])
def update(username):
    if request.method == 'POST':
        new_username = request.form.get('update_username')
        new_password = request.form.get('update_password')
        new_admin = request.form.get('admin')
        print(new_admin)
        user = User.query.filter_by(username=username).first()
        if new_username is not None:
            user.username = new_username

        if new_password is not None:
            user.password = new_password

        db.session.commit()
        return 'Works'
