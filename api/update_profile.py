from flask import Blueprint, request, redirect, url_for
from flask_login import current_user
from Database import User
from Database import db

update_profile_api = Blueprint('update_profile_api', __name__)


@update_profile_api.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        new_username = request.form.get('update_username')
        user = User.query.filter_by(public_id=current_user.public_id).first()
        username_list = User.query.filter_by(username=new_username).all()
        if len(username_list) >= 1:
            exist = True
        else:
            exist = False
        if exist:
            return redirect(url_for('update_profile'))
        elif len(new_username) < 4 or len(new_username) > 50:
            return redirect(url_for('update_profile'))
        else:
            for char in new_username:
                if not char.isdigit() and not char.isalpha() and not char == '_':
                    return redirect(url_for('update_profile'))
            if new_username is not None:
                user.username = new_username
                db.session.commit()
            return redirect(url_for('profile'))
