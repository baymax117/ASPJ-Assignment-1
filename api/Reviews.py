from flask import Blueprint, request, redirect, url_for
from flask_login import current_user
from Database import Reviews
from Database import db, update_js
import re
review_api = Blueprint('review_api', __name__)


@review_api.route('/add/<int:product_id>', methods=["POST", "GET"])
def add(product_id):
    if request.method == "POST":
        if current_user is not None:
            review_list = Reviews.query.all()
            maxi = 1
            for review in review_list:
                if review.review_id >= maxi:
                    maxi = review.review_id + 1
            review = Reviews(review_id=maxi,
                             id=current_user.id,
                             product_id=product_id,
                             review=re.escape(request.form['comment']))
            db.session.add(review)
            db.session.commit()
            update_js()
    return redirect(url_for('home'))
