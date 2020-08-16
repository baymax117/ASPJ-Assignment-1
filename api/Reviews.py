from flask import Blueprint, request, redirect, url_for
from flask_login import current_user
from Database import Reviews
from sqlalchemy.sql import text
from Database import db, update_js

review_api = Blueprint('review_api', __name__)


@review_api.route('/add/<int:product_id>', methods=["POST", "GET"])
def add(product_id):
    if request.method == "POST":
        if current_user is not None:
            statement = text("SELECT review_id FROM reviews")
            result = db.engine.execute(statement)
            maxi = 1
            for row in result:
                if row[0] >= maxi:
                    maxi = row[0] + 1
            review = Reviews(review_id=maxi,
                             id=current_user.id,
                             product_id=product_id,
                             review=request.form['comment'])
            db.session.add(review)
            db.session.commit()
            statement = text("SELECT * FROM reviews")
            result = db.engine.execute(statement)
            for row in result:
                print(row)
            update_js()
    return redirect(url_for('home'))
