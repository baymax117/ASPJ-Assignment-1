from flask import Blueprint

review_api = Blueprint('review_api', __name__)

@review_api.route('/test')
def test():
    return 'It works'