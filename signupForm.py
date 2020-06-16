from wtforms import Form, StringField, validators, RadioField, TextAreaField, SelectField

class CreateUserForm(Form):
    userName = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])
    email = StringField('Email', [validators.Length(min=1, max=150), validators.DataRequired()])
    password = StringField('Password', [validators.Length(min=8, max=150), validators.DataRequired()])
    cfmPassword = StringField('Confirm Password', [validators.Length(min=8, max=150), validators.DataRequired()])

class UserLogin(Form):
    userName = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])
    password = StringField('Password', [validators.Length(min=8, max=150), validators.DataRequired()])