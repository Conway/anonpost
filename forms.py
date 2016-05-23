from flask.ext.wtf import Form
from wtforms import IntegerField, PasswordField, SelectField, SubmitField, TextAreaField, TextField, validators

class SubmissionForm(Form):
    body = TextAreaField("Enter the text of your post here. If you want to add an image, upload it to imgur.com and paste the link in this section", [validators.Required()])
    submit = SubmitField("Submit this post for review")

class BanIPForm(Form):
    ip = TextField("IP to ban", [validators.Required()])
    ban_type = SelectField("Ban Type", choices=[(o, o) for o in ['quiet', 'public']])
    public_ban_note = TextAreaField("Public note for the user", [validators.required()])
    private_ban_note = TextAreaField("Internal ban note")
    expiration = IntegerField("Enter the duration in seconds")
    ban = SubmitField("Ban this IP")

class LoginForm(Form):
    password = PasswordField("Password")
    submit = SubmitField("Login")

class FilterForm(Form):
    regex = TextAreaField("Regex Condition")
    submit = SubmitField("Submit")