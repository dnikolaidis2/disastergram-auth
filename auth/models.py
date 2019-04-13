from auth import db
from auth import ma
from auth import bc


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.Text, unique=True, nullable=False)

    def check_password(self, password):
        return bc.check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = bc.generate_password_hash(password.__str__()).decode('utf-8')

    def __init__(self, **kwargs):
        kwargs['password'] = bc.generate_password_hash(kwargs['password'].__str__()).decode('utf-8')
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username


class UserSchema(ma.ModelSchema):
    class Meta:
        model = User


def init_db(app):
    with app.app_context():
        db.create_all()
