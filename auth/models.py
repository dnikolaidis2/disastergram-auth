from auth import db
from auth import ma
from auth import bc
from sqlalchemy.dialects.postgresql import UUID
from marshmallow import fields
import uuid


def gen_uuid():
    uid = uuid.uuid4()
    while User.query.filter(User.id == uid.hex).one_or_none() is not None:
        uid = uuid.uuid4()

    return uid


def init_db(app):
    with app.app_context():
        db.create_all()


class User(db.Model):
    id = db.Column(UUID(as_uuid=True), default=gen_uuid, primary_key=True, unique=True, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.Text, unique=True, nullable=False)

    def check_password(self, password):
        return bc.check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = bc.generate_password_hash(password.__str__()).decode('utf-8')

    def __init__(self, *args, **kwargs):
        kwargs['password'] = bc.generate_password_hash(kwargs['password'].__str__()).decode('utf-8')
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username


class Token(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)


class UserSchema(ma.ModelSchema):
    id = fields.Function(serialize=lambda obj: str(obj.id.int),
                         deserialize=lambda value: uuid.UUID(int=int(value)))

    class Meta:
        model = User
        fields = ("id", "username")
