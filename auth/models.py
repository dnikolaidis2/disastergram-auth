from auth import db
from auth import ma
from auth import bc
from flask import current_app
from sqlalchemy.dialects.postgresql import UUID
from marshmallow import fields
from hashlib import blake2b
from datetime import datetime, timedelta
import uuid, jwt, enum


def gen_uuid():
    uid = uuid.uuid4()
    while User.query.get(uid) is not None:
        uid = uuid.uuid4()

    return uid


class User(db.Model):
    id = db.Column(UUID(as_uuid=True), default=gen_uuid, primary_key=True, unique=True, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.Text, unique=True, nullable=False)

    def check_password(self, password):
        return bc.check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = bc.generate_password_hash(password.__str__()).decode('utf-8')

    def __init__(self, *args, **kwargs):
        if kwargs.get('id') is None:
            kwargs['id'] = gen_uuid()

        kwargs['password'] = bc.generate_password_hash(str(kwargs['password'])).decode('utf-8')
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User id={}, username={}}>'.format(self.id, self.username)


class TokenEnum(enum.Enum):
    ACTIVE = 1
    INACTIVE = 2


class Token(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, index=True)
    sub = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    exp = db.Column(db.DateTime(), nullable=False)
    status = db.Column(db.Enum(TokenEnum), nullable=False)

    def set_inactive(self):
        self.status = TokenEnum.INACTIVE

    def __init__(self, token=None, *args, **kwargs):
        if token is not None:
            kwargs['id'] = hash_token_to_uuid(token)
            payload = jwt.decode(token, verify=False)
            kwargs['sub'] = uuid.UUID(int=int(payload['sub']))
            kwargs['exp'] = datetime.utcfromtimestamp(payload['exp'])
            kwargs['status'] = TokenEnum.ACTIVE

        super(Token, self).__init__(**kwargs)

    def __repr__(self):
        return '<Token id={}, sub={}>'.format(self.id, self.sub)


class UserSchema(ma.ModelSchema):
    id = fields.Function(serialize=lambda obj: str(obj.id.int),
                         deserialize=lambda value: uuid.UUID(int=int(value)))

    class Meta:
        model = User
        fields = ("id", "username")


def init_db(app):
    with app.app_context():
        db.create_all()


def hash_token_to_uuid(token):
    if isinstance(token, str):
        token = token.encode()

    return uuid.UUID(hex=blake2b(token, digest_size=16).hexdigest())


def update_token_table(defer_commit=False):
    expired_tokens = Token.query.\
        filter(Token.exp < datetime.utcnow() - current_app.config.get('AUTH_LEEWAY', timedelta(seconds=30))).\
        all()
    [db.session.delete(token) for token in expired_tokens]
    if not defer_commit:
        db.session.commit()
