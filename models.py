from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Initialize SQLAlchemy instance without binding to app
db = SQLAlchemy()

# Association table for many-to-many relationship
user_organisation = db.Table('user_organisation',
                             db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                             db.Column('organisation_id', db.Integer, db.ForeignKey('organisation.id'),
                                       primary_key=True)
                             )


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.String(100), nullable=False, unique=True)
    firstName = db.Column(db.String(150), nullable=False)
    lastName = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    phone = db.Column(db.String(50))
    # is_active = db.Column(db.Boolean, default=True)

    organisations_joined = db.relationship('Organisation', secondary=user_organisation,
                                           backref=db.backref('members', lazy='dynamic'))

    def get_id(self):
        return str(self.id)


class Organisation(db.Model):
    __tablename__ = "organisation"
    id = db.Column(db.Integer, primary_key=True)
    orgId = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(250))

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Organisation {self.name}>'
