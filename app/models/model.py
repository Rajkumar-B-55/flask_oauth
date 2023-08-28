from sqlalchemy import Column, Integer, DateTime, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

from app.models import SQLConfig as sa

# models here


base_declaration = declarative_base()


class Base(base_declaration):
    __abstract__ = True
    pid = Column('pid', Integer, primary_key=True, autoincrement=True)
    created_on = Column('created_on', DateTime, default=datetime.now())
    updated_on = Column('updated_on', DateTime, default=datetime.now(), onupdate=datetime.now())

    def save_me(self):
        try:
            sa.session.add(self)
            sa.session.commit()
        except Exception as e:
            sa.session.rollback()
            raise e

    def delete_me(self):
        try:
            sa.session.delete(self)
            sa.session.commit()
        except Exception as e:
            sa.session.rollback()
            raise e

    @classmethod
    def get_by_id(cls, pid):
        try:
            query = sa.session.query(cls)
            query = query.filter(cls.pid == pid)
            result = query.first()
            return result
        except Exception as e:
            sa.session.rollback()
            raise e


class User(Base):
    __tablename__ = 'user'
    first_name = Column('first_name', String(100), nullable=False)
    last_name = Column('last_name', String(100), nullable=False)
    email = Column('email', String(150), nullable=False)  # username
    password = Column('password', String(100), nullable=False)
    is_active = Column('is_active', Boolean, unique=False, default=False)

    @classmethod
    def get_by_username(cls, username):
        try:
            query = sa.session.query(cls)
            query = query.filter(cls.email == username)
            result = query.first()
            return result
        except Exception as e:
            sa.session.rollback()
            raise e
