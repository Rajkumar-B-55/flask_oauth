from app import AppFactory
from app.models.model import User


class UserService:
    @classmethod
    def check_user_exists(cls, usr):
        try:
            user = User.get_by_username(usr)
            if not user:
                return None
            else:
                return user
        except Exception as e:
            raise e

    @classmethod
    def verify_password(cls, hash_pwd, pwd):
        try:
            is_matched = AppFactory.bcrypt.check_password_hash(hash_pwd, pwd)
            return True if is_matched else False
        except Exception as e:
            raise e

    @classmethod
    def add_user(cls, first_name,
                 last_name,
                 email,
                 password):
        try:
            usr_entity = User()
            usr_entity.first_name = first_name
            usr_entity.last_name = last_name
            usr_entity.email = email
            usr_entity.password = AppFactory.bcrypt.generate_password_hash(password)
            usr_entity.is_active = True
            usr_entity.save_me()
            return usr_entity
        except Exception as e:
            raise e
