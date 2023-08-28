from sqlalchemy import create_engine, MetaData
from sqlalchemy import orm

from config import config


class SQLConfig:
    engine = None
    session = None

    @classmethod
    def initialize(cls):
        """
        SQLAlchemy session
        :return:  object
        """
        sql_db_url = config.SQLALCHEMY_DATABASE_URI
        cls.engine = create_engine(url=sql_db_url)
        metadata = MetaData()
        conn = cls.engine.connect()
        Session = orm.sessionmaker(autoflush=True, bind=cls.engine)
        cls.session = Session()
        from app.models.model import Base
        Base.metadata.create_all(bind=cls.engine)
