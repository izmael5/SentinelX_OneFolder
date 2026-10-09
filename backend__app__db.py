from collections.abc import Generator
import ssl
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def normalized_url(value: str) -> str:
    parts = urlsplit(value)
    scheme = 'mysql+pymysql' if parts.scheme == 'mysql' else parts.scheme
    # The managed DSN exposes ssl as a URL string, while PyMySQL expects an
    # SSL dictionary. Remove that query key and provide the dictionary below.
    query = urlencode([(key, val) for key, val in parse_qsl(parts.query) if key.lower() != 'ssl'])
    return urlunsplit((scheme, parts.netloc, parts.path, query, parts.fragment))


settings = get_settings()
database_url = normalized_url(settings.database_url)
connect_args: dict[str, object] = {'check_same_thread': False} if database_url.startswith('sqlite') else {}
if database_url.startswith('mysql+pymysql') and 'ssl=' in settings.database_url.lower():
    connect_args['ssl'] = ssl.create_default_context()
engine = create_engine(database_url, pool_pre_ping=True, pool_recycle=1800, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
