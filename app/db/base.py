"""Base declarativa y utilidades de configuración de BD."""

from __future__ import annotations

import os

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Convención de nombres para que Alembic genere constraints deterministas.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base declarativa de todos los modelos."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def get_database_url() -> str:
    """URL de BD desde entorno; por defecto SQLite local de desarrollo."""
    return os.environ.get("BOUNTYRADAR_DB_URL", "sqlite:///bountyradar.db")
