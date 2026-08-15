"""
database/migrations/env.py
---------------------------
Alembic environment configuration for Cipherix.

This file is called by Alembic on every migration command.  It:

1. Reads the database URL from the application settings (not from
   ``alembic.ini``) so we never hard-code a path.
2. Imports the ORM ``Base`` so Alembic can auto-detect schema changes.
3. Runs migrations in "offline" mode (generates SQL script) or "online"
   mode (connects to the DB and runs migrations directly).
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings  # noqa: E402
from app.database.models import Base  # noqa: E402 — registers all table metadata

config = context.config

# Inject the database URL from application settings into Alembic config.
# This overrides the (intentionally absent) sqlalchemy.url in alembic.ini.
config.set_main_option("sqlalchemy.url", settings.database_url)
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for auto-generation of migrations.
target_metadata = Base.metadata



def run_migrations_offline() -> None:
    """
    Run migrations without a live database connection.

    Alembic emits SQL to stdout.  Useful for generating a migration script
    to review or apply manually in production.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()



def run_migrations_online() -> None:
    """
    Run migrations against a live database connection.

    Creates a connection from the engine config and runs all pending
    migrations inside a transaction.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
