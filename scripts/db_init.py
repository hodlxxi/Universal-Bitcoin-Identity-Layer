#!/usr/bin/env python3
"""
Database initialization script for HODLXXI.

This script initializes the database and creates all tables.
For production, use Alembic migrations instead.
"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from sqlalchemy import create_engine

from app.database import get_database_url, get_health_status, init_all
from app.models import Base


def main():
    """Initialize database and create all tables."""
    print("=" * 60)
    print("HODLXXI Database Initialization")
    print("=" * 60)

    try:
        # Get database URL
        db_url = get_database_url()
        print(f"\n📊 Database URL: {db_url.split('@')[1] if '@' in db_url else 'memory'}")

        # Create engine
        engine = create_engine(db_url)

        # Create all tables
        print("\n🔨 Creating database tables...")
        Base.metadata.create_all(engine)
        print("✅ All tables created successfully")

        # Initialize connections
        print("\n🔌 Initializing connections...")
        init_all()

        # Check health
        print("\n🏥 Checking database health...")
        health = get_health_status()

        print("\n📊 Database Health:")
        print(f"  PostgreSQL: {health['database']['status']}")
        print(f"  Redis: {health['redis']['status']}")

        if health["database"]["status"] == "healthy" and health["redis"]["status"] == "healthy":
            print("\n✅ Database initialization complete!")
            print("\n📝 Next steps:")
            print("  1. Run migrations: alembic upgrade head")
            print("  2. Start the application: python app/app.py")
            return 0
        else:
            print("\n⚠️  Some services are not healthy. Check configuration.")
            return 1

    except Exception as e:
        print(f"\n❌ Error initializing database: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
