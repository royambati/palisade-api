# Simple migration script to create Palisade tables
from db import init_db

if __name__ == "__main__":
    init_db()
    print("Palisade DB tables created (or already exist).")