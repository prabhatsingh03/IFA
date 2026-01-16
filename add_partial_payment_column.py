from app import app, db
from sqlalchemy import text

def add_column():
    with app.app_context():
        try:
            # Check if column exists first to avoid duplicate column error logic 
            # (though MySQL 'ADD COLUMN IF NOT EXISTS' syntax is version dependent)
            # Simplest is just try catch or check information_schema.
            # Let's try direct ALTER TABLE and catch specific error if column exists?
            # Or better, just execute it.
            
            sql = text("ALTER TABLE ifa_forms ADD COLUMN is_partial_payment BOOLEAN DEFAULT FALSE")
            with db.engine.connect() as conn:
                conn.execute(sql)
                conn.commit() # Important for transaction based DBs
            print("Successfully added 'is_partial_payment' column.")
            
        except Exception as e:
            if "Duplicate column name" in str(e):
                print("Column 'is_partial_payment' already exists.")
            else:
                print(f"Error adding column: {e}")

if __name__ == "__main__":
    add_column()
