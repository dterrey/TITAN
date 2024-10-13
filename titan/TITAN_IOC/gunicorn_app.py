from app import app, db  # Import the app and db instance from __init__.py

# Create the tables if they don't exist
with app.app_context():
    db.create_all()
    
if __name__ == "__main__":
    app.run(debug=True)
