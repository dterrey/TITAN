from app import app, db  # Import the db instance

# Create the tables if they don't exist
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, port=5112)

