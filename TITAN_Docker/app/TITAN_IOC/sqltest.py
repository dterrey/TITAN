import sqlite3

# Connect to the database
conn = sqlite3.connect('/home/triagex/Downloads/TITAN/TITAN_IOC/instance/ioc_database.db')
cursor = conn.cursor()

# Query the IOC table
cursor.execute("SELECT * FROM ioc")
rows = cursor.fetchall()

# Print the results
for row in rows:
    print(row)

conn.close()
