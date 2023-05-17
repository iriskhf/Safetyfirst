import sqlite3

# Connect to a SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('URLdatabase.db')

# Create a new table with three columns: "safe", "suspicious", and "malicious"
conn.execute('''CREATE TABLE URLtable
             (safe TEXT,
             most_likely_safe TEXT,
             suspicious TEXT,
             malicious TEXT);''')

# Commit the changes to the database
conn.commit()

# Close the connection to the database
conn.close()
