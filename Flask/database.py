import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()
pass_db_admin = os.getenv('DB_ADMIN_KEY')

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password= pass_db_admin,
    auth_plugin='caching_sha2_password',
)

my_cursor = mydb.cursor()

# CREATE DATABASE
#my_cursor.execute("CREATE DATABASE col")

# DELETE DATABASE
#my_cursor.execute("DROP DATABASE col")


my_cursor.execute("SHOW DATABASES")
for db in my_cursor:
    print(db)