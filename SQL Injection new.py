#!/usr/bin/python3
import sqlite3

db = "./students.db"
conn = sqlite3.connect(db)
c = conn.cursor()
def add(table,*args):
    statement="INSERT INTO %s VALUES %s" % (table,args)
    cursor.execute(statement)
print("Without Hack: \n")

c.execute("SELECT * from students WHERE Name='Robert'")
result = c.fetchall()
print(result)
Name = "Robert'; DROP TABLE students;--"
Name_to_use = (Name,)
print("Name to use:", Name_to_use)

Name
to
use: ("Robert'; DROP TABLE students;--",)
c.execute("SELECT * from students WHERE Name=(?)" , Name_to_use)
data = [("Robert'; DROP TABLE students;--", 10)]
c.executemany("INSERT INTO students VALUES (?,?)", data)
conn.commit()