# makeplan.py

import MySQLdb
import sys

# open a database connection
connection = MySQLdb.connect (host="localhost", user="dream", passwd="bravo", db="test")

# prepare a cursor object using cursor() method
cursor = connection.cursor()

# execute the SQL query using execute() method
cursor.execute("insert into plan (date, user_id, bucket_id, status, lst_mod_dt) \
select date_format(NOW(), '%Y%m%d'), user_id, id, 0, NOW() \
from bucket \
where deadline > NOW() \
and status = '0' \
and level = '0' \
and rpt_type = 'WKRP' \
and substr(rpt_cndt, weekday(NOW())+1,1) = 1 \
union \
select date_format(NOW(), '%Y%m%d'), user_id, id, 0, NOW() \
from bucket \
where deadline > NOW() \
and status = '0' \
and level = '0' \
and rpt_type = 'WEEK' \
and weekday(NOW()) in (0, 6) \
union \
select date_format(NOW(), '%Y%m%d'), user_id, id, 0, NOW() \
from bucket \
where deadline > NOW() \
and status = '0' \
and level = '0' \
and rpt_type = 'MNTH' \
and ((weekday(NOW()) = 0 and dayofmonth(NOW()) <= 7) \
or LAST_DAY(NOW()) - ((7 + WEEKDAY(LAST_DAY(NOW())) - 6) % 7) = date_format(NOW(), '%Y%m%d'));")

connection.commit()
# fetch a single row using fetchone() method
# row = cursor.fetchone()

# print the row[0]
# print "Server Version: ", row[0]
# close the cursor object
cursor.close()

# close the connection
connection.close()

# exit the program
sys.exit()

