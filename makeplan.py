# makeplan.py

import MySQLdb
import sys

# open a database connection
connection = MySQLdb.connect (host="localhost", user="dream", passwd="bravo", db="test")

# prepare a cursor object using cursor() method
cursor = connection.cursor()

# execute the SQL query using execute() method
cursor.execute("insert into plan (date, user_id, bucket_id, status, lst_mod_dt) \
select date_format(now(),'%Y%m%d'), user_id, id, 0, now() \
from Bucket \
where deadline > sysdate() \
and substr(`rpt_cndt`,weekday(sysdate())+1,1) = 1 \
and rpt_type is not null \
and rpt_type <> '' \
union \
select date_format(now(),'%Y%m%d'), b.user_id, b.id, ifnull(p.status,0), now() \
from Bucket b left join Plan p on b.id = p.bucket_id \
where ifnull(p.status,0) <> 1 \
and b.deadline between ADDDATE(LAST_DAY(SUBDATE(NOW(), INTERVAL 1 MONTH)), 1) and ADDDATE(LAST_DAY(NOW()),1) \
union \
select date_format(now(),'%Y%m%d'), b.user_id, b.id, ifnull(p.status,0), now() \
from Bucket b left join Plan p on b.id = p.bucket_id \
where ifnull(p.status,0) <> 1 \
and b.scope = 'YEARLY' \
and b.range = date_format(now(),'%Y') \
and date_format(now(),'%m') = '12';")

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

