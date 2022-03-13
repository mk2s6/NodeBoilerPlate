#!/bin/bash -ue

#Create sql file to cleanup/recreate DB and users
#First line has single > because we want to overwrite existing file.
#Other has >> because they are just appending it.
echo "DROP DATABASE IF EXISTS mk2s_ems;" > /tmp/mk2s_ems.sql
echo "CREATE DATABASE mk2s_ems DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;" >> /tmp/mk2s_ems.sql

echo "Creating New Database..."
mysql -u root -p < /tmp/mk2s_ems.sql
rm -rf /tmp/mk2s_ems.sql

echo "Importing Schema by running migrations..."
cd ../../
db-migrate up
db-migrate up:data
db-migrate up:tests
#To go to folder where we were earlier
cd tools/scripts

# ECHO "Importing Schema..."
# mysql -u root -p mk2s_ems < ..\..\tools\db_schema\mk2s_ems-schema.sql

# ECHO "Importing Test Data..."
# mysql -u root -p mk2s_ems < ..\..\tools\db_schema\mk2s_ems-data.sql

echo "Successfully recreated database"
