#!/bin/bash -ue

# #We are using migrations hence we will not be dumping schema. Schema will be created through migrations.
# #Same things applied for test data also. Use "recreate-dev-db.sh" to create database for development.

# echo "Dumping Schema..."
# mysqldump -h 127.0.0.1 -P 3306 -u root -p --no-data mk2s_ems | sed 's/ AUTO_INCREMENT=[0-9]*//g' > ../../tools/scripts/mk2s_ems-schema.sql

# echo "Dumping Data..."
# mysqldump -h 127.0.0.1 -P 3306 -u root -p --no-create-info mk2s_ems > ../../tools/scripts/mk2s_ems-data.sql

# echo "Successfully dumped database"
