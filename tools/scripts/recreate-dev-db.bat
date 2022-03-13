@ECHO OFF

REM Create sql file to cleanup/recreate DB and users
REM First line has single > because we want to overwrite existing file.
REM Other has >> because they are just appending it.
ECHO DROP DATABASE IF EXISTS mk2s_ems; > %TEMP%\mk2s_ems.sql
ECHO CREATE DATABASE mk2s_ems DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci; >> %TEMP%\mk2s_ems.sql

ECHO "Creating New Database..."
mysql -u root -p < %TEMP%\mk2s_ems.sql
DEL /F /Q %TEMP%\mk2s_ems.sql

ECHO "Importing Schema by running migrations..."
cd ../../
call db-migrate up
call db-migrate up:data
call db-migrate up:tests
REM To go to folder where we were earlier
cd tools/scripts

REM ECHO "Importing Schema..."
REM mysql -u root -p mk2s_ems < ..\..\tools\db_schema\mk2s_ems-schema.sql

REM ECHO "Importing Test Data..."
REM mysql -u root -p mk2s_ems < ..\..\tools\db_schema\mk2s_ems-data.sql

ECHO "Successfully recreated database"
