//
// This module includes some helper functions which are needed for doing setup
// for testing like cleaning up database etc.
//
// TO IMPORT: const setupHelper = require('../test/setup-helper');

const config = require('config');
const mysql = require('mysql2/promise');
const mysqlImport = require('mysql-import');
// const now = require('performance-now');

// ======================================================================
// PRIVATE API FOR THIS MODULE
// ======================================================================

// ======================================================================
// PUBLIC API EXPOSED FROM THIS MODULE
// ======================================================================

/**
 * Cleanup the test DB and resetup it again.
 *
 * If test DB exist then it delete it and recreate schema along with data
 *
 * @returns {void} nothing
 */
async function cleanTestDatabase() {
  //   console.log('==================================');
  //   console.log('Clean test DB');
  //   console.log('==================================');

  // Create MYSQL connection without DB
  const conn = await mysql.createConnection({
    host: config.get('dbConfig.host'),
    user: config.get('dbConfig.user'),
    password: config.get('dbConfig.password'),
    // timezone: 'Z', // We don't need this parameter as we are not doing conversion
    dateStrings: true,
  });

  // Delete test DB if it exist
  try {
    await conn.execute(`DROP DATABASE IF EXISTS ${config.get('dbConfig.database')}`, []);
  } catch (error) {
    console.log(error);
    console.log('CUSTOM_TEST_FRAMEWORK_ERROR: DROP database command failed!');
    process.exit(1);
  }

  // Create a test DB
  try {
    await conn.execute(`CREATE DATABASE ${config.get('dbConfig.database')} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`, []);
  } catch (error) {
    console.log(error);
    console.log('CUSTOM_TEST_FRAMEWORK_ERROR: Unable to create Database!');
    process.exit(1);
  }

  // const t0 = now();
  // Create config for importing DB Schema
  const sqlImporter = mysqlImport.config({
    host: config.get('dbConfig.host'),
    user: config.get('dbConfig.user'),
    password: config.get('dbConfig.password'),
    database: config.get('dbConfig.database'),
  });

  // Import the schema
  try {
    await sqlImporter.import(`${__dirname}\\..\\tools\\db_schema\\fsjarsco-ims.sql`);
  } catch (error) {
    console.log(error);
    console.log('CUSTOM_TEST_FRAMEWORK_ERROR: Unable to import schema SQL file!');
    process.exit(1);
  }

  // const t1 = now();
  // console.log(`Time taken to install DB: ${(t1 - t0).toFixed(3)} Millisecond`);

  // const t10 = now();
  // Create config for importing DB Data
  const dataImporter = mysqlImport.config({
    host: config.get('dbConfig.host'),
    user: config.get('dbConfig.user'),
    password: config.get('dbConfig.password'),
    database: config.get('dbConfig.database'),
  });

  // Import the DB data
  try {
    await dataImporter.import(`${__dirname}\\db\\data\\test-data.sql`);
  } catch (error) {
    console.log('CUSTOM_TEST_FRAMEWORK_ERROR: Unable to import Data SQL file!');
    process.exit(1);
  }

  // const t11 = now();
  // console.log(`Time taken to install DB: ${(t11 - t10).toFixed(3)} Millisecond`);

  conn.close();
}

module.exports.cleanTestDatabase = cleanTestDatabase;
