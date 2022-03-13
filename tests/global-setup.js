/**
 * This file contains code which will run before all the tests only once
 */
// =============================================
// ENVIRONMENT and CONFIGURATION SETTINGS
// =============================================
// Add environment variables from the .env files to the app environment
require('dotenv').config();
const config = require('config');
const setupHelper = require('./setup-helper');

module.exports = async () => {
  console.log('==================================');
  console.log('Executing Global Setup');
  console.log('==================================');

  console.log(`Your Test environment: ${config.get('environment')}`);

  await setupHelper.cleanTestDatabase();
};
