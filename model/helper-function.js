//
// This module create some helper functions. Use this functions elsewhere
// in code instead of writing logic
//
// TO IMPORT: const hf = require('../../model/helper-function');

// FUTURE TASK
// Node.js has experimental support for ES6 hence we can't use syntax like
// import {sleep, isEmptyJSON} from  '<path to helper-function.js>'
// But when we get that as long term support in node.js convert this to import
//

const validatorLibrary = require('validator');
const dateAndTime = require('date-and-time');
const pool = require('../database/db');

// ======================================================================
// PRIVATE API FOR THIS MODULE
// ======================================================================

// ======================================================================
// PUBLIC API EXPOSED FROM THIS MODULE
// ======================================================================

/**
 * Check whether the object (JSON can be used) is empty or not. This also check if object
 * is undefined or null. Generally used when we get response from external API.
 *
 * @param {object|JSON} obj JS variable/object/JSON
 *
 * @returns {boolean} Representing whether the object is empty or not
 */
function isEmptyJSON(obj) {
  // only using obj === will work but this is just for readability
  if (obj === null || obj === undefined) {
    return true;
  }
  return !Object.keys(obj).length;
}

/**
 * Check whether the given value is empty or not. This also check if object
 * is undefined or null. Generally used in case of validator implementation of ifExists****.
 *
 * @param {any} val any value in JS. If it is object use isEmptyJSON
 *
 * @returns {boolean} Representing whether the value is empty or not
 */
function isEmptyValue(val) {
  // only using obj === null will work but this is just for 'undefined' readability
  // https://stackoverflow.com/a/2647888
  return val === undefined || val === null || val === '';
}

/**
 * Check if the given string is email or not
 *
 * @param {string} val
 *
 * @returns {boolean} Representing whether the string is email or not
 */
function isEmail(val) {
  return validatorLibrary.isEmail(val);
}

/**
 * Check if the given string is email or not
 *
 * @param {string} val
 *
 * @returns {boolean} Representing whether the string is email or not
 */
function isMobile(val) {
  return validatorLibrary.isMobilePhone(val);
}

/**
 * Check whether the value privded as string only contains integer.
 *
 * @param {string} val
 *
 * @returns {boolean} true if val contains only digits
 *
 * Reference: https://stackoverflow.com/a/24457420
 */
function hasOnlyDigits(val) {
  return /^\d+$/.test(val);
}

/**
 * Check whether the value privded as string only contains non negative decimal.
 *
 * @param {string} val
 *
 * @returns {boolean} true if val is non negative decimal
 */
function isNonNegativeDecimal(val) {
  validatorLibrary.trim(val);
  // Check if field is numeric and if that is numeric then check if its greater than 0
  if (validatorLibrary.isNumeric(val) && Number(val) >= 0) {
    return true;
  }
  return false;
}

/**
 * Check whether the value privded as string only contains non positive decimal.
 *
 * @param {string} val
 *
 * @returns {boolean} true if val is non positive decimal
 */
function isNonPositiveDecimal(val) {
  validatorLibrary.trim(val);
  // Check if field is numeric and if that is numeric then check if its less than 0
  if (validatorLibrary.isNumeric(val) && Number(val) <= 0) {
    return true;
  }
  return false;
}

/**
 * Return Int ID
 *
 * @param {string} id ID passed passed from front end
 * @param {string} prefix Prefix for the ID that we have to remove
 *
 * @returns {string} ID which is Integer which corresponds to DB's id filed.
 */
function getActualIntID(id, prefix) {
  return id.substr(prefix.length);
}

/**
 * Make execution sleep for ms sec
 * NOTE: There is similar module in nodejs: https://www.npmjs.com/package/sleep
 * This module halts nodejs event loop that is not desirable.
 * Use that only for debugging
 *
 * @param {number} ms Time in mille second to wait before execution continue
 *
 * @returns {Promise} It returns the promise which gets resolved after specified time.
 */
// Implementation: https://stackoverflow.com/a/41957152
// https://stackoverflow.com/questions/14249506/how-can-i-wait-in-node-js-javascript-l-need-to-pause-for-a-period-of-time
function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * @param {string} originalString //the actual string to be masked
 * @param {string} maskText the string to be checked for masking
 * @param {string} responseString if the comparison is true the masked string which has to be sent
 */
function maskStringNoCaseSensitive(originalString, maskText, responseString) {
  // we need the case in sensitive comparison so we have added toLowerCase
  const localMaskText = maskText.toLowerCase();
  if (originalString.toLowerCase().includes(localMaskText)) return responseString;
  return originalString;
}

// ========================================================================
// DATE and TIME RELATED
// ========================================================================

/**
 * This function checks if the date passed in JSON adhers to our YYYY-MM-DD format
 *
 * @param {string} dateString //the actual string to be masked
 *
 * @returns {boolean} Representing whether the format is correct or not
 */
function isDateTimeFormat(dateString) {
  if (dateAndTime.isValid(dateString, 'YYYY-MM-DD hh:mm:ss')) {
    return true;
  }
  return false;
}

/**
 * This function checks if the date passed in JSON adhers to our YYYY-MM-DD format
 *
 * @param {string} dateString //the actual string to be masked
 *
 * @returns {boolean} Representing whether the format is correct or not
 */
function isDateFormat(dateString) {
  if (dateAndTime.isValid(dateString, 'YYYY-MM-DD')) {
    return true;
  }
  return false;
}

/**
 * Convert Standard JS Date object to Date String i.e. YYYY-MM-DD format
 *
 * @param {Date} date Standard JS Date object
 *
 * @returns {string}  date format i.e. YYYY-MM-DD
 */
// Ref: https://stackoverflow.com/a/23593099
function dateToDate(dateParam) {
  // Separate day, month and year from Date object
  let month = (dateParam.getMonth() + 1).toString();
  let day = dateParam.getDate().toString();
  const year = dateParam.getFullYear().toString();

  // Make one digit day and month to two digit.
  if (month.length < 2) {
    month = `0${month}`;
  }
  if (day.length < 2) {
    day = `0${day}`;
  }

  return `${year}-${month}-${day}`;
}

/**
 * Convert dateString to the Date format. This Date string is
 * internally passed to the Date() constructor.
 *
 * @param {string} dateString string that can be passsed to Date() constructor
 *
 * @returns {string}  date format i.e. YYYY-MM-DD
 */
function dateStringToDate(dateString) {
  const myDate = new Date(dateString);
  return dateToDate(myDate);
}

/**
 * Get Today's Date in  format
 *
 * @returns {DateFormat} Today's date in  date format i.e. YYYY-MM-DD
 */
function getFormatToday() {
  const today = new Date();
  return dateToDate(today);
}

/**
 * Get Yesterday's date in  format
 *
 * @returns {DateFormat} Yesterday's date in  date format i.e. YYYY-MM-DD
 */
function getFormatYesterday() {
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  return dateToDate(yesterday);
}

/**
 * This function checks if the time passed in JSON adhers to our HH:MM:SS format
 *
 * @param {string} dateString //the actual string to be masked
 *
 * @returns {boolean} Representing whether the format is correct or not
 */
function isTimeFormat(timeString) {
  if (dateAndTime.isValid(timeString, 'HH:mm:ss')) {
    return true;
  }
  return false;
}

/**
 * Check whether string passed as ID. It only works when prefix is 1 characters long.
 *  If prefix is multiple characters we need to change the implementation.
 *
 * @param {string} id ID given by front end
 * @param {string} prefix string prefix added to this ID representation
 *
 * @returns {boolean} Representing whether the id is valid ID or not
 */
function isValidID(id) {
  validatorLibrary.trim(id);
  // Trim the prefix D.
  const trimmedID = id.substr(1);
  // Second condition don't allow only char as prefix it needs some number(s) followed to it. For example 'E' is not allowed
  if (trimmedID !== '' && hasOnlyDigits(trimmedID)) {
    return true;
  }
  return false;
}

/**
 * Generate a random number with 'n' number of digits.
 *
 * @param {number} n Number of digits the random number should contain
 *
 * @returns {number} Return the random number with n digits
 */
function getRandomNumber(n) {
  const power = 10 ** (n - 1);
  const multiplier = 9 * power;
  const adder = power;
  return Math.floor(Math.random() * multiplier + adder);
}

// ////////////////////////////////////////////
//
//    User related checkrs
//
// ////////////////////////////////////////////

async function isUserDisabled(user) {
  const [rows] = await pool.execute('SELECT is_deactivated AS isDeactivated FROM user WHERE user_id = ?', [user.id]);
  if (rows.length !== 1) return 1;
  return rows[0].isDeactivated;
}

module.exports.isEmptyJSON = isEmptyJSON;
module.exports.isEmptyValue = isEmptyValue;
module.exports.isEmail = isEmail;
module.exports.hasOnlyDigits = hasOnlyDigits;
module.exports.isNonNegativeDecimal = isNonNegativeDecimal;
module.exports.isNonPositiveDecimal = isNonPositiveDecimal;
module.exports.getActualIntID = getActualIntID;
module.exports.sleep = sleep;
module.exports.maskStringNoCaseSensitive = maskStringNoCaseSensitive;
module.exports.isDateTimeFormat = isDateTimeFormat;
module.exports.isDateFormat = isDateFormat;
module.exports.dateToDate = dateToDate;
module.exports.dateStringToDate = dateStringToDate;
module.exports.getFormatToday = getFormatToday;
module.exports.getFormatYesterday = getFormatYesterday;
module.exports.isTimeFormat = isTimeFormat;
module.exports.isValidID = isValidID;
module.exports.getRandomNumber = getRandomNumber;
module.exports.isUserDisabled = isUserDisabled;
module.exports.isMobile = isMobile;
