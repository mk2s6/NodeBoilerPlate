/* eslint-disable arrow-parens */
/* eslint-disable operator-linebreak */
/**
 * This is module which deals with validation and sanitization of input form the user.
 * This way we can separate validation logic into separate module.
 * We are using express-validator package.
 * See documentation: https://www.npmjs.com/package/express-validator
 *
 * GLOSSARY:
 * Location: refer to location from request object like body, cookies, params, header and query
 */

// NOTE:
// - isValidStrLenWithTrim This works with undefined strings too when min length is 0.

// TO IMPORT: const vs = require('../../model/validator-sanitizer');

// eslint-disable-next-line object-curly-newline
const { check, body, cookie, header, param, query, validationResult } = require('express-validator');
const PasswordValidator = require('password-validator');
const validatorLibrary = require('validator');
const hf = require('./helper-function');
const constant = require('./constant');
const error = require('./error');
const responseGenerator = require('./response-generator');
const pool = require('../database/db');

// ======================================================================
// PRIVATE API FOR THIS MODULE
// ======================================================================

// This is needed because if we pass variable from other module it does not
// recognize it as function hence we can't call it with () i.e. location() will give error
function getFunctionName(location) {
  switch (location) {
    case 'body':
      return body;
    case 'cookie':
      return cookie;
    case 'header':
      return header;
    case 'param':
      return param;
    case 'query':
      return query;
    // TODO Make default to throw error instead of checking everything
    // This is hit to performance hence we need to avoid using check always.
    // This should be done after we add tests otherwise we will have runtime errors.
    default:
      return check;
  }
}

// ======================================================================
// API RELATED TO VALIDATION CHAIN OBJECT
// ======================================================================

// SPECIFIC API FOR PROPERTY LIKE EMAIL, PASSWORD
// These should not take error message as parameter to be consistent
// across system
/**
 * Email validator which trim
 *
 * @param location
 * @param email
 *
 * @returns validation chain object of express-validator
 */
function isEmail(location, email) {
  const validator = getFunctionName(location);
  return validator(email)
    .isEmail()
    .withMessage('Please enter a valid email-id')
    .isLength({ max: 150 })
    .withMessage('Email should not exceed maximum of 150 characters length')
    .trim();
}

/**
 * If field exist then validate max length of it. Mostly used for optional field.
 *
 * @param location
 * @param field
 * @param message Custom message
 *
 * @returns validation chain object of express-validator
 */
function ifExistIsEmail(location, field) {
  const validator = getFunctionName(location);
  return validator(field)
    .custom((paramField) => {
      if (hf.isEmptyValue(paramField)) {
        return true;
      }
      validatorLibrary.trim(paramField);
      if (validatorLibrary.isEmail(paramField)) {
        return true;
      }
      return false;
    })
    .withMessage('Please enter valid email');
}

/**
 * Mobile Phone validator for Indian locale
 *
 * @param location
 * @param mobileNumber
 *
 * @returns validation chain object of express-validator
 */
function isMobile(location, mobileNumber) {
  const validator = getFunctionName(location);
  return validator(mobileNumber).isMobilePhone().withMessage('Mobile number is not valid please check if you have entered a 10 digit mobile number');
}

/**
 * If field exist then validates whether the mobile number is valid or not
 *
 * @param location
 * @param field
 *
 * @returns validation chain object of express-validator
 */
function ifExistIsMobile(location, field) {
  const validator = getFunctionName(location);
  return validator(field)
    .custom((paramField) => {
      if (hf.isEmptyValue(paramField)) {
        return true;
      }
      validatorLibrary.trim(paramField);
      if (validatorLibrary.isMobilePhone(paramField, 'en-IN')) {
        return true;
      }
      return false;
    })
    .withMessage('Please enter valid mobile number');
}

/**
 * Username validator which check whether the username provided is either email or mobile
 *
 * @param location
 * @param username
 *
 * @returns validation chain object of express-validator
 */
function isEmailOrMobileOrUsername(location, username) {
  const validator = getFunctionName(location);
  return validator(username)
    .custom((paramUsername) => {
      if (
        validatorLibrary.isEmail(paramUsername) ||
        validatorLibrary.isMobilePhone(paramUsername) ||
        validatorLibrary.isAlphanumeric(paramUsername, 'en-US', { ignore: '.' })
      ) {
        return true;
      }
      throw false;
    })
    .withMessage('Please provide a valid Username or Email-id or Mobile Number!');
}

/**
 * Check if field contain boolean value
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isUrl(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).isURL().withMessage(message);
}

/**
 * Check if field contain boolean value
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function ifExistsIsUrl(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => {
      if (hf.isEmptyValue(paramFieldName)) return true;
      return validatorLibrary.isURL(paramFieldName);
    })
    .withMessage(message);
}
/**
 * Gender validator
 *
 * @param location
 * @param gender
 *
 * @returns validation chain object of express-validator
 */
function isGender(location, gender) {
  const validator = getFunctionName(location);
  return validator(gender).isIn(['Male', 'Female']).withMessage('please provide a valid gender');
}

/**
 * Date of birth validator
 *
 * @param location
 * @param dob in date format i.e. "YYYY-MM-DD".
 *
 * @returns validation chain object of express-validator
 */
function isDOB(location, dob) {
  const validator = getFunctionName(location);
  return validator(dob)
    .custom((paramDOB) => {
      // TODO we should not allow date in future
      if (hf.isDateFormat(paramDOB) && paramDOB >= '1940-01-01') {
        return true;
      }
      return false;
    })
    .withMessage('Date of Birth is not valid. DOB should be greater than 01 Jan 1940');
}

//
// Password Validatory code
//
const schemaPassword = new PasswordValidator();
// eslint-disable-next-line newline-per-chained-call
schemaPassword.is().min(8).is().max(255).has().uppercase().has().lowercase().has().digits().has().symbols();

/**
 * Password validator: password should have uppercase, lowercase
 * and number. It should not contain spaces.
 *
 * @param location
 * @param password
 *
 * @returns validation chain object of express-validator
 */
function isPassword(location, password, message) {
  const validator = getFunctionName(location);
  return validator(password).custom((paramPassword) => {
    if (!schemaPassword.validate(paramPassword)) throw new Error(message);
    return true;
  });
}

// /**
//  * Username validator for Indian locale
//  *
//  * @param location
//  * @param username
//  *
//  * @returns validation chain object of express-validator
//  */
// function isUsername(location, username) {
//   const validator = getFunctionName(location);
//   return validator(username).length({ min: 3, max: 12 }).isAlphanumeric().withMessage('Provide a valid Username to validate');
// }

/**
 * Validates the entered role to be a valid role
 *
 * @param location
 * @param role
 *
 */
function isValidAdminRole(location, role) {
  const validator = getFunctionName(location);
  return validator(role)
    .custom(async (paramRole) => {
      const beRole = paramRole || null;
      try {
        const [rows] = await pool.execute('SELECT role FROM admin_roles WHERE role = ?', [beRole]);
        if (rows.length === 1) return true;
        throw false;
      } catch (e) {
        const beValidateCountrySelectError = error.errList.internalError.ERR_COUNTRY_VALIDATION_SELECT_FAILURE;
        // eslint-disable-next-line no-undef
        return res.status(500).send(responseGenerator.internalError(beValidateCountrySelectError));
      }
    })
    .withMessage('Please choose a valid role for admin');
}

/**
 * Validates the entered role to be a valid role
 *
 * @param location
 * @param role
 *
 */
function isValidEmployeeRole(location, role) {
  const validator = getFunctionName(location);
  return validator(role)
    .custom(async (paramRole, { req }) => {
      const beRole = paramRole || null;
      try {
        const [rows] = await pool.execute('SELECT emp_role FROM employee_roles WHERE emp_role = ? AND emp_role_res_id = ?', [beRole, req.user.resId]);
        if (rows.length === 1) return true;
        throw false;
      } catch (e) {
        const beValidateCountrySelectError = error.errList.internalError.ERR_COUNTRY_VALIDATION_SELECT_FAILURE;
        // eslint-disable-next-line no-undef
        return res.status(500).send(responseGenerator.internalError(beValidateCountrySelectError));
      }
    })
    .withMessage('Please choose a valid role for employee');
}

/**
 * Validates the entered country to be a valid country
 *
 * @param location
 * @param country
 *
 */
function isValidCountry(location, country) {
  const validator = getFunctionName(location);
  return validator(country)
    .custom(async (paramCountry) => {
      const beCountry = paramCountry || null;
      try {
        const [rows] = await pool.execute('SELECT country FROM country WHERE country = ?', [beCountry]);
        if (rows.length === 1) return true;
        throw false;
      } catch (e) {
        const beValidateCountrySelectError = error.errList.internalError.ERR_COUNTRY_VALIDATION_SELECT_FAILURE;
        // eslint-disable-next-line no-undef
        return res.status(500).send(responseGenerator.internalError(beValidateCountrySelectError));
      }
    })
    .withMessage('Please choose a valid country');
}

/**
 * Validates the entered state to be a valid state
 *
 * @param location
 * @param state
 *
 */
function isValidState(location, state) {
  const validator = getFunctionName(location);
  return validator(state)
    .custom(async (paramState) => {
      const beState = paramState || null;
      try {
        const [rows] = await pool.execute('SELECT state FROM state WHERE state = ?', [beState]);
        if (rows.length === 1) return true;
        throw false;
      } catch (e) {
        // console.log(e);
        const beValidateStateSelectError = error.errList.internalError.ERR_STATE_VALIDATION_SELECT_FAILURE;
        // eslint-disable-next-line no-undef
        return res.status(500).send(responseGenerator.internalError(beValidateStateSelectError));
      }
    })
    .withMessage('Please choose a valid state');
}

/**
 * Validates the entered state to be a valid state
 *
 * @param location
 * @param city
 *
 */
function isValidCurrencyCode(location, cc) {
  const validator = getFunctionName(location);
  return validator(cc)
    .custom(async (paramCC) => {
      const beCC = paramCC || null;
      try {
        const [rows] = await pool.execute('SELECT cc_code FROM currency_codes WHERE cc_code = ?', [beCC]);
        // console.log(rows);
        if (rows.length >= 1) return true;
        throw false;
      } catch (e) {
        const beValidateStateSelectError = error.errList.internalError.ERR_CITY_VALIDATION_SELECT_FAILURE;
        // eslint-disable-next-line no-undef
        return res.status(500).send(responseGenerator.internalError(beValidateStateSelectError));
      }
    })
    .withMessage('Please choose a valid city');
}

/**
 * Validates the entered state to be a valid state
 *
 * @param location
 * @param city
 *
 */
function isValidCity(location, city) {
  const validator = getFunctionName(location);
  return validator(city)
    .custom(async (paramCity) => {
      const beState = paramCity || null;
      try {
        const [rows] = await pool.execute('SELECT city FROM city WHERE city = ?', [beState]);
        // console.log(rows);
        if (rows.length >= 1) return true;
        throw false;
      } catch (e) {
        const beValidateStateSelectError = error.errList.internalError.ERR_CITY_VALIDATION_SELECT_FAILURE;
        // eslint-disable-next-line no-undef
        return res.status(500).send(responseGenerator.internalError(beValidateStateSelectError));
      }
    })
    .withMessage('Please choose a valid city');
}

/**
 * Order ID validator Which require format 'E****', these **** must be integer
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function isEmployeeID(location, fieldName) {
  const message = `Invalid Employee ID. Please provide valid Employee ID'`;
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => {
      if (hf.isValidID(paramFieldName)) return true;
      throw new Error(message);
    })
    .withMessage(message);
}

/**
 * Optional User ID validator, if User ID is specified, then it should in format 'E****', these **** must be integer
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function ifExistIsEmployeeID(location, fieldName) {
  const message = `Invalid Employee ID. Please provide valid Employee ID'`;
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom(async (paramFieldName) => {
      if (hf.isEmptyValue(paramFieldName)) {
        return true;
      }
      if (hf.isValidID(paramFieldName)) return true;
      throw false;
    })
    .withMessage(message);
}

/**
 * Order ID validator Which require format 'E****', these **** must be integer
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function isUserID(location, fieldName) {
  const message = `Invalid User ID. Please provide user ID as '${constant.idPrefix.USER}****'`;
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => hf.isValidID(paramFieldName, constant.idPrefix.USER))
    .withMessage(message);
}

/**
 * Optional User ID validator, if User ID is specified, then it should in format 'E****', these **** must be integer
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function ifExistIsUserID(location, fieldName) {
  const message = `Invalid User ID. Please provide user ID as '${constant.idPrefix.USER}****'`;
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => {
      if (hf.isEmptyValue(paramFieldName)) {
        return true;
      }
      return hf.isValidID(paramFieldName, constant.idPrefix.USER);
    })
    .withMessage(message);
}

/**
 * Order ID validator Which require format 'E****', these **** must be integer
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function isProjectID(location, fieldName) {
  const message = `Invalid Project ID. Please provide project ID as '${constant.idPrefix.PROJECT}****'`;
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => hf.isValidID(paramFieldName, constant.idPrefix.PROJECT))
    .withMessage(message);
}

/**
 * Optional Project ID validator, if Project ID is specified, then it should in format 'E****', these **** must be integer
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function ifExistIsProjectID(location, fieldName) {
  const message = `Invalid Project ID. Please provide project ID as '${constant.idPrefix.PROJECT}****'`;
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => {
      if (hf.isEmptyValue(paramFieldName)) {
        return true;
      }
      return hf.isValidID(paramFieldName, constant.idPrefix.PROJECT);
    })
    .withMessage(message);
}

/**
 * Check if field is valid Amount.
 * Only two digits after decimal point is allowed.
 * We do not allow any separator like ','
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isAmount(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .isCurrency({ allow_negatives: false }) // To check if it is valid currency
    .isFloat() // To not allow separator ',' as it make DB inconsistent
    .withMessage(message);
}

/**
 * username validator which require username
 *
 * @param location
 * @param username
 *
 * @returns validation chain object of express-validator
 */
function isUsername(location, username) {
  const message = 'Username contains only characters and Numerics !';
  const validator = getFunctionName(location);
  // eslint-disable-next-line newline-per-chained-call
  return validator(username).trim().isAlphanumeric('en-US', { ignore: '.' }).withMessage(message).isLength({ min: 3, max: 100 }).withMessage(message);
}

/**
 * PINCODE validator which require pincode should be exactly 6 characters and numeric
 *
 * @param location
 * @param pincode
 *
 * @returns validation chain object of express-validator
 */
function isPINCODE(location, pincode) {
  const message = 'Characters are not allowed in zip code, zipcode contains only numeric digits!';
  const validator = getFunctionName(location);
  // eslint-disable-next-line newline-per-chained-call
  return validator(pincode).trim().isLength({ min: 4, max: 10 }).withMessage(message).isNumeric().withMessage(message);
}

/**
 * Optional PINCODE validator, if PINCODE is specified then it should be exactly 6 characters and numeric
 *
 * @param location
 * @param pincode
 *
 * @returns validation chain object of express-validator
 */
function ifExistIsPINCODE(location, pincode) {
  const message = 'Invalid Pincode Provided, it should be numeric and exactly 6 characters long.';
  const validator = getFunctionName(location);
  return validator(pincode)
    .custom((paramPincode) => {
      if (hf.isEmptyValue(paramPincode)) {
        return true;
      }
      validatorLibrary.trim(paramPincode);
      if (validatorLibrary.isNumeric(paramPincode) && validatorLibrary.isLength(paramPincode, { min: 6, max: 6 })) {
        return true;
      }
      return false;
    })
    .withMessage(message);
}

// ==============================================================================
// GENERIC API APPLICABLE FOR ANY PROPERTY
// ==============================================================================

// NOTE:
// - These should take error message as parameter as
//   we don't know why these are used for.

/**
 * Check if field exist i.e. not undefined
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isExist(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).exists().withMessage(message);
}

/**
 * First trim white spaces on both side and then check
 * if field contain exactly exactLength number of character
 *
 * @param location
 * @param fieldName
 * @param exactLength
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isExactLenWithTrim(location, fieldName, exactLength, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).trim().isLength({ min: exactLength, max: exactLength }).withMessage(message);
}

/**
 * First trim white spaces on both side and then check
 * if field contain minimum of minLength character
 *
 * @param location
 * @param fieldName
 * @param minLength
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isMinLenWithTrim(location, fieldName, minLength, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).trim().isLength({ min: minLength }).withMessage(message);
}

/**
 * First trim white spaces on both side and then check
 * if field contain maximum of maxLength character
 *
 * @param location
 * @param fieldName
 * @param maxLength
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isMaxLenWithTrim(location, fieldName, maxLength, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).trim().isLength({ max: maxLength }).withMessage(message);
}

/**
 * First trim white spaces on both side and then check
 * if field contain minimum of minLength and maximum of maxLength characters.
 * NOTE: This works with undefined strings too when min length is 0.
 *
 * @param location
 * @param fieldName
 * @param minLength
 * @param maxLength
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isValidStrLenWithTrim(location, fieldName, minLength, maxLength, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).trim().isLength({ min: minLength, max: maxLength }).withMessage(message);
}

/**
 * Check if field contains only numbers which has +, - or . as symbol in it
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isNumeric(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).isNumeric().withMessage(message);
}

/**
 * Check if field contains only numbers empty strings are allowed
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function ifExistsIsNumeric(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramField) => {
      if (hf.isEmptyValue(paramField)) {
        return true;
      }
      validatorLibrary.trim(paramField);
      if (validatorLibrary.isNumeric(paramField)) {
        return true;
      }
      return false;
    })
    .withMessage(message);
}

/**
 * Check if field contains only non negative decimals. This does not allow exponential form such as '1e10' (actual number 100)
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isNonNegativeNumeric(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => hf.isNonNegativeDecimal(paramFieldName))
    .withMessage(message);
}

/**
 * Check if field exists then contains only non negative decimals. This does not allow exponential form such as '1e10' (actual number 100)
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function ifExistsIsNonNegativeNumeric(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => {
      if (hf.isEmptyValue(paramFieldName)) {
        return true;
      }
      return hf.isNonNegativeDecimal(paramFieldName);
    })
    .withMessage(message);
}

/**
 * Check if field contains only non positive decimals. This does not allow exponential form such as '1e10' (actual number 100)
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isNonPositiveNumeric(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => hf.isNonPositiveDecimal(paramFieldName))
    .withMessage(message);
}

/**
 * Check if field exists then contains only non positive decimals. This does not allow exponential form such as '1e10' (actual number 100)
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function ifExistsIsNonPositiveNumeric(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName)
    .custom((paramFieldName) => {
      if (hf.isEmptyValue(paramFieldName)) {
        return true;
      }
      return hf.isNonPositiveDecimal(paramFieldName);
    })
    .withMessage(message);
}

/**
 * Check if field is integer and within given range [min, max] inclusive
 *
 * @param location
 * @param fieldName
 * @param minValue Minimum allowed value
 * @param maxValue Maximum allowed value
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isWithinRange(location, fieldName, minValue, maxValue, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).isInt({ min: minValue, max: maxValue }).withMessage(message);
}

/**
 * Check if field is in array of allowed values
 *
 * @param {string} location
 * @param {string} fieldName
 * @param {Array} values array of allowed values
 * @param {string} message Message to be displayed to client
 *
 * @returns validation chain object of express-validator
 */
function isIn(location, fieldName, values, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).isIn(values).withMessage(message);
}

/**
 * Check if field contain boolean value
 *
 * @param location
 * @param fieldName
 * @param message
 *
 * @returns validation chain object of express-validator
 */
function isBoolean(location, fieldName, message) {
  const validator = getFunctionName(location);
  return validator(fieldName).isBoolean().withMessage(message);
}

/**
 * Date validator to check if the date provided is of correct ARS date format (YYYY-MM-DD)
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD"
 *
 * @returns validation chain object of express-validator
 */
function isValidDate(location, date, message) {
  const validator = getFunctionName(location);
  return validator(date)
    .custom((paramDate) => {
      if (hf.isDateFormat(paramDate)) {
        return true;
      }
      return false;
    })
    .withMessage(message);
}

/**
 * Date validator to check if the date provided is of correct ARS date format (YYYY-MM-DD)
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD"
 *
 * @returns validation chain object of express-validator
 */
function ifExistsIsValidDate(location, date) {
  const validator = getFunctionName(location);
  return validator(date)
    .custom((paramDate) => {
      if (paramDate === null || paramDate === undefined || hf.isDateFormat(paramDate)) {
        return true;
      }
      return false;
    })
    .withMessage('Invalid Date Format. Please specify the date in YYYY-MM-DD format');
}

/**
 * Date validator to check if the date provided is of correct ARS date format (YYYY-MM-DD HH:MM:SS)
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD HH:MM:SS"
 *
 * @returns validation chain object of express-validator
 */
function isValidDateTime(location, dateTime) {
  const validator = getFunctionName(location);
  return validator(dateTime)
    .custom((paramDateTime) => {
      if (hf.isDateTimeFormat(paramDateTime)) {
        return true;
      }
      return false;
    })
    .withMessage('Invalid Date Format. Please specify the dateTime in YYYY-MM-DD HH:MM:SS format');
}

/**
 * Date validator to check if the dateTime provided is of correct ARS dateTime format (YYYY-MM-DD HH:MM:SS)
 *
 * @param location
 * @param dateTime Format "3012-04-23". This is  Date format "YYYY-MM-DD HH:MM:SS"
 *
 * @returns validation chain object of express-validator
 */
function ifExistsIsValidDateTime(location, dateTime) {
  const validator = getFunctionName(location);
  return validator(dateTime)
    .custom((paramDateTime) => {
      if (paramDateTime === null || paramDateTime === undefined || paramDateTime === '' || hf.isDateTimeFormat(paramDateTime)) {
        return true;
      }
      return false;
    })
    .withMessage('Invalid Date Format. Please specify the dateTime in YYYY-MM-DD HH:MM:SS format');
}

/**
 * Time validator to check if the time provided is in correct ARS time format (HH:mm:ss)
 *
 * @param location
 * @param time Format "20:30:05". This is  Time format "HH:mm:ss"
 *
 * @returns validation chain object of express-validator
 */
function isValidTime(location, time) {
  const validator = getFunctionName(location);
  return validator(time)
    .custom((paramTime) => {
      if (hf.isTimeFormat(paramTime)) {
        return true;
      }
      return false;
    })
    .withMessage('Invalid Time Format. Please specify the time in 24-hour clock with HH:mm:ss format.');
}

/**
 * Date validator for future date.
 * NOTE: This does not accept today as future date
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD"
 *
 * @returns validation chain object of express-validator
 */
function isValidFutureDateTodayNotAllowed(location, date) {
  const validator = getFunctionName(location);
  return validator(date)
    .custom((paramDate) => {
      if (!hf.isDateFormat(paramDate) || paramDate <= hf.getFormatToday()) {
        return false;
      }

      return true;
    })
    .withMessage('Please specify valid date in future. Today is not allowed.');
}

/**
 * Date validator for future date.
 * NOTE: Accept today as future date
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD"
 *
 * @returns validation chain object of express-validator
 */
function isValidFutureDateTodayAllowed(location, date) {
  const validator = getFunctionName(location);
  return validator(date)
    .custom((paramDate) => {
      if (!hf.isDateFormat(paramDate) || paramDate < hf.getFormatToday()) {
        return false;
      }
      return true;
    })
    .withMessage('Please specify valid date in future.');
}

/**
 * Date validator for past date
 * NOTE: This allow today's date as past date
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD"
 *
 * @returns validation chain object of express-validator
 */
function isValidPastDateTodayAllowed(location, date) {
  const validator = getFunctionName(location);
  return validator(date)
    .custom((paramDate) => {
      if (!hf.isDateFormat(paramDate) || paramDate > hf.getFormatToday()) {
        return false;
      }
      return true;
    })
    .withMessage('Please specify valid date in past.');
}

/**
 * @deprecated
 *
 * Date validator for past date
 * NOTE: This allow does not allow today's date as past date
 *
 * @param location
 * @param date Format "3012-04-23". This is  Date format "YYYY-MM-DD"
 *
 * @returns validation chain object of express-validator
 */
function isValidPastDateTodayNotAllowed(location, date) {
  const validator = getFunctionName(location);
  return validator(date)
    .custom((paramDate) => {
      if (!hf.isDateFormat(paramDate) || paramDate >= hf.getFormatToday()) {
        return false;
      }
      return true;
    })
    .withMessage('Please specify valid date in past. Today is not allowed.');
}

// ======================================================================
// API RELATED TO VALIDATION RESULT OBJECT
// ======================================================================

/**
 * Return validation results object created after validation checks completes
 *
 * @param object Object on which we ran validation logic (Mostly Request object)
 *
 * @returns validation result object of express-validator
 */
function getValidationResult(object) {
  return validationResult(object);
}

// eslint-disable-next-line consistent-return
function returnValidations(req, res, next) {
  const errors = getValidationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).send(responseGenerator.validationError(errors));
  }
  next();
}

// ======================================================================
// API RELATED TO SANITIZATION
// ======================================================================
/**
 * Trim white spaces on both side and then check
 * if field contain minimum of minLength character
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function trim(location, fieldName) {
  const validator = getFunctionName(location);
  return validator(fieldName).trim();
}

/**
 * Removes the white spaces from the input
 *
 * @param location
 * @param fieldName
 *
 * @returns validation chain object of express-validator
 */
function removeSpaces(location, fieldName) {
  const validator = getFunctionName(location);
  return validator(fieldName).blacklist(' ');
}

/**
 * Export functions logic which should be available outside this module.
 */
module.exports.isEmail = isEmail;
module.exports.ifExistIsEmail = ifExistIsEmail;
module.exports.isMobile = isMobile;
module.exports.ifExistIsMobile = ifExistIsMobile;
module.exports.isEmailOrMobileOrUsername = isEmailOrMobileOrUsername;
module.exports.isUrl = isUrl;
module.exports.ifExistsIsUrl = ifExistsIsUrl;
module.exports.returnValidations = returnValidations;
module.exports.isGender = isGender;
module.exports.isDOB = isDOB;
module.exports.isPassword = isPassword;
module.exports.isValidCountry = isValidCountry;
module.exports.isValidState = isValidState;
module.exports.isValidCurrencyCode = isValidCurrencyCode;
module.exports.isValidCity = isValidCity;
module.exports.isAmount = isAmount;
module.exports.isUsername = isUsername;
module.exports.isPINCODE = isPINCODE;
module.exports.isValidAdminRole = isValidAdminRole;
module.exports.isValidEmployeeRole = isValidEmployeeRole;
module.exports.ifExistIsPINCODE = ifExistIsPINCODE;
module.exports.isExist = isExist;
module.exports.isExactLenWithTrim = isExactLenWithTrim;
module.exports.isMinLenWithTrim = isMinLenWithTrim;
module.exports.isMaxLenWithTrim = isMaxLenWithTrim;
module.exports.isValidStrLenWithTrim = isValidStrLenWithTrim;
module.exports.isNumeric = isNumeric;
module.exports.ifExistsIsNumeric = ifExistsIsNumeric;
module.exports.isEmployeeID = isEmployeeID;
module.exports.ifExistIsEmployeeID = ifExistIsEmployeeID;
module.exports.isUserID = isUserID;
module.exports.ifExistIsUserID = ifExistIsUserID;
module.exports.isProjectID = isProjectID;
module.exports.ifExistIsProjectID = ifExistIsProjectID;
module.exports.isNonNegativeNumeric = isNonNegativeNumeric;
module.exports.ifExistsIsNonNegativeNumeric = ifExistsIsNonNegativeNumeric;
module.exports.isNonPositiveNumeric = isNonPositiveNumeric;
module.exports.ifExistsIsNonPositiveNumeric = ifExistsIsNonPositiveNumeric;
module.exports.getValidationResult = getValidationResult;
module.exports.isWithinRange = isWithinRange;
module.exports.isIn = isIn;
module.exports.isBoolean = isBoolean;
module.exports.isValidDateTime = isValidDateTime;
module.exports.ifExistsIsValidDateTime = ifExistsIsValidDateTime;
module.exports.isValidDate = isValidDate;
module.exports.ifExistsIsValidDate = ifExistsIsValidDate;
module.exports.isValidTime = isValidTime;
module.exports.isValidFutureDateTodayNotAllowed = isValidFutureDateTodayNotAllowed;
module.exports.isValidFutureDateTodayAllowed = isValidFutureDateTodayAllowed;
module.exports.isValidPastDateTodayNotAllowed = isValidPastDateTodayNotAllowed;
module.exports.isValidPastDateTodayAllowed = isValidPastDateTodayAllowed;
module.exports.trim = trim;
module.exports.removeSpaces = removeSpaces;
