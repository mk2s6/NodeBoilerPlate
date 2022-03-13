/**
 * Here we define constants used in our web application at backend only.
 * These constants are not needed in front end.
 */

// TO IMPORT: const constant = require('./constant');

/**
 * List of Error Types we have
 */
const errType = {
  VALIDATION_ERROR: 0,
  INTERNAL_ERROR: 1,
  DB_ERROR: 2,
  AUTH_ERROR: 3, // Frontend should redirect to Login page
};

/**
 * email verified code
 */
const emailVerifiedCode = {
  CODE: 1,
  DEFAULT: 0,
};

/**
 * Default image location
 */
const defaultImageLocation = {
  DEFAULT: '/some/image',
};

/**
 * List of constant related to JWT
 */
const TOKEN_NAME = 'x-id-token';
const tokenType = {
  ADMIN: 'adm', // Company Admin
  EMPLOYEE: 'emp', // Employee
  USER: 'usr',
  MK2S_ADMIN: 'MK2S',
  RESTAURANT_OWNER: 'onr',
};

const idPrefix = {
  EMPLOYEE: 'E',
  USER: 'U',
  HOTEL: 'H',
  ADMIN: 'AD',
  OWNER: 'O',
};

/**
 * Permission for an company employee
 */
const permissions = {
  EMPLOYEE: 'Employee',
  PAYMENT: 'payment',
  ONBOARDING: 'onboarding',
};

/**
 * Permission level constants
 */
const LEVELS = {
  READ: 1,
  UPDATE: 2,
  INSERT: 3,
  DELETE: 4,
};

/**
 * List of available employee Roles
 */
const roles = {
  ADMIN: 'Admin',
  EMPLOYEE: 'Employee',
  USER: 'User',
  EXECUTIVE: 'Executive',
  OWNER: 'Owner',
};

/**
 * Email verification response string
 */
const emailVerificationRespString = {
  SUCCESS: 'Email verification sent, Please check your email.!',
  FAILURE: 'Email verification failed, please proceed with email verification manually',
};

/**
 * Month Names array helpful when we want to get monthName from date.getMonth()
 */
const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

/**
 * Order status
 */
// const orderStatus = {
//   COMPLETED: 'Completed',
//   PENDING: 'Pending',
//   REJECTED: 'Rejected',
// };

/**
 * Notification Status
 */
const notificationStatus = {
  NEW: 'New',
  READ: 'Read',
  UNREAD: 'Unread',
};

/**
 * Project Status
 */
const projectStatus = {
  NEW: 'New',
  INPROGRESS: 'In-Progress',
  ARCHIVED: 'Archived',
  COMPLETED: 'Completed',
};

const userImageStorageBaseLocation = {
  DEFAULT: 'assets\\img\\profile\\user\\',
  PATH: '/assets/img/profile/user/',
};

// /**
//  * Notification Type
//  */
// const empNotificationType = {
//   ENQUIRY: 'Enquiry',
//   TASK: 'Task',
// };

// /**
//  * Email subjects
//  */
// const emailSubject = {
//   RESET_PASSWORD: 'Reset password link for TMS',
//   EMAIL_VERIFICATION: 'Email verification for TMS',
//   ENQUIRY_FOLLOWUP: 'FollowUps Pending for today',
// };

/**
 * Strings constant we are sending as response for validator and sanitizers middleware
 */
const validatorResponseStrings = {
  LOGIN_PWD_RESPONSE: 'Please provide a valid password!',
  USER_REGISTER_PASSWORD_RESPONSE: `Password should contain uppercase, lowercase and numeric characters.
  It must be at least 8 characters long.`,
  EMPLOYEE_REGISTER_PASSWORD_RESPONSE: `Password should contain uppercase, lowercase, numbers and symbol.
   It must be at least 8 characters long.`,
};

const IMG_EXTENSION = '.jpg';

// ============================================
// For TESTING ONLY
// ============================================
/**
 * Time taken by beforeAll function for its setup including DB setup
 * and some other work.
 */
const testTimeout = {
  beforeAll: 10000,
  afterAll: 10000,
};

module.exports.errType = errType;
module.exports.emailVerifiedCode = emailVerifiedCode;
module.exports.TOKEN_NAME = TOKEN_NAME;
module.exports.tokenType = tokenType;
module.exports.idPrefix = idPrefix;
module.exports.roles = roles;
module.exports.LEVELS = LEVELS;
module.exports.permissions = permissions;
module.exports.validatorResponseStrings = validatorResponseStrings;
module.exports.emailVerificationRespString = emailVerificationRespString;
module.exports.monthNames = monthNames;
module.exports.defaultImageLocation = defaultImageLocation;
module.exports.notificationStatus = notificationStatus;
module.exports.projectStatus = projectStatus;
module.exports.IMG_EXTENSION = IMG_EXTENSION;
module.exports.userImageStorageBaseLocation = userImageStorageBaseLocation;
// module.exports.notificationStatus = notificationStatus;
// module.exports.empNotificationType = empNotificationType;
// module.exports.emailSubject = emailSubject;

// Testing related exports
module.exports.testTimeout = testTimeout;
