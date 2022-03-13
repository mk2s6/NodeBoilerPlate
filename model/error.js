/**
 * This module deal with consistent error messages to send to client.
 * Here we define error messages and error code.
 */

// TO IMPORT: const error = require('./error');

const errMsg = {
  INTERNAL_SERVER_ERROR: 'An internal error has occurred. Please try again!',
  DATABASE_ERROR: 'An internal error has occurred. Please try again!',
};

//
// Why I have added name property which is same as name of object?
// Answer: This is to avoid programming errors, because if we don't have
// name property we have to write 'VAL_ERR_...' as this is treated as string
// By JS it will not throw error and there is possibility to make typo there
// but now we have to write errList.VAL_ERR_.. this is JS variable name
// and JS will throw error when we make typo there.

//
// NOTE:
// - Error code must be unique for all error objects.
// - Internal error is used for debugging purpose hence don't send it to client.
//
//

const errList = {
  //
  // INTERNAL SERVER ERRORS
  // These errors occurs when some request fails either authentication or authorization
  // In this case front end should redirect to Login page
  //
  // ERR_PR_ : ERROR_PROTECT_ROUTE_
  authError: {
    ERR_PR_PERMISSION_MISMATCH: {
      code: '20001',
      message: 'You are not authorized to access this resource. Please login again.',
      internalDescription: 'Role provided in token does not matched with route accessed.',
    },
    ERR_PR_INVALID_TOKEN: {
      code: '20002',
      message: 'You are not authorized to access this resource. Please login again.',
      internalDescription: 'Verify function for token provided fails. Token may be tampered with.',
    },
    ERR_PR_NO_TOKEN: {
      code: '20003',
      message: 'You are not authorized to access this resource. Please login again.',
      internalDescription: 'No token provided while accessing protected route.',
    },
    ERR_PR_TOKEN_EXPIRED: {
      code: '20004',
      message: 'You are not authorized to access this resource. Please login again..',
      internalDescription: 'Token provided while accessing the protected route has been expired.',
    },
  }, // End of authError Array

  //
  // DATABASE ERRORS
  // These error occurred when given values does not match with the value
  // present in DB or they are missing
  // ERR_<Operation>_<Description>
  //
  dbError: {
    ERR_LOGIN_USER_PASSWORD_NO_MATCH: {
      code: '30001',
      message: 'Invalid Email/Mobile/Username or Password provided.!!',
      internalDescription: 'Provided password does not match with hashed password present in DB.',
    },
    ERR_INSERT_COUNTRY_DUPLICATE_ENTRY: {
      code: '30002',
      message: 'Country you are trying to add already exists! Please check the list to continue',
      internalDescription: 'The insert query to insert the country failed as its a duplicate entry into database with the same country name',
    },
    ERR_INSERT_EMPLOYEE_DUPLICATE_ENTRY: {
      code: '30003',
      message: 'Employee with provided Email/Mobile already exists.',
      internalDescription:
        'The insert query to insert the employee failed as there is an employee who exists already with the provided email or mobile',
    },
    ERR_INSERT_STATE_DUPLICATE_ENTRY: {
      code: '30004',
      message: 'State you are trying to add already exists! Please check the list to continue',
      internalDescription: 'The insert query to insert the state failed as its a duplicate entry into database with the same country name',
    },
    ERR_INSERT_CITY_DUPLICATE_ENTRY: {
      code: '30005',
      message: 'City you are trying to add already exists! Please check the list to continue',
      internalDescription: 'The insert query to insert the city failed as its a duplicate entry into database with the same country name',
    },
    ERR_RESTAURANT_CREATE_FATAL_AFFECTED_ROWS_0: {
      code: '30006',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant insert',
    },
    ERR_USER_LOGIN_USER_DOES_NOT_EXIST: {
      code: '30007',
      message: 'Invalid Email/Mobile/Username or Password provided !',
      internalDescription: 'user is not in the user table so it returns an error status',
    },
    ERR_UPDATE_CITY_DUPLICATE_ENTRY: {
      code: '30008',
      message: 'City you are trying to add already exists! Please check the list to continue',
      internalDescription: 'The update query to update the city failed as its a duplicate entry into database with the same country name',
    },
    ERR_EMPLOYEE_CHANGE_PASSWORD_NO_MATCH: {
      code: '30009',
      message: 'Invalid Current Password provided!, Please enter correct password',
      internalDescription: 'when change password is done and the employee provided a wrong current password',
    },
    ERR_EMPLOYEE_DETAIL_NOT_IN_DB: {
      code: '30010',
      message: 'Please login again to continue!',
      internalDescription: 'User ID present in Token does not exist in DB or it has been deleted.',
    },
    ERR_INSERT_USER_DUPLICATE_ENTRY: {
      code: '30011',
      message: 'User with provided Email/Mobile already exists.',
      internalDescription: 'The insert query to insert the user failed as there is an user who exists already with the provided email or mobile',
    },
    ERR_USER_CHANGE_PASSWORD_NO_MATCH: {
      code: '30012',
      message: 'Invalid Current Password provided!, Please enter correct password',
      internalDescription: 'when change password is done and the user provided a wrong current password',
    },
    ERR_USER_DETAIL_NOT_IN_DB: {
      code: '30013',
      message: 'Please login again to continue!',
      internalDescription: 'User ID present in Token does not exist in DB or it has been deleted.',
    },
    ERR_ADMIN_USERNAME_UNAVAILABLE: {
      code: '30014',
      message: 'Username Un-Available - Already taken.',
      internalDescription: 'User ID present in Token does not exist in DB or it has been deleted.',
    },
    ERR_INSERT_RESTAURANT_DUPLICATE_ENTRY: {
      code: '30015',
      message: 'Restaurant Code, Email or Mobile number provided is already registered with a restaurant please check and provide the details.',
      internalDescription: 'Email or mobile number is already present in the db hence error',
    },
    ERR_INSERT_RESTAURANT_OWNER_DUPLICATE_ENTRY: {
      code: '30016',
      message: 'Email or Mobile number provided is already registered with an owner please check and provide the details.',
      internalDescription: 'Email or mobile number is already present in the db hence error',
    },
    ERR_RESTAURANT_OWNER_CREATE_FATAL_AFFECTED_ROWS_0: {
      code: '30017',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant OWNER insert',
    },
    ERR_INSERT_RESTAURANT_BRANCH_DUPLICATE_ENTRY: {
      code: '30018',
      message: 'Email or Mobile number provided is already registered with a branch please check and provide the details.',
      internalDescription: 'Email or mobile number is already present in the db hence error',
    },
    ERR_RESTAURANT_BRANCH_CREATE_FATAL_AFFECTED_ROWS_0: {
      code: '30019',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant OWNER insert',
    },
    ERR_RESTAURANT_ROLES_CREATE_FATAL_AFFECTED_ROWS_0: {
      code: '30020',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant OWNER insert',
    },
    ERR_RESTAURANT_ROLE_PERMISSIONS_CREATE_FATAL_AFFECTED_ROWS_0: {
      code: '30021',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant OWNER insert',
    },
    ERR_INSERT_RESTAURANT_EMPLOYEE_DUPLICATE_ENTRY: {
      code: '30022',
      message: 'Email or Mobile number provided is already registered with an employee please check and provide the details.',
      internalDescription: 'Email or mobile number is already present in the db hence error',
    },
    ERR_RESTAURANT_EMPLOYEE_CREATE_FATAL_AFFECTED_ROWS_0: {
      code: '30023',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant employee insert',
    },
    ERR_RESTAURANT_EMPLOYEE_USERNAME_CHECK_NOT_AVAILABLE: {
      code: '30024',
      message: 'Username already taken, Please choose another username.',
      internalDescription: 'Employee with the given username already exists',
    },
    ERR_RESTAURANT_EMPLOYEE_SET_PIN_FATAL_AFFECTED_ROWS_0: {
      code: '30025',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant employee pin update',
    },
    ERR_LOGIN_USER_PIN_NO_MATCH: {
      code: '30026',
      message: 'Invalid PIN provided.!',
      internalDescription: 'Provided pin does not match with hashed pin present in DB.',
    },
    ERR_RESTAURANT_EMPLOYEE_SET_USERNAME_FATAL_AFFECTED_ROWS_0: {
      code: '30027',
      message: errMsg.DATABASE_ERROR,
      internalDescription: 'Affected rows != 1 for restaurant employee username update',
    },
  }, // End of DB error Array

  //
  // INTERNAL SERVER ERRORS
  // These errors occurs when some server modules throws error
  // For example hashing module or encoding module. The operation
  // done on server which does not involve DB. This also involve some external API
  // call returned error or failed.
  //
  internalError: {
    ERR_HASH_PASSWORD: {
      code: '50001',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'Hashing a password provided by user is failing.',
    },
    ERR_INSERT_COUNTRY_NO_EXCEPTION_INSERT_ERROR: {
      code: '50002',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the country failed and there is no exception',
    },
    ERR_INSERT_COUNTRY_FAILURE: {
      code: '50003',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the country failed',
    },
    ERR_INSERT_EMPLOYEE_INSERT_FAILURE_NO_INSERT: {
      code: '50004',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the country failed',
    },
    ERR_INSERT_EMPLOYEE_INSERT_FAILURE: {
      code: '50005',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the country failed',
    },
    ERR_INSERT_STATE_NO_EXCEPTION_INSERT_ERROR: {
      code: '50006',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the state failed and there is no exception',
    },
    ERR_INSERT_STATE_FAILURE: {
      code: '50007',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the state failed',
    },
    ERR_INSERT_CITY_NO_EXCEPTION_INSERT_ERROR: {
      code: '50008',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the city failed and there is no exception',
    },
    ERR_INSERT_CITY_FAILURE: {
      code: '50009',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the city failed',
    },
    ERR_LOGIN_SELECT_THROW_EXCEPTION: {
      code: '50010',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: `while fetching the credentials for login exception generated a Database error
          or Internal error. This might have happened because of database server which might be down `,
    },
    ERR_COMPARE_PASSWORD_AND_HASH: {
      code: '50011',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'While comparing password and its hash throw.',
    },
    ERR_UPDATE_CITY_NO_EXCEPTION_UPDATE_ERROR: {
      code: '50012',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the city failed and there is no exception',
    },
    ERR_UPDATE_CITY_FAILURE: {
      code: '50013',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the city failed',
    },
    ERR_SELECT_COUNTRY_LIST_FAILURE: {
      code: '50014',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the city failed',
    },
    ERR_SELECT_STATE_LIST_FAILURE: {
      code: '50015',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the city failed',
    },
    ERR_SELECT_CITY_LIST_FAILURE: {
      code: '50016',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the city failed',
    },
    ERR_EMPLOYEE_CHANGE_PASSWORD_SELECT_FAILURE: {
      code: '50017',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: `this occurs when the employee wants to update the password
      but select query fails and returns an error`,
    },
    ERR_EMPLOYEE_DETAIL_SELECT_THROW_EXCEPTION: {
      code: '50018',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the details of the employee throws an error',
    },
    ERR_UPDATE_EMPLOYEE_UPDATE_FAILURE_NO_UPDATE: {
      code: '50019',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update query to update the details of the employee throws an error',
    },
    ERR_UPDATE_EMPLOYEE_UPDATE_FAILURE: {
      code: '50020',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update query to update the details of the employee throws an error',
    },
    ERR_INSERT_USER_INSERT_FAILURE_NO_INSERT: {
      code: '50021',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the details of the user throws an error',
    },
    ERR_INSERT_USER_INSERT_FAILURE: {
      code: '50022',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The insert query to insert the details of the user throws an error',
    },
    ERR_EMPLOYEE_CHANGE_PASSWORD_FAILURE_UPDATE_QUERY: {
      code: '50023',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update query to update the password of the employee throws an error',
    },
    ERR_EMPLOYEE_CHANGE_PASSWORD_CAN_NOT_BE_DONE: {
      code: '50024',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update can not happen as the user id does not exist in db or deleted but we have the user id in ',
    },
    ERR_USER_CHANGE_PASSWORD_FAILURE_UPDATE_QUERY: {
      code: '50025',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update query to update the password of the user throws an error',
    },
    ERR_USER_CHANGE_PASSWORD_CAN_NOT_BE_DONE: {
      code: '50026',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update can not happen as the user id does not exist in db or deleted but we have the user id in ',
    },
    ERR_USER_CHANGE_PASSWORD_SELECT_FAILURE: {
      code: '50027',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: `this occurs when the user wants to update the password
      but select query fails and returns an error`,
    },
    ERR_EMPLOYEE_UPDATE_PASSWORD_NO_UPDATE_NO_EXCEPTION: {
      code: '50028',
      message: 'Please login again to continue..',
      internalDescription: ' The employee password is not updated and there is no exception even with correct details.',
    },
    ERR_USER_UPDATE_PASSWORD_NO_UPDATE_NO_EXCEPTION: {
      code: '50029',
      message: 'Please login again to continue..',
      internalDescription: ' The user password is not updated and there is no exception even with correct details.',
    },
    ERR_UPDATE_USER_UPDATE_FAILURE_NO_UPDATE: {
      code: '50030',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update query to update the details of the user throws an error',
    },
    ERR_UPDATE_USER_UPDATE_FAILURE: {
      code: '50031',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The update query to update the details of the user throws an error',
    },
    ERR_USER_DETAIL_SELECT_THROW_EXCEPTION: {
      code: '50032',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the details of the user throws an error',
    },
    ERR_PAGINATION_LIST_GET_NUMBER_OF_PAGES_FAILURE: {
      code: '50033',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the counts for pagination throws an error',
    },
    ERR_STATE_VALIDATION_SELECT_FAILURE: {
      code: '50034',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the State for validation details throws an error',
    },
    ERR_COUNTRY_VALIDATION_SELECT_FAILURE: {
      code: '50035',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the country for validation details throws an error',
    },
    ERR_CITY_VALIDATION_SELECT_FAILURE: {
      code: '50036',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the city for validation details throws an error',
    },
    ERR_USER_LIST_SELECT_THROW_EXCEPTION: {
      code: '50037',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'The select query to select the user list for admin throws an error',
    },
    ERR_EMP_IMAGE_UPLOAD_WRONG_TYPE: {
      code: '50038',
      message: 'Only jpg/jpeg files are allowed',
      internalDescription: 'While image uploading the image type is not jpeg, jpg or png',
    },
    ERR_EMP_IMG_UPLOAD_IMAGE_WRONG_FIELD_NAME: {
      code: '50039',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'While uploading the profile image of the employee the field name from the front end is wrong',
    },
    ERR_EMP_IMG_UPLOAD_FILE_SIZE_TOO_LARGE: {
      code: '50040',
      message: 'Image size should be maximum of 3MB',
      internalDescription: 'While uploading the profile image of the employee the file size is too large',
    },
    ERR_EMP_IMG_UPLOAD_IMAGE_UNKNOWN_ERROR: {
      code: '50041',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'While uploading the profile image of the employee there is an unknown error in the process',
    },
    ERR_EMP_IMG_UPLOAD_IMAGE_FILE_NOT_SELECTED: {
      code: '50042',
      message: 'Please select a file to be uploaded',
      internalDescription: 'While uploading the profile image of the employee there is no image selected',
    },
    ERR_EMP_IMG_UPLOAD_DB_UPDATE_NO_UPDATE_NO_EXCEPTION: {
      code: '50043',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription:
        'While uploading the profile image of the employee update query for db update is executed but query returns affected rows as 0',
    },
    ERR_EMP_IMG_UPLOAD_DB_UPDATE_ERROR: {
      code: '50044',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'While uploading the profile image of the employee update query for db update throws an error',
    },
    ERR_EMP_IMG_UPLOAD_IMAGE_FILEPATH_NOT_EXIST: {
      code: '50045',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while uploading the employee image the destination file path does not exist so the FS responds with the error',
    },
    ERR_EMP_IMG_UPLOAD_IMAGE_FILE_NOT_MOVED: {
      code: '50046',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while uploading the employee image there is an error FS responds with the error',
    },
    ERR_RESTAURANT_CREATION_FAILURE: {
      code: '50047',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while INSERTING THE company there is an error in creation of the restaurant',
    },
    ERR_TRANSACTION_GET_CONNECTION_FAILURE: {
      code: '50048',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'Get Transaction connection failure',
    },
    ERR_TRANSACTION_BEGIN_TRANSACTION_FAILURE: {
      code: '50049',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'Begin Transaction connection failure',
    },
    ERR_RESTAURANT_OWNER_CREATION_FAILURE: {
      code: '50050',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while INSERTING THE company there is an error in creation of the restaurant',
    },
    ERR_RESTAURANT_BRANCH_CREATION_FAILURE: {
      code: '50051',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while INSERTING THE company there is an error in creation of the restaurant',
    },
    ERR_RESTAURANT_SELECT_LIST_FAILURE: {
      code: '50052',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while selecting restaurants list there is an error in selection',
    },
    ERR_SELECT_RESTAURANT_DETAILS_FAILURE: {
      code: '50053',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while selecting restaurants DETAILS there is an error in selection',
    },
    ERR_TRANSACTION_COMMIT_TRANSACTION_FAILURE: {
      code: '50054',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'Commit Transaction connection failure',
    },
    ERR_GENERATE_PASSWORD: {
      code: '50055',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'Generating a password provided by user is failing.',
    },
    ERR_RESTAURANT_ROLES_CREATION_FAILURE: {
      code: '50056',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while INSERTING THE company there is an error in creation roles of the restaurant',
    },
    ERR_RESTAURANT_EMPLOYEE_ROLES_CREATION_FAILURE: {
      code: '50057',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while INSERTING THE company there is an error in creation of the restaurant',
    },
    ERR_RESTAURANT_ROLE_PERMISSIONS_CREATION_FAILURE: {
      code: '50058',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while INSERTING THE company there is an error in creation of Employee role permissions the restaurant',
    },
    ERR_LOGIN_TOKEN_GENERATION_ERROR: {
      code: '50059',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: 'while LOGIN TOKEN generation failure',
    },
    ERR_EMPLOYEE_UPDATE_PASSWORD_NO_UPDATE_NO_EXCEPTION: {
      code: '50060',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: ' The employee pin is not updated and there is no exception even with correct details.',
    },
    ERR_EMPLOYEE_UPDATE_PASSWORD_ERROR: {
      code: '50061',
      message: errMsg.INTERNAL_SERVER_ERROR,
      internalDescription: ' The employee username is not updated and there is an Error.',
    },
  }, // End of Internal Error Array
};

module.exports.errMsg = errMsg;
module.exports.errList = errList;
