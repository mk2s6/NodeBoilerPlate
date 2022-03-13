/* eslint-disable linebreak-style */
const express = require('express');
const auth = require('../../model/auth');
const logger = require('../../model/logger');
const vs = require('../../model/validator-sanitizer');
const responseGenerator = require('../../model/response-generator');
const constant = require('../../model/constant');
const db = require('./db-admin');
const error = require('../../model/error');

const router = express.Router();

/**
 * @api {get} /admin/validate/username/:username Validate username for available usernames
 * @apiPrivate
 * @apiVersion 1.0.0
 * @apiGroup Admins
 * @apiName Validate Admin Username
 * @apiDescription Route for checking available usernames for admin
 * @apiPermission none
 *
 * @apiParam {String} username Username for Admin
 */
router.get('/validate/username/:username', [vs.isUsername('path', 'username')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['username'];
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  try {
    const [rows] = await db.validateUsername(req.params.username);
    if (!rows[0].isAvailable) {
      return res
        .status(200)
        .send(responseGenerator.success('Validate Username', 'Availability of username for admin', [{ isAvailable: !rows[0].isAvailable }]));
    }
    // 'Validate Username', 'Username Un-Available -  Already Taken', [{ isAvailable: !rows[0].isAvailable }])
    return res.status(400).send(responseGenerator.dbError(error.errList.dbError.ERR_ADMIN_USERNAME_UNAVAILABLE));
  } catch (e) {
    logger.error(e.message, { error: { name: e.name, message: e.message, stack: e.stack }, ...req.logger_meta });
    const responseUnableToCompareHash = responseGenerator.internalError(error.errList.internalError.ERR_COMPARE_PASSWORD_AND_HASH);
    return res.status(400).send(responseUnableToCompareHash);
  }
});

/**
 * @api {post} /admin/login Admin Login
 * @apiPrivate
 * @apiVersion 1.0.0
 * @apiGroup Admins
 * @apiName Admin Login
 * @apiDescription Route for Company Admin login action.
 * @apiPermission none
 *
 * @apiParam {String} username Mobile or Email of Admin
 * @apiParam {String} password Account password.
 *
 * @apiParamExample {json} Sample-Request
 * {
 *   "username": "admin1@fsjars.com",
 *   "password": "Qwerty12$"
 * }
 *
 * @apiSuccessExample {json} Success-Response
 * {
 *     "data": {
 *         "kind": "MK2S LLC - Admin login",
 *         "description": "Login Successful!!!",
 *         "items": [
 *             {
 *                 "id": "AD3",
 *                 "name": "Test Admin"
 *             }
 *         ]
 *     }
 * }
 *
 * @apiErrorExample {json} Validation-Error
 * HTTP/1.1 422 Un-Processable Entity
 * {
 *    "type": 0,
 *    "code": "",
 *    "message": "Validation failure.",
 *    "errors": [
 *        {
 *            "message": "Please provide valid a email-id or a phone number as the username",
 *            "field": "username",
 *            "location": "body"
 *        },
 *        {
 *            "message": "Login Failed: Invalid Email/Mobile or Password provided",
 *            "field": "password",
 *            "location": "body"
 *        }
 *    ]
 * }
 *
 * @apiErrorExample {json} Invalid-Credentials
 * HTTP/1.1 400 Bad Request
 * {
 *     "type": 2,
 *     "code": "30003",
 *     "message": "Invalid Username or Password provided !",
 *     "errors": []
 * }
 */
router.post(
  '/login',
  [
    // This comment is needed for proper formatting by prettier
    vs.isEmailOrMobileOrUsername('body', 'username'),
    vs.isPassword('body', 'password', constant.validatorResponseStrings.USER_LOGIN_PWD_RESPONSE),
  ],
  async (req, res) => {
    const bePassword = req.body.password;
    const beUsername = req.body.username;

    try {
      const [rows] = await db.getLoginDetails(beUsername);
      // User exist in DB
      if (rows.length === 1) {
        // Verify pwd
        let isValidPwd;
        try {
          isValidPwd = await auth.verifyPassword(bePassword, rows[0].password);
        } catch (e) {
          // Unable to compare hash and Password
          logger.error(e.message, { error: { name: e.name, message: e.message, stack: e.stack }, ...req.logger_meta });
          const responseUnableToCompareHash = responseGenerator.internalError(error.errList.internalError.ERR_COMPARE_PASSWORD_AND_HASH);
          return res.status(400).send(responseUnableToCompareHash);
        }
        if (!isValidPwd) {
          const responsePasswordNoMatch = responseGenerator.dbError(error.errList.dbError.ERR_LOGIN_USER_PASSWORD_NO_MATCH);
          return res.status(400).send(responsePasswordNoMatch);
        }
        const token = auth.genAuthToken({
          id: rows[0].id,
          token_type: constant.tokenType.MK2S_ADMIN,
          role: rows[0].role,
        });
        // console.log(token);
        const items = [{ id: constant.idPrefix.ADMIN + rows[0].id, name: rows[0].name }];
        return res
          .status(200)
          .header(constant.TOKEN_NAME, token)
          .send(responseGenerator.success('MK2S LLC - Admin login', 'Login Successful!!!', items));
      }
      // User does not exist in DB
      const responseUserNotExist = responseGenerator.dbError(error.errList.dbError.ERR_USER_LOGIN_USER_DOES_NOT_EXIST);
      return res.status(400).send(responseUserNotExist);
    } catch (e) {
      logger.error(e.message, { error: { name: e.name, message: e.message, stack: e.stack }, ...req.logger_meta });
      const responseExceptionInSelect = responseGenerator.internalError(error.errList.internalError.ERR_LOGIN_SELECT_THROW_EXCEPTION);
      return res.status(500).send(responseExceptionInSelect);
    }
  },
);

/**
 * @api {post} /admin/register Register route for admin
 * @apiPrivate
 * @apiVersion 1.0.0
 * @apiGroup Admins
 * @apiName Register route for admin
 * @apiDescription Route for registering an admin - An executive of MK2S_LLC
 *
 * @apiBody {String{3..50}} name Name of admin
 * @apiBody {String{3..12}} username Username for the admin
 * @apiBody {String} gender Gender of admin.
 * @apiBody {String} password Password of admin
 * @apiBody {String} email Email of the admin
 * @apiBody {Number} phone phone number of the admin
 * @apiBody {Date} dob Date of birth admin
 * @apiBody {Date} doj Date of Joining
 * @apiBody {String} role Role of admin
 * @apiBody {String{3..50}} address Address of the admin
 * @apiBody {String} city City of the admin
 * @apiBody {String} state State of the admin
 * @apiBody {String} country Country of the admin
 * @apiBody {Number} pincode Pincode of the address of admin
 *
 * @apiParamExample {json} Sample-Request
 * {
 *     "name" : "Test Admin",
 *     "username" : "admin",
 *     "gender" : "Male",
 *     "password" : "Qwerty12$",
 *     "dob" : "1998-05-21",
 *     "doj" : "2021-02-21",
 *     "email" : "sivakusi.12@gmail.com",
 *     "phone" : "7842487859",
 *     "address" : "test address",
 *     "city" : "Chittoor",
 *     "role" : "Owner",
 *     "state" : "Andhra Pradesh",
 *     "country" : "India",
 *     "pincode" : "517419"
 * }
 * @apiSuccessExample {json} Success-Response
 * {
 *     "data": {
 *         "kind": "Admin register",
 *         "description": "Admin registered successfully",
 *         "items": [
 *             {
 *                 "id": "U3",
 *                 "name": "Test Admin",
 *                 "username": "admin",
 *                 "gender": "Male",
 *                 "email": "sivakusi.12@gmail.com",
 *                 "phone": "7842487859",
 *                 "dob": "1998-05-21",
 *                 "address": "test address",
 *                 "city": "Chittoor",
 *                 "state": "Andhra Pradesh",
 *                 "country": "India",
 *                 "pincode": "517419",
 *                 "role": "Owner",
 *                 "dateOfJoining": "2021-02-21"
 *             }
 *         ]
 *     }
 * }
 *
 * @apiErrorExample {json} Validation-Error
 * HTTP/1.1 422 Un-Processable Entity
 *
 * @apiErrorExample {json} Internal-Error
 * HTTP/1.1 400 Bad Request
 * {
 *     "type": 1,
 *     "code": "50156",
 *     "message": "An internal error has occurred. Please try again!",
 *     "errors": []
 * }
 *
 * @apiErrorExample {json} Duplicate-Details
 * HTTP/1.1 400 Bad Request
 * {
 *     "type": 2,
 *     "code": "30011",
 *     "message": "User with provided Email/phone already exists.",
 *     "errors": []
 * }
 *
 * @apiErrorExample {json} Authentication-Error
 * HTTP/1.1 400 Bad Request
 * {
 *     "type": 3,
 *     "code": "20002",
 *     "message": "You are not authorized to access this resource. Please login again.",
 *     "errors": []
 * }
 */
router.post(
  '/register',
  auth.protectAdminRoute,
  [
    vs.isValidStrLenWithTrim('body', 'name', 3, 50, 'Please enter a valid name'),
    vs.isUsername('body', 'username'),
    vs.isGender('body', 'gender'),
    vs.isPassword('body', 'password', constant.validatorResponseStrings.USER_REGISTER_PASSWORD_RESPONSE),
    vs.isDOB('body', 'dob'),
    vs.isValidDate('body', 'doj', 'Invalid Date of Joining. Please specify the date in YYYY-MM-DD format'),
    vs.isEmail('body', 'email'),
    vs.isMobile('body', 'phone'),
    vs.isValidAdminRole('body', 'role'),
    vs.isValidStrLenWithTrim('body', 'address', 3, 50, 'Please enter a valid address'),
    vs.isValidCity('body', 'city'),
    vs.isValidState('body', 'state'),
    vs.isValidCountry('body', 'country'),
    vs.isPINCODE('body', 'pincode'),
  ],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = [
        'name',
        'username',
        'gender',
        'role',
        'dob',
        'password',
        'email',
        'phone',
        'address',
        'city',
        'doj',
        'state',
        'country',
        'pincode',
      ];
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    const bePassword = req.body.password;

    let beHashedPassword = '';

    try {
      beHashedPassword = await auth.hashPassword(bePassword);
    } catch (e) {
      logger.error(e.message, { error: e, ...req.logger_meta });
      const responseUnableToHash = responseGenerator.internalError(error.errList.internalError.ERR_HASH_PASSWORD);
      return res.status(500).send(responseUnableToHash);
    }

    req.body.beHashedPassword = beHashedPassword;

    try {
      const [rows] = await db.insertMK2SLLCUsers(req.body);
      if (rows.affectedRows !== 1) {
        const responsePasswordNoMatch = responseGenerator.internalError(error.errList.internalError.ERR_INSERT_USER_INSERT_FAILURE_NO_INSERT);
        return res.status(400).send(responsePasswordNoMatch);
      }
      return res.status(200).send(
        responseGenerator.success('Admin register', 'Admin registered successfully', [
          {
            id: constant.idPrefix.ADMIN + rows.insertId,
            name: req.body.name,
            username: req.body.username,
            gender: req.body.gender,
            email: req.body.email,
            phone: req.body.phone,
            dob: req.body.dob,
            address: req.body.address,
            city: req.body.city,
            state: req.body.state,
            country: req.body.country,
            pincode: req.body.pincode,
            role: req.body.role,
            dateOfJoining: req.body.doj,
          },
        ]),
      );
    } catch (e) {
      logger.error(e.message, { error: e, ...req.logger_meta });
      if (e.sqlMessage.includes('username')) {
        return res.status(400).send(responseGenerator.dbError(error.errList.dbError.ERR_ADMIN_USERNAME_UNAVAILABLE));
      }
      if (e.code === 'ER_DUP_ENTRY') {
        const beUserDuplicateEntry = error.errList.dbError.ERR_INSERT_USER_DUPLICATE_ENTRY;
        return res.status(400).send(responseGenerator.dbError(beUserDuplicateEntry));
      }
      const responsePasswordNoMatch = responseGenerator.internalError(error.errList.internalError.ERR_INSERT_USER_INSERT_FAILURE);
      return res.status(400).send(responsePasswordNoMatch);
    }
  },
);

module.exports = router;
