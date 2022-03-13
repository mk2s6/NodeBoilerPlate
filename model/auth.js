/* eslint-disable consistent-return */
/* eslint-disable arrow-parens */

/**
 * JWT Object Structure (All things are defined in constant)
 *
 * [TOKEN_NAME] =
 *    payload :{
 *    id: 'EMP_ID',
 *    iid: 'HOTEL_ID',
 *    role: ''
 * }
 *
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const PG = require('generate-password');
const constant = require('./constant');
const RG = require('./response-generator');
const error = require('./error');
const { logger } = require('./logger');

const functionName = (str) => `***  auth ${str ? ` || ${str}` : ''}  ***`;

const jwtSecret = config.get('authJWT.secret');

/**
 * Hash the given password. Before passing the password to this function
 * it must be validated through validator module.
 *
 * @public
 * @async
 * @param {string} password Password to be hashed
 *
 * @return {string} Hashed password
 */
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

/**
 *
 * @public
 * @async
 *
 * @return {string} Generated password
 */
function genPassword() {
  return PG.generate({
    length: 8,
    lowercase: true,
    uppercase: true,
    numbers: true,
    symbols: true,
    strict: true,
    exclude: ';:\'"`\\/{}[]()',
    excludeSimilarCharacters: true,
  });
}

/**
 * Compare plain text password with hashed password
 *
 * @public
 * @async
 * @param {string} password Plain text password
 * @param {string} hashedPassword Hashed password from DB
 *
 * @return {boolean} Indicating whether passwords are equal
 */
async function verifyPassword(password, hashedPassword) {
  const areEqual = await bcrypt.compare(password, hashedPassword);
  return areEqual;
}

/**
 * Create signed JSON Web Token encoding given payload using secret.
 *
 * @public
 * @param {object} payload Object we need to encode as JSON Web Token
 *
 * @return {jwt} payload encoded as JSON Web Token
 */
function genAuthToken(payload, remember) {
  return jwt.sign(payload, jwtSecret, { expiresIn: remember ? '30d' : '48h' });
}

/**
 * Create signed JSON Web Token encoding given payload using secret.
 *
 * @public
 * @param {object} payload Object we need to encode as JSON Web Token
 *
 * @return {jwt} payload encoded as JSON Web Token
 */
function genAuthTokenResetPassword(payload) {
  return jwt.sign(payload, jwtSecret, { expiresIn: '30m' });
}

/**
 * Create signed JSON Web Token encoding given payload using secret.
 *
 * @public
 * @param {object} payload Object we need to encode as JSON Web Token
 *
 * @return {jwt} payload encoded as JSON Web Token
 */
function genAuthTokenVerifyEmail(payload) {
  return jwt.sign(payload, jwtSecret, { expiresIn: '2d' });
}

/**
 * authentication middle ware to check token of verify the email
 */
function protectEmailVerify(req, res, next) {
  const log = logger(req.logger_meta);
  log.info(functionName('protectMK2SAdminRoute'));
  const token = req.query.email_verify_tkn;
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }
      next();
    } catch (e) {
      log.error(e);
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

/**
 * Check if user is an employee and have permission to payment management
 *
 * @public
 */

function protectMK2SAdminRoute(req, res, next) {
  const log = logger(req.logger_meta);
  log.info(functionName('protectMK2SAdminRoute'));
  const token = req.header(constant.TOKEN_NAME);
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }

      if (req.user.token_type !== constant.tokenType.MK2S_ADMIN && req.user.role !== constant.roles.ADMIN) {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_PERMISSION_MISMATCH));
      }
      next();
    } catch (e) {
      log.error(e.message, { error: e });
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

/**
 * Only check if the user is an employee of company. No additional permission required.
 */
async function protectEmployeeRoute(req, res, next) {
  const log = logger(req.logger_meta);
  log.info(functionName('protectEmployeeRoute'));
  const token = req.header(constant.TOKEN_NAME);
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }
      if (req.user.token_type !== constant.tokenType.EMPLOYEE) {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_PERMISSION_MISMATCH));
      }
      next();
    } catch (e) {
      log.error(functionName(e.message), { error: e });
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

/**
 * Only check if the user is an employee of company. No additional permission required.
 */
function protectUserRoute(req, res, next) {
  const token = req.header(constant.TOKEN_NAME);
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }
      if (req.user.token_type !== constant.tokenType.USER) {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_PERMISSION_MISMATCH));
      }
      next();
    } catch (e) {
      console.log(e);
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

/**
 * Check if user is an employee and have permission to payment management
 *
 * @public
 */

function protectAdminRoute(req, res, next) {
  const token = req.header(constant.TOKEN_NAME);
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }

      if (req.user.token_type !== constant.tokenType.ADMIN) {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_PERMISSION_MISMATCH));
      }
      next();
    } catch (e) {
      console.log(e);
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

function protectResetPasswordRoute(req, res, next) {
  const token = req.query.reset_pwd_tkn;
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }
      next();
    } catch (e) {
      console.log(e);
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

/**
 * general auth token verification route
 *
 * @public
 *
 */
function protectTokenVerify(req, res, next) {
  const token = req.header(constant.TOKEN_NAME);
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }
      next();
    } catch (e) {
      console.log(e);
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}
/**
 * general auth token verification route
 *
 * @public
 *
 */
function protectTokenValidate(req, res, next) {
  const token = req.header(constant.TOKEN_NAME);
  if (token) {
    try {
      if (req.user === null || req.user === undefined) {
        const payload = jwt.verify(token, jwtSecret);
        req.user = payload;
      }
      next();
    } catch (e) {
      console.log(e);
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return next();
  }
}

function protectEmployeeResetPasswordRoute(req, res, next) {
  const token = req.query.tkn;
  if (token) {
    try {
      const payload = jwt.verify(token, jwtSecret);
      if (!payload.role.startsWith('FSJ_')) {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_ROLE_MISMATCH));
      }
      req.user = payload;
      next();
    } catch (e) {
      if (e.name === 'TokenExpiredError') {
        return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_TOKEN_EXPIRED));
      }
      return res.status(403).send(RG.authError(error.errList.authError.ERR_PR_INVALID_TOKEN));
    }
  } else {
    return res.status(401).send(RG.authError(error.errList.authError.ERR_PR_NO_TOKEN));
  }
}

module.exports.hashPassword = hashPassword;
module.exports.genPassword = genPassword;
module.exports.genAuthToken = genAuthToken;
module.exports.genAuthTokenResetPassword = genAuthTokenResetPassword;
module.exports.protectEmailVerify = protectEmailVerify;
module.exports.protectResetPasswordRoute = protectResetPasswordRoute;
module.exports.genAuthTokenVerifyEmail = genAuthTokenVerifyEmail;
module.exports.verifyPassword = verifyPassword;
module.exports.protectTokenVerify = protectTokenVerify;
module.exports.protectEmployeeRoute = protectEmployeeRoute;
module.exports.protectUserRoute = protectUserRoute;
module.exports.protectAdminRoute = protectAdminRoute;
module.exports.protectMK2SAdminRoute = protectMK2SAdminRoute;
module.exports.protectTokenValidate = protectTokenValidate;
module.exports.protectEmployeeResetPasswordRoute = protectEmployeeResetPasswordRoute;
