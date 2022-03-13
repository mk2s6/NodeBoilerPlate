const express = require('express');
const vs = require('../../model/validator-sanitizer');
const responseGenerator = require('../../model/response-generator');
const constant = require('../../model/constant');
const error = require('../../model/error');
const hf = require('../../model/helper-function');

const router = express.Router();

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidFSJDate', [vs.isValidFSJDate('query', 'date')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['date'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Date Validator', 'Date Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isEmail', [vs.isEmail('query', 'email')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['email'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Email Validator', 'Email Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/ifExistIsEmail', [vs.ifExistIsEmail('query', 'email')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['email'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('If exists email Validator', 'If exists email Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isMobile', [vs.isMobile('query', 'mobile')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['mobile'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Mobile Validator', 'Mobile Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/ifExistIsMobile', [vs.ifExistIsMobile('query', 'mobile')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['mobile'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('If exists Mobile Validator', 'If exists Mobile Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isEmailOrMobile', [vs.isEmailOrMobile('query', 'username')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['username'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Is email-id or Mobile Validator', 'Is email-id or Mobile Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isGender', [vs.isGender('query', 'gender')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['gender'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Gender Validator', 'Gender Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isDOB', [vs.isDOB('query', 'date')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['date'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('DOB Validator', 'DOB Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get(
  '/isEmpPassword',
  [vs.isEmpPassword('query', 'password', constant.passwordValidatorResponses.EMPLOYEE_REGISTER_PASSWORD_RESPONSE)],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = ['password'];
      // This is if else so we don't need return
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    return res.status(200).send(responseGenerator.success('Employee Password Validator', 'Employee Password Validator validation Success', {}));
  },
);

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get(
  '/isInstituteEmployeePassword',
  [vs.isInstituteEmployeePassword('query', 'password', constant.passwordValidatorResponses.COMPANY_EMPLOYEE_REGISTER_PASSWORD_RESPONSE)],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = ['password'];
      // This is if else so we don't need return
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    return res
      .status(200)
      .send(responseGenerator.success('Institute Employee Password Validator', 'Institute Employee Password Validator validation Success', {}));
  },
);

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isAmount', [vs.isAmount('query', 'amount', 'Please enter a valid amount value')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['amount'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Amount Validator', 'Amount Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isBranches', [vs.isBranches('query', 'branches')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['branches'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Branches Validator', 'Branches Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidEnquiryClassification', [vs.isValidEnquiryClassification('query', 'classification')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['classification'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Valid Classification Validator', 'Valid Classification Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isPINCODE', [vs.isPINCODE('query', 'pincode')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['pincode'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Pin-Code Validator', 'Pin-Code Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/ifExistIsPINCODE', [vs.ifExistIsPINCODE('query', 'pincode')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['pincode'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('If exists Pin-Code Validator', 'If exists Pin-Code Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidEnquiryStatus', [vs.isValidEnquiryStatus('query', 'status')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['status'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Valid Enquiry status Validator', 'Valid Enquiry status Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/ifExistIsValidEnquiryStatus', [vs.ifExistIsValidEnquiryStatus('query', 'status')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['status'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res
    .status(200)
    .send(responseGenerator.success('If exists Valid Enquiry status Validator', 'If exists Valid Enquiry status Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isExist', [vs.isExist('query', 'parameter', "The entered parameter doesn't exist")], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['parameter'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('If exists Validator', 'If exists Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get(
  '/isExactLenWithTrim',
  [vs.isExactLenWithTrim('query', 'string', 10, 'Please enter a string with exactly 10 characters in length')],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = ['string'];
      // This is if else so we don't need return
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    return res
      .status(200)
      .send(responseGenerator.success('Exact length with trim Validator', 'Exact length with trim Validator validation Success', {}));
  },
);

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get(
  '/isMinLenWithTrim',
  [vs.isMinLenWithTrim('query', 'string', 6, 'Please enter a string with minimum of 6 characters')],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = ['string'];
      // This is if else so we don't need return
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    return res
      .status(200)
      .send(responseGenerator.success('Minimum length with trim Validator', 'Minimum length with trim Validator validation Success', {}));
  },
);

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get(
  '/isMaxLenWithTrim',
  [vs.isMaxLenWithTrim('query', 'string', 100, 'Please enter a string of maximum 100 characters only')],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = ['string'];
      // This is if else so we don't need return
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    return res
      .status(200)
      .send(responseGenerator.success('Maximum length with trim Validator', 'Maximum length with trim Validator validation Success', {}));
  },
);

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get(
  '/isValidStrLenWithTrim',
  [vs.isValidStrLenWithTrim('query', 'string', 0, 100, 'Please enter a string with length between 0 to 100 characters only')],
  async (req, res) => {
    const errors = vs.getValidationResult(req);
    if (!errors.isEmpty()) {
      const fieldsToValidate = ['string'];
      // This is if else so we don't need return
      return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
    }
    return res
      .status(200)
      .send(responseGenerator.success('Valid string length with trim Validator', 'Valid string length with trim Validator validation Success', {}));
  },
);

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isNumeric', [vs.isNumeric('query', 'number', 'Please enter a valid number')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['number'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Numeric Validator', 'Numeric Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidInstituteCode', [vs.isValidInstituteCode('query', 'code')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['code'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Institute code Validator', 'Institute code Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isWithinRange', [vs.isWithinRange('query', 'number', 0, 100000, 'Please enter a value between 0 and 100000')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['number'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Number in range Validator', 'Number in range Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isBoolean', [vs.isBoolean('query', 'bool', 'Please enter a valid boolean value')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['bool'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Boolean Validator', 'Boolean Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidFSJTime', [vs.isValidFSJTime('query', 'time')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['time'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res.status(200).send(responseGenerator.success('Time Validator', 'Time Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidFutureDateTodayNotAllowed', [vs.isValidFutureDateTodayNotAllowed('query', 'date')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['date'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res
    .status(200)
    .send(
      responseGenerator.success('Future date and today not allowed Validator', 'Future date and today not allowed Validator validation Success', {}),
    );
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidFutureDateTodayAllowed', [vs.isValidFutureDateTodayAllowed('query', 'date')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['date'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res
    .status(200)
    .send(responseGenerator.success('Future date and today allowed Validator', 'Future date and today allowed Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidPastDateTodayNotAllowed', [vs.isValidPastDateTodayNotAllowed('query', 'date')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['date'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res
    .status(200)
    .send(responseGenerator.success('Past date and today not allowed Validator', 'Past date and today not allowed Validator validation Success', {}));
});

/**
 * This route is used by developer for quick testing of validations etc.
 */
router.get('/isValidPastDateTodayAllowed', [vs.isValidPastDateTodayAllowed('query', 'date')], async (req, res) => {
  const errors = vs.getValidationResult(req);
  if (!errors.isEmpty()) {
    const fieldsToValidate = ['date'];
    // This is if else so we don't need return
    return res.status(422).send(responseGenerator.validationError(errors.mapped(), fieldsToValidate));
  }
  return res
    .status(200)
    .send(responseGenerator.success('Past date and today allowed Validator', 'Past date and today allowed Validator validation Success', {}));
});

module.exports = router;
