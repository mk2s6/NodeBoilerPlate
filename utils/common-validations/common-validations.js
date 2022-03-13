const { isNumeric, returnValidations } = require('../../model/validator-sanitizer');

const paginationValidation = [
  isNumeric('query', 'limit', 'Please provide number of rows per page'),
  isNumeric('query', 'page_no', 'Please provide page number'),
  returnValidations,
];

module.exports = { paginationValidation };
