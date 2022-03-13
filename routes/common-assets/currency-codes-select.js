const express = require('express');
const vs = require('../../model/validator-sanitizer');
const responseGenerator = require('../../model/response-generator');
const db = require('./db-common-assets');
const error = require('../../model/error');

const router = express.Router();

// eslint-disable-next-line arrow-parens
const routeName = (str) => `*** currency-codes-select ${str ? `|| ${str}` : ''}***`;

/**
 *
 * @api {get} assets/commons/currency-codes/:country Get Country Currency Codes list
 * @apiName Get Country Currency Codes list
 * @apiGroup Common Assets
 * @apiVersion 0.0.1
 * @apiDescription Retrieve all the Country Currency Codes in the database
 *
 * @apiPermission none
 *
 * @apiParam {String} country Country to get the Country Currency Codes
 *
 * @apiSuccessExample {json} Sample-Request-Response
 * {
 *     "data": {
 *         "kind": "Currency Codes list",
 *         "description": "Currency Codes list retrieved successfully!!!",
 *         "items": [
 *             "INR"
 *         ]
 *     }
 * }
 *
 * @apiErrorExample {json} Internal-Error
 * HTTP/1.1 400 Bad Request
 * {
 *     "type": 1,
 *     "code": "50***",
 *     "message": "An internal error has occurred. Please try again!",
 *     "errors": []
 * }
 *
 * @apiErrorExample {json} Validation-Error
 * HTTP/1.1 422 Unprocessable Entity
 * {
 *     "type": 0,
 *     "code": "",
 *     "message": "Validation failure.",
 *     "errors": [
 *         {
 *             "message": "Please choose a valid country",
 *             "field": "country",
 *             "location": "params"
 *         }
 *     ]
 * }
 *
 * @apiSampleRequest /assets/commons/currency-codes/:country
 */
router.get('/:country', [vs.isValidCountry('params', 'country')], vs.returnValidations, async (req, res) => {
  const log = req.logger;
  log.info(routeName());
  try {
    const [rows] = await db.selectCurrencyCodes(req.params);
    log.verbose(routeName(), { data: rows });
    const data = rows[0].codes ? rows[0].codes.split(',') : [];
    return res.status(200).send(responseGenerator.success('Currency Codes list', 'Currency Codes list retrieved successfully!!!', data));
  } catch (e) {
    log.error(routeName(e.message), { error: e });
    const resErrorInInsert = responseGenerator.internalError(error.errList.internalError.ERR_SELECT_COUNTRY_LIST_FAILURE);
    return res.status(500).send(resErrorInInsert);
  }
});

module.exports = router;
