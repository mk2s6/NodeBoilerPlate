const express = require('express');
const vs = require('../../model/validator-sanitizer');
const responseGenerator = require('../../model/response-generator');
const db = require('./db-common-assets');
const error = require('../../model/error');

const router = express.Router();

// eslint-disable-next-line arrow-parens
const routeName = (str) => `*** state-select ${str ? `|| ${str}` : ''}***`;

/**
 *
 * @api {get} assets/commons/states/:country Get states list
 * @apiName Get states list
 * @apiGroup Common Assets
 * @apiVersion 0.0.1
 * @apiDescription Retrieve all the states in the database
 *
 * @apiPermission none
 *
 * @apiParam {String} country Country to get the states
 *
 * @apiSuccessExample {json} Sample-Request-Response
 * {
 *     "data": {
 *         "kind": "States list",
 *         "description": "States list retrieved successfully!!!",
 *         "items": [
 *             "Andhra Pradesh",
 *             "Goa",
 *             "Karnataka"
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
 * @apiSampleRequest /assets/commons/states/:country
 */
router.get('/:country', [vs.isValidCountry('params', 'country')], vs.returnValidations, async (req, res) => {
  const log = req.logger;
  log.info(routeName(), { ...req.logger_meta });
  try {
    const [rows] = await db.selectStates(req.params);
    log.verbose(routeName(), { data: rows });

    return res.status(200).send(responseGenerator.success('States list', 'States list retrieved successfully!!!', rows[0].states.split(',')));
  } catch (e) {
    log.error(routeName(e.message), { error: e, ...req.logger_meta });
    const resErrorInInsert = responseGenerator.internalError(error.errList.internalError.ERR_SELECT_COUNTRY_LIST_FAILURE);
    return res.status(500).send(resErrorInInsert);
  }
});

module.exports = router;
