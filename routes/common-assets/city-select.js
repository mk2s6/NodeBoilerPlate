const express = require('express');
const vs = require('../../model/validator-sanitizer');
const responseGenerator = require('../../model/response-generator');
const db = require('./db-common-assets');
const error = require('../../model/error');

const router = express.Router();

// eslint-disable-next-line arrow-parens
const routeName = (str) => `*** city-select ${str ? `|| ${str}` : ''}***`;

/**
 *
 * @api {get} assets/commons/cities/:state Get cities list
 * @apiName Get cities list
 * @apiGroup Common Assets
 * @apiVersion 0.0.1
 * @apiDescription Retrieve all the cities for a state in the database
 *
 * @apiPermission none
 *
 * @apiParam {String} state state to get the cities
 *
 * @apiSuccessExample {json} Sample-Request-Response
 * {
 *     "data": {
 *         "kind": "Cities list",
 *         "description": "Cities list retrieved successfully!!!",
 *         "items": [
 *             "Chittoor",
 *             "SriKalahasti"
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
 * @apiSampleRequest /assets/commons/cities/:state
 */
router.get('/:state', [vs.isValidState('params', 'state')], vs.returnValidations, async (req, res) => {
  const log = req.logger;
  log.info(routeName());
  try {
    const [rows] = await db.selectCities(req.params);
    log.verbose(routeName(), { data: rows });
    return res.status(200).send(responseGenerator.success('Cities list', 'Cities list retrieved successfully!!!', rows[0].cities.split(',')));
  } catch (e) {
    log.error(routeName(e.message), { error: e });
    const resErrorInInsert = responseGenerator.internalError(error.errList.internalError.ERR_SELECT_COUNTRY_LIST_FAILURE);
    return res.status(500).send(resErrorInInsert);
  }
});

module.exports = router;
