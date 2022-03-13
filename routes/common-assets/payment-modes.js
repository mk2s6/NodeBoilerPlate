const express = require('express');
const responseGenerator = require('../../model/response-generator');
const db = require('./db-common-assets');
const error = require('../../model/error');

const router = express.Router();

// eslint-disable-next-line arrow-parens
const routeName = (str) => `*** payment-modes ${str ? `|| ${str}` : ''}***`;

/**
 *
 * @api {get} assets/commons/payment/modes Get payment modes list
 * @apiName Get payment modes list
 * @apiGroup Common Assets
 * @apiVersion 0.0.1
 * @apiDescription Retrieve all the payment modes in the database
 *
 * @apiPermission none
 *
 * @apiSuccessExample {json} Sample-Request-Response
 * {
 *     "data": {
 *         "kind": "Payment Modes list",
 *         "description": "Payment Modes list retrieved successfully!!!",
 *         "items": [
 *             "Card",
 *             "Cash",
 *             "Online"
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
 * @apiSampleRequest /assets/commons/payment/modes
 */
router.get('', async (req, res) => {
  const log = req.logger;
  log.info(routeName());
  try {
    const [rows] = await db.selectPaymentModes();
    log.verbose(routeName(), { data: rows });
    return res
      .status(200)
      .send(responseGenerator.success('Payment Modes list', 'Payment Modes list retrieved successfully!!!', rows[0].modes.split(',')));
  } catch (e) {
    log.error(routeName(e.message), { error: e });
    const resErrorInInsert = responseGenerator.internalError(error.errList.internalError.ERR_SELECT_COUNTRY_LIST_FAILURE);
    return res.status(500).send(resErrorInInsert);
  }
});

module.exports = router;
