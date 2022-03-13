/* eslint-disable linebreak-style */
const express = require('express');
const citySelect = require('./city-select');
const countrySelect = require('./country-select');
const stateSelect = require('./state-select');
const currencyCodesSelect = require('./currency-codes-select');
const paymentModes = require('./payment-modes');

const router = express.Router();

router.use('/countries', countrySelect);
router.use('/states', stateSelect);
router.use('/cities', citySelect);
router.use('/currency-codes', currencyCodesSelect);
router.use('/payment/modes', paymentModes);
// router.use('/', create);

module.exports = router;
