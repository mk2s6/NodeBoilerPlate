/* eslint-disable linebreak-style */
const express = require('express');
const commonRoutes = require('./common-assets');

const router = express.Router();

router.use('/test', require('./index'));
/**
 * This is the code that is serving the common files to the client.
 */
router.use('/assets/commons', commonRoutes);

module.exports = router;
