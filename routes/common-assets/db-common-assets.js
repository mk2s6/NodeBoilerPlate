const pool = require('../../database/db');

async function selectCountries() {
  return pool.execute('SELECT GROUP_CONCAT(country) AS countries FROM country');
}

async function selectStates({ country }) {
  return pool.execute('SELECT GROUP_CONCAT(state) AS states FROM state WHERE country = ?', [country]);
}

async function selectCities({ state }) {
  return pool.execute('SELECT GROUP_CONCAT(city) AS cities FROM city WHERE state = ?', [state]);
}

async function selectCurrencyCodes({ country }) {
  return pool.execute('SELECT GROUP_CONCAT(cc_code) AS codes FROM currency_codes WHERE cc_country = ?', [country]);
}

async function selectPaymentModes() {
  return pool.execute('SELECT GROUP_CONCAT(payment_mode) AS modes FROM payment_modes WHERE payment_mode_active = ?', [1]);
}

module.exports = {
  selectCountries,
  selectStates,
  selectCities,
  selectCurrencyCodes,
  selectPaymentModes,
};
