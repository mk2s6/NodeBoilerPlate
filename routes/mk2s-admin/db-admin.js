const pool = require('../../database/db');
const hf = require('../../model/helper-function');


async function validateUsername(userName) {
  return pool.execute('SELECT count(adm_username) AS isAvailable FROM admin WHERE adm_username = ?', [userName]);
}

async function getLoginDetails(userName) {
  const beUsername = userName;

  let strUserSelectQuery = `SELECT adm_id AS id, adm_name AS name,
                                     adm_password AS password, adm_role as role
                              FROM admin`;

  if (hf.isEmail(beUsername)) {
    strUserSelectQuery += ' WHERE adm_email = ?';
  } else if (hf.isMobile(beUsername)) {
    strUserSelectQuery += ' WHERE adm_phone = ?';
  } else {
    strUserSelectQuery += ' WHERE adm_username = ?';
  }

  // Only allow non deleted employee
  strUserSelectQuery += ' AND adm_active = ?';

  return pool.execute(strUserSelectQuery, [beUsername, 1]);
}

async function insertMK2SLLCUsers(user) {
  return pool.execute(
    `
        INSERT INTO admin (
              adm_username, adm_email, adm_phone, adm_password, adm_name,
              adm_gender, adm_dob, adm_role, adm_doj, adm_address, adm_city,
              adm_state, adm_country, adm_zip_code
          )
        VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
      `,
    [
      user.username,
      user.email,
      user.phone,
      user.beHashedPassword,
      user.name,
      user.gender,
      user.dob,
      user.role,
      user.doj,
      user.address,
      user.city,
      user.state,
      user.country,
      user.pincode,
    ],
  );
}

module.exports = {
  validateUsername,
  getLoginDetails,
  insertMK2SLLCUsers,
};
