/* eslint-disable no-await-in-loop */
/* eslint-disable arrow-parens */
const pool = require('../database/db');
const error = require('../model/error');

const routeName = (str) => `*** DB-Transaction ${str ? `|| ${str}` : ''}***`;

/**
 * This function is used to execute multiple queries in a single transaction.
 * @param log - The log object.
 * @param funcs - an array of functions that will be executed in the order they are passed in.
 * @param data - an array of data to be passed to the functions
 * @param errors - an array of objects that contain the following keys:
 * @returns The responseData array.
 */
const dbTransactions = async (log, funcs, data, errors) => {
  const responseData = [];

  let conn;
  try {
    conn = await pool.getConnection();
  } catch (e) {
    log.error(routeName(e.message), { error: e });
    const transactionGetConnection = error.errList.internalError.ERR_TRANSACTION_GET_CONNECTION_FAILURE;
    return Promise.reject(transactionGetConnection);
  }

  // Begin Transaction
  try {
    await conn.beginTransaction();
  } catch (e) {
    log.error(routeName(e.message), { error: e });

    await conn.rollback();
    await conn.release();
    const beginTransactionFailure = error.errList.internalError.ERR_TRANSACTION_BEGIN_TRANSACTION_FAILURE;
    return Promise.reject(beginTransactionFailure);
  }
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < funcs.length; i++) {
    try {
      const [rows] = await funcs[i](conn, data[i]);

      log.verbose(rows, {});
      if (errors[i].ROW_CHECK && !rows.affectedRows) {
        const rowCheck = error.errList.dbError[errors[i].AFFECTED_ROWS];
        return Promise.reject(rowCheck);
      }
      responseData.push(rows);
    } catch (e) {
      log.error(routeName(e.message), { error: e });
      await conn.rollback();
      await conn.release();
      if (e.code === 'ER_DUP_ENTRY') {
        const duplicateEntry = error.errList.dbError[errors[i].DUPLICATE_ENTRY];
        return Promise.reject(duplicateEntry);
      }
      const funcsError = error.errList.internalError[errors[i].ERROR];
      return Promise.reject(funcsError);
    }
  }

  try {
    await conn.commit();
    await conn.release();
  } catch (e) {
    log.error(routeName(e.message), { error: e });
    await conn.rollback();
    await conn.release();
    const commitFailure = error.errList.internalError.ERR_INSERT_USER_INSERT_FAILURE;
    return Promise.reject(commitFailure);
  }
  return responseData;
};

module.exports = dbTransactions;
