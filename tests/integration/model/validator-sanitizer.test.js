const server = require('../../test-server');
const constant = require('../../../model/constant');

beforeAll(() => {
  server.start();
}, constant.testTimeout.beforeAll);

afterAll(async () => {
  await server.close();
}, constant.testTimeout.afterAll);

describe('ValidatorSanitizerTests', () => {
  beforeEach(() => {
    // No setup needed
  });
  afterEach(async () => {
    // No teardown needed
  });

  describe('isValidFSJDate', () => {
    const paramsArray = [
      ['Valid', '2017-08-12', 200],
      ['Valid', '2020-02-29', 200], // Feb Leap Year
      ['Invalid', '2017-02-30', 422], // Invalid Feb date
      ['Invalid', '2017-20-30', 422], // Invalid Month
      ['Invalid', '', 422], // Empty
      // The following test case is error in library date-and-time
      // ['Invalid', '77-04-12', 422], // Less than 4 YYYY
      ['Invalid', '20177-04-12', 422], // More than 4 YYYY
      ['Invalid', '2017-0-12', 422], // Less than 2 MM
      ['Invalid', '2017-012-12', 422], // More than 2 MM
      ['Invalid', '2017-04-2', 422], // Less than 2 DD
      ['Invalid', '2017-04-222', 422], // More than 2 DD
      ['Invalid', '2017/04/222', 422], // Correct date with slash
    ];
    paramsArray.forEach(([testName, value, expectedStatus]) => {
      it(`${testName} YYYY-MM-DD: ${value}`, async () => {
        const response = await server.GET('/QA/validator_sanitizer/isValidFSJDate', { date: value });
        expect(response.status).toBe(expectedStatus);
      });
    });
  });
});
