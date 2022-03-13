/* eslint-disable object-curly-newline */
/* eslint-disable max-len */
const config = require('config');

const generateWelcomeMail = ({ owner, name, email, address, city }, password) => ({
  to: owner.email,
  cc: email,
  subject: 'Congratulations..!! Restaurant have been registered with MK2S..!!',
  text: `Dear ${owner.name}, \n\nYour restaurant ${name} @ ${address}, ${city} have been registered with MK2S LLC successfully.\n\nThank you for registering with us, we are so delighted that you are onboarding with us\n\nLogin Credentials for owner login after the setup are as follows.\n\n\nEmail: ${owner.email}.\nPassword: ${password}\n\n\nThanks and regards,\nMK2S LLC.`,
});

const generateEmployeeWelcomeMail = ({ name, email }, password, restaurantDetails) => ({
  to: email,
  cc: restaurantDetails.email,
  bcc: config.get('nodeMailerConfig.sender_email'),
  subject: `Welcome to HMS Application with ${restaurantDetails.name}..!!`,
  text: `Dear ${name}, \n\nYour restaurant ${restaurantDetails.name} have registered you with the HMS Application.\n\nLogin Credentials for you with the restaurant are as follows.\n\n\nEmail: ${email}.\nPassword: ${password}\n\n\nThanks and regards,\n${restaurantDetails.name}.`,
});

module.exports = { generateWelcomeMail, generateEmployeeWelcomeMail };
