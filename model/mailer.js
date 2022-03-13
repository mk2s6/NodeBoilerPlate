/* eslint-disable object-curly-newline */
const nodemailer = require('nodemailer'); // nodemailer package used to send emails
const config = require('config');

// eslint-disable-next-line arrow-parens
const functionName = (str) => `*** mailer ${str ? `|| ${str}` : ''} ***`;

// transporter object is used for creating an object that uses a SMTP service
// it is the one which is used for authenticating the hosting server and sends email
const transporter = nodemailer.createTransport({
  host: config.get('nodeMailerConfig.host'),
  port: config.get('nodeMailerConfig.port'),
  secure: false,
  auth: {
    user: config.get('nodeMailerConfig.email'),
    pass: config.get('nodeMailerConfig.password'),
  },
  tls: {
    rejectUnauthorized: false,
  },
});

const sendEmail = async (log, { to, subject, text, bcc, cc }) => {
  try {
    const res = await transporter.sendMail({
      to,
      cc,
      bcc,
      from: `${config.get('nodeMailerConfig.sender_name')}<${config.get('nodeMailerConfig.sender_email')}>`,
      subject,
      text,
    });
    log.debug(functionName('sendEmail'), { response: res });
    return res;
  } catch (e) {
    log.error(functionName('sendEmail'), { error: e });
    return Promise.reject(e);
  }
};

// sendEmail({ to: 'kusumanjali.55@gmail.com', subject: 'test', text: 'test' });

module.exports = { sendEmail };
