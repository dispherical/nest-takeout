const nodemailer = require('nodemailer')

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
})

async function sendCompletionEmail({ to, username, expiresAt }) {
  const base = process.env.PUBLIC_URL || ''
  const dashboard = `${base}/dashboard`
  const download = `${base}/zip/download`
  const expiry = expiresAt.toUTCString()

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject: 'Your nest export is ready',
    text: [
      `Hi ${username},`,
      '',
      'Your nest home export has finished and is ready to download:',
      download,
      '',
      `This link expires ${expiry} (24 hours from now).`,
      "After that the file is deleted and you'll need to start a new export.",
      '',
      `Dashboard: ${dashboard}`,
    ].join('\n'),
  })
}

module.exports = { sendCompletionEmail }
