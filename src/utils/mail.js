import Mailgen from "mailgen";
import nodemailer from "nodemailer";


const sendEmail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "https://taskmanegelink.com",
    },
  })

  const emailtexual = mailGenerator.generatePlaintext(options.mailgenContent);

  const emailHTML = mailGenerator.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  })

  const mail = {
    from: "mail.taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailtexual,
    html: emailHTML,
  }

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error("Email service failed siliently. Make sure that you provided your MAILTRAP credentials in the .env file");
    console.error("Error: ", error);
  }
}

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our app! We're very excited to have you on board.",
      action: {
        instructions: "To verify your email, please click here:",
        button: {
          color: "#22BC66", 
          text: "Confirm your account",
          link: verificationUrl,
        },
      },
      outro: "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  }
} 

const passwordResetMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset your password. No worries, we are here to help!",
      action: {
        instructions: "To reset your password, please click here:",
        button: {
          color: "#DC4D2F", 
          text: "Reset your password",
          link: passwordResetUrl,
        },
      },
      outro: "If you did not request a password reset, no further action is required on your part.",
    },
  }
}


export { emailVerificationMailgenContent, passwordResetMailgenContent, sendEmail };




