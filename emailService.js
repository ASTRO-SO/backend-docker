// emailService.js
const nodemailer = require('nodemailer');
require('dotenv').config();

// Create transporter with your email service configuration
const createTransporter = () => {
  return nodemailer.createTransport({
    // For Gmail
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, 
      pass: process.env.EMAIL_PASS  
    }
  });
};

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP email
const sendOTPEmail = async (email, otp, fullname = 'Khách hàng') => {
  const transporter = createTransporter();

  const mailOptions = {
    from: {
      name: 'ASTRO SỐ',
      address: process.env.EMAIL_USER
    },
    to: email,
    subject: 'Mã xác thực đặt lại mật khẩu - ASTRO SỐ',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          .container {
            max-width: 600px;
            margin: 0 auto;
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
          }
          .header {
            background-color: #CCA508;
            padding: 20px;
            text-align: center;
            color: white;
          }
          .content {
            padding: 30px;
            background-color: #f9f9f9;
          }
          .otp-code {
            background-color: #fff;
            border: 2px solid #CCA508;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
            border-radius: 8px;
          }
          .otp-number {
            font-size: 32px;
            font-weight: bold;
            color: #CCA508;
            letter-spacing: 8px;
          }
          .footer {
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 14px;
          }
          .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Đặt lại mật khẩu</h1>
          </div>
          <div class="content">
            <h2>Xin chào ${fullname}!</h2>
            <p>Chúng tôi đã nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn.</p>
            <p>Vui lòng sử dụng mã xác thực dưới đây để tiếp tục:</p>
            
            <div class="otp-code">
              <div class="otp-number">${otp}</div>
              <p style="margin: 10px 0 0 0; color: #666;">Mã xác thực có hiệu lực trong 10 phút</p>
            </div>
            
            <div class="warning">
              <strong>Lưu ý bảo mật:</strong>
              <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                <li>Không chia sẻ mã này với bất kỳ ai</li>
                <li>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này</li>
                <li>Mã xác thực chỉ có hiệu lực trong 10 phút</li>
              </ul>
            </div>
            
            <p>Nếu bạn cần hỗ trợ, vui lòng liên hệ với chúng tôi.</p>
            <p>Trân trọng,<br>Đội ngũ hỗ trợ Your App Name</p>
          </div>
          <div class="footer">
            <p>Email này được gửi tự động, vui lòng không trả lời.</p>
            <p>&copy; 2024 Your App Name. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', info.messageId);
    return {
      success: true,
      messageId: info.messageId
    };
  } catch (error) {
    console.error('Error sending email:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Verify transporter configuration
const verifyEmailConfig = async () => {
  const transporter = createTransporter();
  try {
    await transporter.verify();
    console.log('Email configuration is valid');
    return true;
  } catch (error) {
    console.error('Email configuration error:', error);
    return false;
  }
};

module.exports = {
  generateOTP,
  sendOTPEmail,
  verifyEmailConfig
};