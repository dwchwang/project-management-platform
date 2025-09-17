import express from 'express';
import {
  registerUser,
  loginUser,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendVerificationEmail,
  refreshToken,
  forgotPassword,
  resetForgotPassword,
  changeCurrentPassword,
} from '../controllers/auth.controller.js';

import { validate } from '../middlewares/validator.middleware.js';

import {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
} from '../validators/index.js';

import { verifyJWT } from '../middlewares/auth.middleware.js';

const router = express.Router();


// unsecured routes
router.post('/register', userRegisterValidator(), validate, registerUser);
router.post('/login', userLoginValidator(), validate, loginUser);
router.get('/verify-email/:verificationToken', verifyEmail);
router.post("/refresh-token", refreshToken);
router.post('/forgot-password', userForgotPasswordValidator(), validate, forgotPassword);
router.post('/reset-forgot-password/:resetToken', userResetForgotPasswordValidator(), validate, resetForgotPassword);

// secured routes
router.post('/logout', verifyJWT, logoutUser);
router.get('/current', verifyJWT, getCurrentUser);
router.post('/change-password', verifyJWT, userChangeCurrentPasswordValidator(), validate, changeCurrentPassword);
router.post('/resend-email-verification', verifyJWT, resendVerificationEmail);



export default router;
