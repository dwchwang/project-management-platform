import { body } from 'express-validator';

const userRegisterValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Please provide a valid email address'),
    body('username')
      .trim()
      .notEmpty()
      .withMessage('Username is required')
      .isLowercase()
      .withMessage('Username must be in lowercase')
      .isLength({ min: 3, max: 20 })
      .withMessage('Username must be between 3 and 20 characters'),
    body('password').trim().notEmpty().withMessage('Password is required'),
    body('fullName').optional().trim(),
  ];
};

const userLoginValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Please provide a valid email address'),
    body('password').trim().notEmpty().withMessage('Password is required'),
  ];
};

const userChangeCurrentPasswordValidator = () => {
  return [
    body('oldPassword')
      .trim()
      .notEmpty()
      .withMessage('Old password is required'),
    body('newPassword')
      .trim()
      .notEmpty()
      .withMessage('New password is required'),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Please provide a valid email address'),
  ];
};

const userResetForgotPasswordValidator = () => {
  return [
    body('newPassword')
      .trim()
      .notEmpty()
      .withMessage('New password is required'),
  ];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
