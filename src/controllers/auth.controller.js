import { User } from '../models/user.models.js';
import { asyncHandler } from '../utils/async-handler.js';
import { ApiResponse } from '../utils/api-response.js';
import { ApiError } from '../utils/api-error.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import {
  emailVerificationMailgenContent,
  sendEmail,
  passwordResetMailgenContent,
} from '../utils/mail.js';

// Function to generate access and refresh tokens
const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, 'User not found', []);
    }
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, 'Something went wrong when generate token', []);
  }
};

// Register a new user
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password, role } = req.body;

  // Check if user already exists
  const existedUser = await User.findOne({
    $or: [{ email }, { username }],
  });

  if (existedUser) {
    throw new ApiError(400, 'User already exists', []);
  }

  // Create new user

  const newUser = await User.create({
    username,
    email,
    password,
    role,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    newUser.generateTemporaryToken();

  newUser.emailVerificationToken = hashedToken;
  newUser.emailVerificationExpiry = tokenExpiry;

  await newUser.save({ validateBeforeSave: false });

  await sendEmail({
    email: newUser?.email,
    subject: 'Please verify your email',
    mailgenContent: emailVerificationMailgenContent(
      newUser?.username,
      `${req.protocol}://${req.get('host')}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  const createdUser = await User.findById(newUser._id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationExpiry',
  );

  if (!createdUser) {
    throw new ApiError(500, 'Something went wrong when create user', []);
  }

  res.status(201).json(
    new ApiResponse(
      201,
      'User registered successfully and verification email has been sent on your email',
      {
        user: createdUser,
      },
    ),
  );
});

//login user
const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if (!email) {
    throw new ApiError(400, 'Please provide email or username', []);
  }

  // Check if user exists
  const exitedUser = await User.findOne({ email });

  if (!exitedUser) {
    throw new ApiError(400, 'User does not exists', []);
  }

  const isPasswordCorrect = await exitedUser.isPasswordCorrect(password);

  if (!isPasswordCorrect) {
    throw new ApiError(400, 'Invalid credentials', []);
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    exitedUser._id,
  );

  const loginUser = await User.findById(exitedUser._id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationExpiry',
  );

  if (!loginUser) {
    throw new ApiError(500, 'Something went wrong when login user', []);
  }

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie('refreshToken', refreshToken, options)
    .cookie('accessToken', accessToken, options)
    .json(
      new ApiResponse(200, 'User logged in successfully', {
        user: loginUser,
        accessToken,
        refreshToken,
      }),
    );
});

// Logout user
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    { $set: { refreshToken: null } },
    { new: true },
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  res.clearCookie('accessToken', options);
  res.clearCookie('refreshToken', options);

  res
    .status(200)
    .json(new ApiResponse(200, 'User logged out successfully', {}));
});

// get Current User
const getCurrentUser = asyncHandler(async (req, res) => {
  res.status(200).json(
    new ApiResponse(200, 'Current user fetched successfully', {
      user: req.user,
    }),
  );
});

// verify email
const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken) {
    throw new ApiError(400, 'Invalid or missing verification token', []);
  }

  const hashedToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, 'Invalid or expired verification token', []);
  }

  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;
  user.isEmailVerified = true;

  await user.save({ validateBeforeSave: false });

  return res.status(200).json(
    new ApiResponse(200, 'Email verified successfully', {
      isEmailVerified: true,
    }),
  );
});

//resend verification email
const resendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    throw new ApiError(404, 'User not found', []);
  }

  if (user.isEmailVerified) {
    throw new ApiError(400, 'Email is already verified', []);
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Please verify your email',
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get('host')}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        'Verification email has been sent on your email',
        {},
      ),
    );
});

//refresh token
const refreshToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, 'No refresh token provided', []);
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, 'Invalid refresh token', []);
    }

    if (user?.refreshToken !== incomingRefreshToken) {
      throw new ApiError(401, 'RefreshToken in expired', []);
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    user.save();

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie('accessToken', accessToken, options)
      .cookie('refreshToken', newRefreshToken, options)
      .json(
        new ApiResponse(200, 'Token refreshed successfully', {
          accessToken,
          refreshToken: newRefreshToken,
        }),
      );
  } catch (error) {
    throw new ApiError(401, 'Invalid refresh token', []);
  }
});

//forgot password \
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, 'Please provide email', []);
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, 'User not found', []);
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordTokenExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Reset your password',
    mailgenContent: passwordResetMailgenContent(
      user?.username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  res.status(200).json(new ApiResponse(200, 'Password reset email sent', {}));
});

//reset forgot password
const resetForgotPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  if (!resetToken) {
    throw new ApiError(400, 'Invalid or missing reset token', []);
  }

  if (!newPassword) {
    throw new ApiError(400, 'Please provide new password', []);
  }

  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, 'Invalid or expired reset token', []);
  }

  user.forgotPasswordToken = undefined;
  user.forgotPasswordTokenExpiry = undefined;

  user.password = newPassword;
  await user.save({ validateBeforeSave: true });
  res.status(200).json(new ApiResponse(200, 'Password reset successfully', {}));
});

//change password
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!newPassword) {
    throw new ApiError(400, 'Please provide new password', []);
  }

  const user = await User.findById(req.user?._id);
  if (!user) {
    throw new ApiError(404, 'User not found', []);
  }

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordCorrect) {
    throw new ApiError(400, 'Old password is incorrect', []);
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: true });
  res
    .status(200)
    .json(new ApiResponse(200, 'Password changed successfully', {}));
});

export {
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
};
