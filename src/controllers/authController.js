import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import sendEmail from '../utils/email.js';

// Helper function to create JWT token
const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  };

  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

export const register = async (req, res, next) => {
  try {
    const { name, email, password, passwordConfirm } = req.body;
    
    // Password validation
    if (password !== passwordConfirm) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }
    
    const newUser = await User.create({
      name,
      email,
      password
    });

    // Create activation token
    const activationToken = newUser.createActivationToken();
    await newUser.save({ validateBeforeSave: false });

    // Send activation email
    const activationURL = `${process.env.CLIENT_URL}/activate/${activationToken}`;
    const message = `Welcome to our app! Please click this link to activate your account: ${activationURL}`;

    await sendEmail({
      email: newUser.email,
      subject: 'Account Activation (Valid for 24 hours)',
      message
    });

    res.status(201).json({
      status: 'success',
      message: 'Activation token sent to email!'
    });
  } catch (err) {
    next(err);
  }
};

export const activateAccount = async (req, res, next) => {
  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).toString('hex');
    
    const user = await User.findOne({
      activationToken: hashedToken,
      activationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Token is invalid or has expired' });
    }

    user.active = true;
    user.activationToken = undefined;
    user.activationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    // Automatically log the user in after activation
    createSendToken(user, 200, res);
  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({ message: 'Incorrect email or password' });
    }

    // 3) Check if user is active
    if (!user.active) {
      return res.status(401).json({ 
        message: 'Please activate your account. Check your email for activation link.' 
      });
    }

    // 4) If everything ok, send token to client
    createSendToken(user, 200, res);
  } catch (err) {
    next(err);
  }
};

export const logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
};

export const forgotPassword = async (req, res, next) => {
  try {
    // 1) Get user based on POSTed email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: 'There is no user with that email address.' });
    }

    // 2) Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // 3) Send it to user's email
    const resetURL = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 min)',
      message
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!'
    });
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    // 1) Get user based on the token
    const hashedToken = crypto.createHash('sha256').update(req.params.token).toString('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
      return res.status(400).json({ message: 'Token is invalid or has expired' });
    }

    if (req.body.password !== req.body.passwordConfirm) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // 3) Log the user in, send JWT
    createSendToken(user, 200, res);
  } catch (err) {
    next(err);
  }
};
