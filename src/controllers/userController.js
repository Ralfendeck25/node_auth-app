import User from '../models/User.js';

export const getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    next(err);
  }
};

export const updateProfile = async (req, res, next) => {
  try {
    // Filter out unwanted fields that should not be updated
    const filteredBody = {};
    if (req.body.name) filteredBody.name = req.body.name;
    
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    next(err);
  }
};

export const updatePassword = async (req, res, next) => {
  try {
    // 1) Get user from collection
    const user = await User.findById(req.user.id).select('+password');

    // 2) Check if POSTed current password is correct
    if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
      return res.status(401).json({ message: 'Your current password is wrong' });
    }

    // 3) If so, update password
    if (req.body.newPassword !== req.body.newPasswordConfirm) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    user.password = req.body.newPassword;
    await user.save();

    // 4) Log user in, send JWT
    createSendToken(user, 200, res);
  } catch (err) {
    next(err);
  }
};

export const updateEmail = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select('+password');
    
    // 1) Verify current password
    if (!(await user.correctPassword(req.body.password, user.password))) {
      return res.status(401).json({ message: 'Your password is incorrect' });
    }
    
    // 2) Verify new email is different
    if (req.body.newEmail === user.email) {
      return res.status(400).json({ message: 'New email must be different' });
    }
    
    // 3) Check if new email already exists
    const emailExists = await User.findOne({ email: req.body.newEmail });
    if (emailExists) {
      return res.status(400).json({ message: 'Email already in use' });
    }
    
    // 4) Notify old email
    const message = `Your email has been changed from ${user.email} to ${req.body.newEmail}.`;
    await sendEmail({
      email: user.email,
      subject: 'Email Change Notification',
      message
    });
    
    // 5) Update email
    user.email = req.body.newEmail;
    await user.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Email updated successfully'
    });
  } catch (err) {
    next(err);
  }
};
