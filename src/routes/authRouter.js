import express from 'express';
import * as authController from '../controllers/authController.js';
import { isNotAuthenticated } from '../middlewares/authMiddleware.js';

const router = express.Router();

router.post('/register', isNotAuthenticated, authController.register);
router.get('/activate/:token', isNotAuthenticated, authController.activateAccount);
router.post('/login', isNotAuthenticated, authController.login);
router.get('/logout', authController.logout);
router.post('/forgot-password', isNotAuthenticated, authController.forgotPassword);
router.patch('/reset-password/:token', isNotAuthenticated, authController.resetPassword);

app.all('*', (req, res, next) => {
  res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server!`
  });
});

// routes/authRouter.js
import passport from 'passport';

// Google
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

router.get('/google/callback', passport.authenticate('google', {
  failureRedirect: '/login',
  session: false
}), (req, res) => {
  // Successful authentication, create JWT and redirect
  const token = signToken(req.user._id);
  res.cookie('jwt', token, {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  });
  
  res.redirect('/profile');
});

// Similar routes for Facebook and GitHub...

export default router;
