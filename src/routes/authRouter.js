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

export default router;
