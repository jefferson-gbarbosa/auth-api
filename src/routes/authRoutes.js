const { Router } = require('express');
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');

const router = Router();

router.post('/signup', authController.register);
router.post('/login', authController.login);
router.get('/logout', authController.logout);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password/:token', authController.resetPassword);
router.post('/verify-email', authController.verifyEmail);
router.get('/profile',authMiddleware.requireAuth, authController.infoUser);
router.get('/refresh',authMiddleware.requireRefreshToken, authController.refreshToken);

module.exports = router;