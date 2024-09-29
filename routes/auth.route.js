const router = require('express').Router();
const User = require('../models/user.model');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const { ensureLoggedOut, ensureLoggedIn } = require('connect-ensure-login');
const { registerValidator } = require('../utils/validators');

// Middleware to check if the user is an admin
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'ADMIN') {
    return next();
  }
  req.flash('error', 'You do not have permission to access this page.');
  return res.redirect('/');
}

// Login route (GET)
router.get(
  '/login',
  ensureLoggedOut({ redirectTo: '/' }),
  async (req, res, next) => {
    res.render('login');
  }
);

// Login form submission (POST)
router.post(
  '/login',
  ensureLoggedOut({ redirectTo: '/' }),
  passport.authenticate('local', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/auth/login',
    failureFlash: true,
  })
);

// Register route (GET) - Only Admins can access
router.get(
  '/register',
  ensureLoggedIn({ redirectTo: '/auth/login' }), // Ensure the user is logged in
  ensureAdmin, // Ensure the user is an admin
  async (req, res, next) => {
    res.render('register');
  }
);

// Register form submission (POST) - Only Admins can register users
router.post(
  '/register',
  ensureLoggedIn({ redirectTo: '/auth/login' }), // Ensure the user is logged in
  ensureAdmin, // Ensure the user is an admin
  registerValidator,
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        errors.array().forEach((error) => {
          req.flash('error', error.msg);
        });
        return res.render('register', {
          email: req.body.email,
          messages: req.flash(),
        });
      }

      const { email } = req.body;
      const doesExist = await User.findOne({ email });
      if (doesExist) {
        req.flash('warning', 'Username/email already exists');
        return res.redirect('/auth/register');
      }

      const user = new User(req.body);
      await user.save();
      req.flash('success', `${user.email} registered successfully, you can now login`);
      res.redirect('/auth/login');
    } catch (error) {
      next(error);
    }
  }
);

// Logout route (GET) - No changes made here
router.get(
  '/logout',
  ensureLoggedIn({ redirectTo: '/' }),
  async (req, res, next) => {
    req.logout();
    res.redirect('/');
  }
);

module.exports = router;
