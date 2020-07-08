const { Router } = require('express');
const router = Router();

const User = require('../models/User');
const verifyToken = require('./verifyToken');

const jwt = require('jsonwebtoken');
const config = require('../config');

router.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const user = new User({
    username,
    email,
    password,
  });
  user.password = await user.encryptPassword(password);
  await user.save();
  const token = jwt.sign({ id: user.id }, config.secret, {
    expiresIn: 60 * 60 * 24,
  });
  res.json({ auth: true, token });
});

router.get('/me', verifyToken, async (req, res) => {
  const user = await User.findById(req.userId, { password: 0 });
  if (!user) {
    return res.status(404).send('No user found');
  }
  res.status(200).json(user);
});

router.post('/signin', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(404).send('The email is not registered');
  }
  const validPassword = await user.validatePassword(
    req.body.password,
    user.password
  );
  if (!validPassword) {
    return res.status(401).send({ auth: false, token: null });
  }
  const token = jwt.sign({ id: user._id }, config.secret, {
    expiresIn: 60 * 60 * 24,
  });
  res.status(200).json({ auth: true, token });
});

router.get('/logout', function (req, res) {
  res.status(200).send({ auth: false, token: null });
});

module.exports = router;
