const { Router } = require('express');
const router = Router();
const jwt = require('jsonwebtoken');
const config = require('../config');

const User = require('../models/User');

router.post('/signup', async (req, res, next) => {
  const { username, email, password } = req.body;
  const user = new User({
    username: username,
    email: email,
    password: password,
  });
  user.password = await user.encryptPassword(user.password);
  await user.save();
  const token = jwt.sign({ id: user._id }, config.secret, {
    expiresIn: 60 * 60 * 24,
  });
  res.json({ auth: true, token });
});

router.get('/me', async (req, res, next) => {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).json({ auth: false, message: 'No token provided' });
  } else {
    const decoded = jwt.verify(token, config.secret);
    const user = await User.findById(decoded.id, { password: 0 });
    if (!user) {
      return res.status(404).send('No user found');
    } else {
      res.json('user');
    }
  }
});

router.post('/signin', async (req, res, next) => {
  const { email, password } = req.body;
  console.log(email, password);
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).send('The email is not registered');
  }
});

module.exports = router;
