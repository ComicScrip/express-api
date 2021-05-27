const authRouter = require('express').Router();
const User = require('../models/user');

authRouter.post('/checkCredentials', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findByEmail(email);
  if (user) {
    if (await User.verifyPassword(password, user.hashedPassword)) {
      res.send('Valid credentials !');
    } else {
      res.send('Invalid Credentials');
    }
  } else {
    res.send('Invalid Credentials');
  }
});

module.exports = authRouter;
