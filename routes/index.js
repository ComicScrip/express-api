const authRouter = require('./auth');
const usersRouter = require('./users');

module.exports = (app) => {
  app.use('/users', usersRouter);
  app.use('/auth', authRouter);
};
