const argon2 = require('argon2');
const db = require('../db');
const Joi = require('joi');

const emailAlreadyExists = (email) => {
  return db.user.findFirst({ where: { email } }).then((user) => !!user);
};

const findByEmail = (email) => {
  return db.user.findFirst({ where: { email } });
};

const hashingOptions = {
  memoryCost: 2 ** 16,
  timeCost: 5,
  type: argon2.argon2id,
};

const hashPassword = (plainPassword) => {
  return argon2.hash(plainPassword, hashingOptions);
};

const verifyPassword = (plainPassword, hashedPassword) => {
  return argon2.verify(hashedPassword, plainPassword, hashingOptions);
};

const create = async ({ email, password }) => {
  const hashedPassword = await hashPassword(password);
  return db.user.create({ data: { email, hashedPassword } });
};

const validate = (data) =>
  Joi.object({
    email: Joi.string().email().max(255).required(),
    password: Joi.string().min(8).max(100).required(),
  }).validate(data, { abortEarly: false }).error;

module.exports = {
  emailAlreadyExists,
  hashPassword,
  create,
  findByEmail,
  verifyPassword,
  validate,
};
