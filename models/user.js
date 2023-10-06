const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const AuthError = require('../errors/AuthError');
const { Schema } = mongoose;

const { URL_REGEX } = require('../utils/constants');

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      validate: {
        validator: (email) => /.+@.+\..+/.test(email),
        message: 'Требуется ввести электронный адрес',
      },
    },

    password: {
      type: String,
      required: true,
      select: false,
    },

    name: {
      type: String,
      default: 'Жак-Ив Кусто',
      minlength: [2, 'Имя не может быть короче 2 символов'],
      maxlength: [30, 'Имя не может быть длиннее 30 символов'],
    },

    about: {
      type: String,
      default: 'Исследователь',
      validate: {
        validator: ({ length }) => length >= 2 && length <= 30,
        message: 'Информация о пользователе должна быть длиной от 2 до 30 символов',
      },
    },

    avatar: {
      type: String,
      default: 'https://pictures.s3.yandex.net/resources/jacques-cousteau_1604399756.png',
      validate: {
        validator: (url) => URL_REGEX.test(url),
        message: 'Требуется ввести URL',
      },
    },
  },

  {
    versionKey: false,
    statics: {
      findUserByCredentials(email, password) {
        return this
          .findOne({ email })
          .select('+password')
          .then((user) => {
            if (!user) {
              return Promise.reject(new AuthError('Неправильные почта или пароль'));
            }
            return bcrypt.compare(password, user.password)
              .then((matched) => {
                if (!matched) {
                  return Promise.reject(new AuthError('Неправильные почта или пароль'));
                }
                return user;
              }
            );
          }
        );
      },
    },
  }
);

module.exports = mongoose.model('user', userSchema);
