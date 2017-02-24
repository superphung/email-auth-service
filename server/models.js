import mongoose from 'mongoose'
import bcrypt from 'bcrypt-nodejs'

const userSchema = mongoose.Schema({
  username: {type: String},
  password: {type: String}
})

const User = mongoose.model('User', userSchema)

User.schema.pre('save', function (next) {
  const schema = this
  if (!schema.isModified('password')) {
    return next()
  }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return next(err)
    }
    bcrypt.hash(schema.password, salt, null, (err, hash) => {
      if (err) {
        return next(err)
      }
      schema.password = hash
      next()
    })
  })
})

export {
  User
}

