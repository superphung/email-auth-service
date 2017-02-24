import * as db from './models'
import auth from 'basic-auth'
import jwt from 'jwt-simple'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt-nodejs'
import jwtMiddleware from 'express-jwt'
import cors from 'cors'

import app from './app'
const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost/identitydb'
const PORT = process.env.PORT || 3002
const SECRET = process.env.SECRET

mongoose.connect(MONGO_URL)

app.use(cors())

app.get('/login', async (req, res) => {
  const credentials = auth(req)
  if (!credentials) {
    return res.status(401).json('unauthorized')
  }
  const user = await db.User.findOne({username: credentials.name})
  if (!user) {
    return res.status(401).json('unauthorized')
  }
  bcrypt.compare(credentials.pass, user.password, function (err, data) {
    if (err || !data) {
      return res.status(401).json('unauthorized')
    }
    const payload = {
      sub: user._id
    }
    const token = jwt.encode(payload, SECRET)
    return res.status(200).json({token})
  })
})

app.get('/authenticate', jwtMiddleware({secret: SECRET}), async (req, res) => {
  if (!req.user || !req.user.sub) {
    return res.status(401).json('unauthorized')
  }
  const user = await db.User.findById(req.user.sub)
  if (!user) {
    return res.status(401).json('unauthorized')
  }
  return res.status(200).json({message: 'ok'})
})

app.listen(PORT)
