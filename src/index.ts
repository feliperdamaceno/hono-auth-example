import type { JwtVariables } from 'hono/jwt'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { jwt, sign } from 'hono/jwt'
import { setCookie } from 'hono/cookie'

type Token = { email: string; exp: number }
type Bindings = { JWT_SECRET: string }
type Variables = JwtVariables<Token>

type User = {
  email: string
  password: string
}

const JWT_SECRET = process.env.JWT_SECRET!

const database: Map<string, User> = new Map()

async function getHashedPassword(password: string) {
  return await Bun.password.hash(password, {
    algorithm: 'bcrypt',
    cost: 4
  })
}

const app = new Hono<{
  Bindings: Bindings
  Variables: Variables
}>()

app.use(logger())
app.use(
  '/auth/*',
  jwt({
    secret: JWT_SECRET,
    cookie: 'token'
  })
)

app.get('/', (c) => {
  return c.json({ message: 'Server working!' })
})

app.post('/signup', async (c) => {
  const { email, password } = await c.req.json<Partial<User>>()

  if (!email || !password) {
    c.status(400)
    return c.json({ message: 'Please provide valid credentials' })
  }

  if (database.get(email)) {
    c.status(400)
    return c.json({ message: `User with email <${email}> already exist` })
  }

  const user = {
    email,
    password: await getHashedPassword(password)
  }

  database.set(email, user)

  return c.json({
    message: `User <${email}> successfully created`,
    user: user
  })
})

app.post('/login', async (c) => {
  const { email, password } = await c.req.json<Partial<User>>()

  if (!email || !password) {
    c.status(400)
    return c.json({ message: 'Please provide valid credentials' })
  }

  const user = database.get(email)
  if (!user) {
    c.status(404)
    return c.json({ message: `User with email <${email}> has not been found` })
  }

  const isValidPassword = await Bun.password.verify(password, user.password)
  if (!isValidPassword) {
    c.status(401)
    return c.json({ message: 'Invalid password provided' })
  }

  const token = await sign(
    { email, exp: Math.floor(Date.now() / 1000) + 60 * 15 },
    JWT_SECRET
  )

  setCookie(c, 'token', token, {
    path: '/',
    maxAge: 900,
    httpOnly: process.env.NODE_ENV! === 'production',
    sameSite: 'Strict',
    secure: process.env.NODE_ENV! === 'production'
  })

  return c.json({ message: `User <${email}> logged in successfully` })
})

app.get('/users', (c) => {
  return c.json({
    users: Array.from(database.values())
  })
})

app.get('/auth/protected', (c) => {
  const payload = c.get('jwtPayload')
  return c.json({
    message: `Welcome ${payload.email}!`
  })
})

export default app
