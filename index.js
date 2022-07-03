require('dotenv').config()

const fastify = require('fastify')
const path = require('path')

const app = fastify({ logger: process.env.NODE_ENV === 'development' })

app.register(require('@fastify/cors'), {
	origin:
		process.env.NODE_ENV === 'development' ? '*' : 'https://www.example.com',
	methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
	allowedHeaders: '*',
})

app.register(require('@fastify/jwt'), {
	secret: process.env.PRIVATE_KEY,
	cookie: {
		cookieName: 'token',
		signed: false,
	},
})

app.register(require('@fastify/cookie'))

app.decorate('authenticate', async function (request, reply) {
	try {
		await request.jwtVerify()
	} catch (err) {
		reply.send(err)
	}
})

app.route({
	method: 'GET',
	url: '/',
	handler: async (request, reply) => {
		reply.send({ hello: 'world' })
	},
})

app.route({
	method: 'POST',
	url: '/ping',
	schema: {
		summary: 'Login',
		description: 'Only @Giridhar is allowed!',
		tags: ['auth'],
		body: {
			type: 'object',
			required: ['password'],
			properties: {
				password: { type: 'string' },
			},
		},
	},
	handler: async (request, reply) => {
		const { password } = request.body
		// const match = await bcrypt.compare(password, process.env.PASSWORD)
		const match = password === process.env.PASSWORD
		if (match) {
			const { access_token, refresh_token } = await getTokens(app.jwt)

			reply
				.cookie('token', refresh_token, {
					expires: new Date(Date.now() + process.env.REFRESH_TOKEN_LIFE),
					httpOnly: true,
					secure: process.env.NODE_ENV === 'production',
					sameSite: 'strict',
				})
				.send({ message: 'Welcome!', access_token })
		} else {
			reply.send({ message: 'Wrong password!' })
		}
	},
})

app.listen({ port: process.env.PORT || 8080 }, (err, address) => {
	if (err) {
		return console.log('Error: ', err)
	}
	return console.log(`Server listening on ${address} 🚀`)
})
