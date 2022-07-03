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
})

app.decorate('authenticate', async function (request, reply) {
	try {
		await request.jwtVerify()
	} catch (err) {
		reply.send(err)
	}
})

// const getToken = (request) => {
// 	return request.headers.authorization.replace('Bearer ', '')
// }

// const getTokenData = async (request) => {
// 	const token = getToken(request)
// 	const decoded = await fastify.jwt.decode(token)
// 	return decoded
// }

// app.decorate('getToken', getToken)
// app.decorate('getTokenData', getTokenData)

app.route({
	method: 'GET',
	url: '/',
	handler: async (request, reply) => {
		reply.send({ hello: 'world' })
	},
})

app.listen({ port: process.env.PORT || 8080 }, (err, address) => {
	if (err) {
		return console.log('Error: ', err)
	}
	return console.log(`Server listening on ${address} 🚀`)
})
