require('dotenv').config()

const fastify = require('fastify')
const path = require('path')
const fs = require('fs')
const multer = require('fastify-multer')
const { getFiles, getTokens, extractToken } = require('./utils')

const app = fastify()

app.register(multer.contentParser)

app.register(require('@fastify/static'), {
	root: path.join(__dirname, 'public'),
})

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

app.decorate('authenticate_refreshtoken', async function (request, reply) {
	try {
		await request.jwtVerify({ onlyCookie: true })
	} catch (err) {
		reply.send(err)
	}
})

const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		const dir = file.mimetype.split('/')[0]
		const upload_path = path.join(__dirname, !!dir ? `public/${dir}` : 'public')
		if (fs.existsSync(upload_path)) {
			cb(null, upload_path)
		} else {
			fs.mkdir(upload_path, (err) => {
				if (err) {
					return console.error(err)
				}
				cb(null, upload_path)
			})
		}
	},
	filename: (req, file, cb) => {
		cb(null, Date.now() + '-' + file.originalname)
	},
})

const upload = multer({ storage })

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

app.route({
	method: 'GET',
	url: '/refresh_token',
	onRequest: [app.authenticate_refreshtoken],
	schema: {
		summary: 'Refresh token',
		tags: ['auth'],
		cookies: {
			refresh_token: {
				type: 'string',
				required: true,
			},
		},
	},
	handler: async (request, reply) => {
		const { token } = request.cookies
		const { user } = await app.jwt.verify(token, {
			algorithm: 'HS256',
		})

		if (user.name !== process.env.PUBLIC_KEY) {
			reply.send({ message: 'Wrong user!' })
		}

		const { access_token, refresh_token } = await getTokens(app.jwt)

		reply.setCookie('token', refresh_token, {
			expires: new Date(Date.now() + process.env.REFRESH_TOKEN_LIFE),
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'strict',
		})
		reply.send({ access_token })
	},
})

app.route({
	method: 'GET',
	url: '/data',
	onRequest: [app.authenticate],
	schema: {
		summary: 'Get all files',
		tags: ['files'],
		querystring: {
			type: 'object',
			properties: {
				dir: { type: 'string' },
			},
		},
		response: {
			200: {
				type: 'object',
				properties: {
					files: {
						type: 'array',
						items: {
							type: 'object',
							properties: {
								file_path: { type: 'string' },
								file_type: { type: 'string' },
								file_name: { type: 'string' },
							},
						},
					},
				},
			},
		},
	},
	handler: async (request, reply) => {
		const { dir } = request.query

		try {
			const token = extractToken(request)
			const { user } = await app.jwt.verify(token, {
				algorithm: 'HS256',
			})

			if (user.name !== process.env.PUBLIC_KEY) {
				reply.send({ message: 'Wrong user!' })
			}

			const files_path = path.join(
				process.cwd(),
				!!dir ? `public/${dir}` : 'public'
			)
			const data = await getFiles(files_path)
			reply.send({
				files: data?.map((file) => ({
					file_path: file,
					file_type: file.split('.').pop(),
					file_name: file.split(/(\\|\/)/g).pop(),
				})),
			})
		} catch (err) {
			console.log(err)
		}
	},
})

app.route({
	method: 'POST',
	url: '/upload',
	onRequest: [app.authenticate],
	schema: {
		summary: 'Upload file',
		tags: ['files'],
		consumes: ['multipart/form-data'],
		response: {
			200: {
				type: 'object',
				properties: {
					originalname: { type: 'string' },
					mimetype: { type: 'string' },
					path: { type: 'string' },
					filename: { type: 'string' },
					size: { type: 'number' },
				},
			},
		},
	},
	preHandler: [upload.single('file')],
	handler: async (request, reply) => {
		const { originalname, mimetype, path, filename, size } = request.file
		reply.send({ originalname, mimetype, path, filename, size })
	},
})

app.route({
	method: 'POST',
	url: '/uploads',
	onRequest: [app.authenticate],
	schema: {
		summary: 'Upload files',
		tags: ['files'],
		consumes: ['multipart/form-data'],
		response: {
			200: {
				type: 'array',
				items: {
					type: 'object',
					properties: {
						originalname: { type: 'string' },
						mimetype: { type: 'string' },
						path: { type: 'string' },
						filename: { type: 'string' },
						size: { type: 'number' },
					},
				},
			},
		},
	},
	preHandler: [upload.array('files')],
	handler: async (request, reply) => {
		const { originalname, mimetype, path, filename, size } = request.file
		reply.send({ originalname, mimetype, path, filename, size })
	},
})

app.route({
	method: 'POST',
	url: '/delete',
	onRequest: [app.authenticate],
	schema: {
		summary: 'Delete file',
		tags: ['files'],
		body: {
			type: 'object',
			properties: {
				file_path: { type: 'string' },
			},
		},
		response: {
			200: {
				type: 'object',
				properties: {
					message: { type: 'string' },
				},
			},
		},
	},
	handler: async (request, reply) => {
		fs.unlink(request.body.file_path, (err) => {
			if (err) {
				console.log(err)
			}
			reply.send({ message: 'File deleted!' })
		})
	},
})

app.listen({ port: process.env.PORT || 8080 }, (err, address) => {
	if (err) {
		return console.log('Error: ', err)
	}
	return console.log(`Server listening on ${address} 🚀`)
})
