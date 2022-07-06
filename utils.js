const fs = require('fs')
const path = require('path')

const getPaths = async (filePath) => {
	const file = await fs.promises.readdir(filePath)
	return file
}

const getFiles = async (filePath) => {
	const dir = await fs.promises.readdir(filePath)
	const files = await Promise.all(
		dir.map(async (relativePath) => {
			const absolutePath = path.join(filePath, relativePath)
			const stat = await fs.promises.lstat(absolutePath)

			return stat.isDirectory() ? getFiles(absolutePath) : absolutePath
		})
	)

	return files.flat()
}

const getTokens = async (jwt) => {
	const access_token = await jwt.sign(
		{
			user: {
				name: process.env.PUBLIC_KEY,
			},
		},
		{ expiresIn: process.env.ACCESS_TOKEN_LIFE }
	)
	const refresh_token = await jwt.sign(
		{
			user: {
				name: process.env.PUBLIC_KEY,
			},
		},
		{ expiresIn: process.env.REFRESH_TOKEN_LIFE }
	)

	return { access_token, refresh_token }
}

const extractToken = (request) => {
	return request.headers.authorization.replace('Bearer ', '')
}

module.exports = { getFiles, getPaths, getTokens, extractToken }
