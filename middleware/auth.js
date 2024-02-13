const jwt = require('jsonwebtoken')
const {UnauthenticatedError} = require('../errors')

const authMiddleware = async (req, res, next) =>{
    const authHeader = req.headers.authorization

    if(!authHeader || !authHeader.startsWith('Bearer ')){
        throw new UnauthenticatedError('No token Provided')
    }

    const token = authHeader.split(' ')[1]
    //console.log('Received Token:', token)

    if(!token){
        throw new UnauthenticatedError('No token found', 401)
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        //console.log('Decoded Token:', decoded) 

        const {id, username} = decoded
        req.user = {id, username}
        next()
    } catch (error) {
        //console.error('Error verifying token:', error)
        throw new UnauthenticatedError('Not authorized to access this route')
    }

}

module.exports = {
    authMiddleware
}