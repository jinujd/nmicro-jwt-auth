import jsonwebtoken  from 'jsonwebtoken'
export class JWTAuth {
    validationSecret
    authHeaderPrefix
    authHeaderName
    constructor(validationSecret, authHeaderName = "authorization" ) {
        this.validationSecret =  validationSecret 
        this.authHeaderName = authHeaderName
    }
    getToken = async (req, res, next, options) => {
        const bearerHeader = req.headers[this.authHeaderName] 
        let bearer
        let token
        if (typeof bearerHeader == 'undefined' || !(bearer = bearerHeader.trim().split(' ')) || !(token = bearer[1]))
            return
        return token
    }
    verifyToken = (token, validationSecret, req, res, next,  options) => new Promise((resolve, reject) => {
        try {
            jsonwebtoken.verify(token, validationSecret, (err, data) => {   
                resolve({
                    err, data
                }) 
            })
        } catch(err) {
            reject(err)
        }
    }) 
    sendAuthResult(data, error) {
        return  {data, error}
    }
    async authenticate(req, res, next, options) { 
        const token = await this.getToken(req, res, next, options)
        if(!token) return this.sendAuthResult(null, `Bearer token is missing. It should be passed via "Authorization" header with prefix "Bearer"`)
        const {data, err} = await this.verifyToken(token, this.validationSecret, req, res, next, options) 
        return  this.sendAuthResult(data, err?err.message: null)
    }
}

         
       