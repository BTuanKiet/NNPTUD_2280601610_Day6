let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let publicKey = fs.readFileSync('public.pem');
module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token) {
                res.status(401).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            // Extract token from "Bearer <token>" format
            if (token.startsWith('Bearer ')) {
                token = token.slice(7);
            }
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
            if (result.exp * 1000 < Date.now()) {
                res.status(401).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(401).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(401).send({
                message: "ban chua dang nhap"
            })
        }
    }
}