const express = require('express')
const bodyParser = require('body-parser')
const hmacSHA256 = require('crypto-js/hmac-sha256')
const fs = require('fs')
const ip = require('ip').address()
require('dotenv').config()


const app = express()

let jsonParser = bodyParser.json({ type: 'application/json' })

app.use(jsonParser)
app.use(express.static('public'))


const flag = 'ispclub{______________g00d______________j0b______________<333}'
const { SECRET_KEY } = process.env

app.get('/', (req, res) => {
    res.send(fs.readFileSync('./views/index.html', { encoding: 'utf-8' }))
})

app.get('/~', (req, res) => {
    res.status(200)
    req.header('Content-Type', 'application/x-javascript');
    let source = fs.readFileSync('index.js', { encoding: 'utf-8' })
    source = source.replace(/ispclub{(.+?)}/, '??????????????????')
    res.send(source)
})

app.use('/flag', (req, res) => {
    let { host, nonce } = req.query
    let { verifyKey } = req.body
    let address = req.connection.remoteAddress
    if (address.includes('127.0.0.1')) {
      
        if (host.includes(address) && host.includes(ip) && host.length !== address.length + ip.length) {
            let publicKey = hmacSHA256(nonce, SECRET_KEY).toString()
            
            if (publicKey !== verifyKey) {
                verifyKey = hmacSHA256(verifyKey, SECRET_KEY).toString()
                
                if (verifyKey === publicKey) {
                    res.send(`Flag: ${flag}`)
                  
                } else {
                    res.status(403)
                    res.send('Forbidden')
                  
                }
            } else {
                res.status(403)
                res.send('Forbidden')
              
            }
        } else {
            res.status(403)
            res.send('Forbidden')
          
        }
    } else {
        res.status(403)
        res.send('Forbidden')
      
    }
})

app.listen(process.env.PORT, () => {
    console.log(`Listening on port ${process.env.PORT}`)
})