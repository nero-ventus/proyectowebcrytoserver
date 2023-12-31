const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require('crypto');
const bodyParser = require('body-parser');
const forge = require('node-forge');
const {createDiffieHellman} = require("diffie-hellman");
const prime = Buffer.from('', 'hex');
const generator = Buffer.from('', 'hex');

function toHex(str) {
    return str
        .toString(16) // Convert to hexadecimal representation
        .padStart(str.length * 2, '0'); // Pad with leading zeros to ensure consistent length
}

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for 587, false for other ports
    requireTLS: true,
    auth: {
        user: '', // Reemplaza con tu correo electrónico
        pass: '' // Reemplaza con tu contraseña
    }
});

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
    host: "",
    user: "",
    password: "",
    database: ""
});

app.post('/signup', (req, res) => {
    const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
    const dh = createDiffieHellman(prime, generator);
    dh.generateKeys();
    const token = crypto.createHash('md5').update(req.body.email + req.body.password).digest('hex');
    const values = [
        req.body.username,
        req.body.email,
        req.body.password,
        token
    ];

    const sqlkeys = 'insert into userkeys (usertoken, publickey, privatekey, dhpublickey, dhprivatekey) values (?)';
    db.query(sqlkeys, [[token, publicKeyPem, privateKeyPem, dh.getPublicKey('hex'), dh.getPrivateKey('hex')]], (err, data) => {
        if(err) {
            console.log(err);
            const deleteSql = 'DELETE FROM userkeys WHERE usertoken = ?';
            db.query(deleteSql, [token], (deleteErr, deleteData) => {
                if (deleteErr) {
                    console.log(deleteErr);
                }
                console.log('Usuario eliminado al generar llaves');
            });
            return res.status(500).send(`Error al resgistrar usuario`);
        }

        const sql = 'INSERT INTO users (username, email, password, token, email_confirmed) VALUES (?, false)';
        db.query(sql, [values], (err, data) => {
            if(err) {
                console.log(err);
                return res.status(500).send(`Error al resgistrar usuario`);
            }

            const mailOptions = {
                from: 'apolopets666@gmail.com',
                to: req.body.email,
                subject: 'Confirmación de Registro',
                text: 'Por favor, confirma tu registro ingresando al siguiente enlace: http://localhost:8081/confirmemail?token=' + token
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    const deleteSql = 'DELETE FROM users WHERE email = ?';
                    db.query(deleteSql, [req.body.email], (deleteErr, deleteData) => {
                        if (deleteErr) {
                            console.log(deleteErr);
                        }
                        console.log('Usuario eliminado debido al error al enviar el correo');
                    });

                    return res.status(500).send(`Error al enviar el correo de confirmación. Usuario no registrado`);
                } else {
                    console.log('Correo de confirmación enviado: ' + info.response);
                    return res.json("Registro exitoso");
                }
            });
        });
    });
});

app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM users WHERE email = ? AND password = ? AND email_confirmed = true';

    db.query(sql, [req.body.username, req.body.password], (err, data) => {
        if(err){
            console.log(err)
            return res.status(500).send(`Error al enviar buscar usuario`);
        }
        if (data.length > 0) {
            // Usuario autenticado correctamente
            return res.json({user: data[0].username, token: data[0].token});
        } else {
            // Usuario no encontrado o credenciales incorrectas
            return res.status(500).send(`Credenciales incorrectas o correo no confirmado`);
        }
    });
});

app.get('/confirmemail', (req, res) => {
    const token = req.query.token; // Obtén el token de la URL

    // Aquí puedes buscar el token en la base de datos y realizar la confirmación del correo
    const sql = 'UPDATE users SET email_confirmed = true WHERE token = ?';
    db.query(sql, [token], (err, data) => {
        if(err){
            console.log(err);
            return res.status(500).send(`Error al enviar el confirmar correo`);
        }
        if (data.affectedRows > 0) {
            // Si al menos una fila se vio afectada (es decir, se actualizó correctamente), se confirma el correo
            return res.send('Correo confirmado exitosamente');
        } else {
            // Si no se encontró ningún token coincidente en la base de datos
            return res.status(500).send(`Error al confirmar correo`);
        }
    });
});

app.post('/recover', (req, res) => {
    const email = req.body.email;
    console.log(email);

    const sql = 'SELECT * FROM users WHERE email = ? AND email_confirmed = true';
    db.query(sql, [email], (err, data) => {
        if(err){
            console.log(err);
            return res.status(500).send(`Error al buscar cuenta`);
        }
        if (data.length > 0) {
            const token = data[0].token;
            const mailOptions = {
                from: 'apolopets666@gmail.com',
                to: req.body.email,
                subject: 'Recuperacion de cuenta',
                text: 'Por favor, recupera tu cuenta ingresando al siguiente enlace: http://localhost:8081/recover2?token=' + token
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send(`Error al enviar el correo de recuperacion`);
                } else {
                    console.log('Correo de recuperacion enviado: ' + info.response);
                    res.json("Correo exitoso");
                }
            });

        } else {
            // Si no se encontró ningún token coincidente en la base de datos
            return res.status(500).send(`Usuario no registrado`);
        }
    });
});

app.get('/recover2', (req, res) => {
    const token = req.query.token; // Obtén el token de la solicitud POST
    console.log(token);

    const sql = 'SELECT * FROM users WHERE token = ?';
    db.query(sql, [token], (err, data) => {
        if(err){
            console.log(err);
            return res.status(500).send(`Error al buscar cuenta`);
        }
        if (data.length > 0) {
            res.send(`
                <html>
                <body>
                    <h2>Restablecer Contraseña</h2>
                    <form action="/recover3" method="post">
                        <input type="hidden" name="token" value="${token}">
                        <label for="password">Nueva Contraseña:</label>
                        <input type="password" id="password" name="password" required>
                        <button type="submit">Restablecer Contraseña</button>
                    </form>
                </body>
                </html>
            `);

        } else {
            // Si no se encontró ningún token coincidente en la base de datos
            return res.status(500).send(`Token invalido`);
        }
    });
});

app.use(bodyParser.urlencoded({ extended: false }));

app.post('/recover3', (req, res) => {
    const token = req.body.token;
    const newPassword = crypto.createHash('md5').update(req.body.password).digest('hex')

    const updateSql = 'UPDATE users SET password = ? WHERE token = ?';
    db.query(updateSql, [newPassword, token], (updateErr, updateData) => {
        if (updateErr) {
            console.log(updateErr);
            return res.status(500).send(`Error al actualizar la contraseña`);
        }

        if (updateData.affectedRows > 0) {
            // Si al menos una fila se vio afectada (es decir, se actualizó correctamente), se confirma el correo
            return res.send('Contraseña actualizada exitosamente');
        } else {
            // Si no se encontró ningún token coincidente en la base de datos
            return res.status(500).send(`Contraseña no valida`);
        }
    });
});

app.post('/buy', (req, res) => {
    const sqlgetkeys = 'select * from userkeys where usertoken = ?';

    db.query(sqlgetkeys, [req.body.token], (err, data) => {
        if(err){
            console.log(err)
            return res.status(500).send(`Error registrar la compra`);
        }

        const privateKey = forge.pki.privateKeyFromPem(data[0].privatekey);
        const date = new Date();

        const billToken = crypto.createHash('md5').update(req.body.token + req.body.description + date.toDateString()).digest('hex');
        const md = forge.md.md5.create(); // Usamos el algoritmo de hash SHA-256
        md.update(billToken, 'utf8');
        const signature = privateKey.sign(md);

        const values = [
            req.body.username,
            date.toDateString(),
            req.body.description,
            req.body.token,
            billToken,
            forge.util.bytesToHex(signature)
        ];

        const sql = 'INSERT INTO bill (username, date, description, usertoken, billtoken, signature) VALUES (?)';

        db.query(sql, [values], (err, data) => {
            if(err){
                console.log(err)
                return res.status(500).send(`Error registrar la compra`);
            }
            return res.status(200).send("Compra registrada");
        });
    });
});

app.get('/shoppinglist', (req, res) => {
    const { token } = req.query; // Suponiendo que los datos llegan como parámetros de consulta (query parameters)

    // Realiza la consulta a la base de datos para obtener la lista de compras del usuario
    const sql = 'SELECT * FROM bill WHERE usertoken = ?';

    db.query(sql, [token], (err, data) => {
        if (err) {
            console.error('Error al obtener la lista de compras', err);
            return res.status(500).json({ error: 'Error al obtener la lista de compras' });
        }

        // Si se obtienen los datos correctamente, enviar la lista de compras al cliente
        const shoppingList = data.map(item => [item.date, item.description, item.billtoken]);
        return res.status(200).json({ shoppingList });
    });
});

app.get('/getOneBill', (req, res) => {

    const { token } = req.query; // Suponiendo que los datos llegan como parámetros de consulta (query parameters)

    // Realiza la consulta a la base de datos para obtener la lista de compras del usuario
    const sql = 'SELECT * FROM bill WHERE billtoken = ?';

    db.query(sql, [token], (err, data) => {
        if (err) {
            console.error('Error al obtener la lista de compras', err);
            return res.status(500).json({ error: 'Error al obtener factura' });
        }
        if (data.length > 0)
            return res.status(200).json(data);
        else
            return res.status(500).json("Factura no encontrada");
    });

});

app.get('/validatebill1', (req, res) => {
    const token = req.query.token; // Obtén el token de la solicitud POST

    const sql = 'SELECT * FROM bill WHERE billtoken = ?';
    db.query(sql, [token], (err, data) => {
        if(err){
            console.log(err);
            return res.status(500).send(`Error al buscar factura`);
        }
        if (data.length > 0) {
            res.send(`
                <html>
                <body>
                    <h2>Datos de Factura</h2>
                    <h3>Usuario: ${data[0].username}</h3>
                    <h3>Fecha: ${data[0].date}</h3>
                    <h3>Descripcion: ${data[0].description}</h3>
                    <h3>Firma: ${data[0].signature}</h3>
                    <h2>Validar Firma</h2>
                    <form action="/validatebill2" method="get">
                        <input type="hidden" name="token" value="${token}">
                        <label for="password">LLave Publica: </label>
                        <input type="password" id="publickey" name="publickey" required>
                        <button type="submit">Validar</button>
                    </form>
                </body>
                </html>
            `);

        } else {
            // Si no se encontró ningún token coincidente en la base de datos
            return res.status(500).send(`Firma invalida`);
        }
    });
});

app.get('/validatebill2', (req, res) => {
    const token = req.query.token; // Obtén el token de la solicitud POST
    try {
        const publicKey = forge.pki.publicKeyFromPem(req.query.publickey);
        // Operaciones adicionales con la clave pública
        const sql = 'SELECT * FROM bill WHERE billtoken = ?';
        db.query(sql, [token], (err, data) => {
            if(err){
                console.log(err);
                return res.status(500).send(`Error al buscar factura`);
            }
            if (data.length > 0) {

                const billToken = crypto.createHash('md5').update(data[0].usertoken + data[0].description + data[0].date).digest('hex');
                const mdVerify = forge.md.md5.create();
                mdVerify.update(billToken, 'utf8');
                let verified = false;
                try {
                    verified = publicKey.verify(mdVerify.digest().bytes(), forge.util.hexToBytes(data[0].signature));
                } catch (error) {
                    // Captura cualquier error que pueda ocurrir al intentar verificar la firma
                    console.error('Error al verificar la firma:', error.message);
                }

                if(verified)
                    res.send(`
                        <html>
                        <body>
                            <h2>Firma Valida</h2>
                        </body>
                        </html>
                    `);
                else
                    return res.status(500).send(`Firma invalida`);

            } else {
                // Si no se encontró ningún token coincidente en la base de datos
                return res.status(500).send(`Firma invalida`);
            }
        });
    } catch (error) {
        return res.status(500).send(`Llave invalida`);
        // Manejo de errores
    }
});

app.get('/getpublickey', (req, res) => {
    const { token } = req.query;

    const sqlgetkeys = 'select * from userkeys where usertoken = ?';

    db.query(sqlgetkeys, [token], (err, data) => {
        if(err){
            console.log(err)
            return res.status(500).send(`Error al buscar llave`);
        }
        if (data.length > 0)
            return res.status(200).json({publickey: data[0].publickey});
        else
            return res.status(500).json("Llave no encontrada");
    });
});

app.get('/getdhpublickey', (req, res) => {
    const { token } = req.query;

    const sqlgetkeys = 'select * from userkeys where usertoken = ?';

    db.query(sqlgetkeys, [token], (err, data) => {
        if(err){
            console.log(err)
            return res.status(500).send(`Error al buscar llave`);
        }
        if (data.length > 0)
            return res.status(200).json({dhpublickey: data[0].dhpublickey});
        else
            return res.status(500).json("Llave no encontrada");
    });
});

app.get('/generatedhsecret', (req, res) => {
    const { token, dhpublickey } = req.query;

    const sqlgetkeys = 'select * from userkeys where usertoken = ?';

    db.query(sqlgetkeys, [token], (err, data) => {
        if(err){
            console.log(err)
            return res.status(500).send(`Error al buscar llave`);
        }
        if (data.length > 0) {
            const yourPrivateKey = Buffer.from(data[0].dhprivatekey, 'hex');
            const otherPublicKeyBuffer = Buffer.from(dhpublickey, 'hex');

            const dh = crypto.createDiffieHellman(prime, generator);
            dh.setPrivateKey(yourPrivateKey);
            const secret = dh.computeSecret(otherPublicKeyBuffer);

            return res.status(200).json({dhsecretkey: secret.toString('hex')});
        }
        else {
            return res.status(500).json("Llave no encontrada");
        }
    });
});

app.listen(8081,() => {
    console.log("listening")
});