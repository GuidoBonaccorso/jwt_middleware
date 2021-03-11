const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const unless = require('express-unless');
const bcrypt = require('bcrypt');
const util = require('util');

const app = express();
const port = process.env.PORT ? process.env.PORT : 3000; //me esta proveyendo de un puerto. Es una estructura ternaria (compuesta del ? y :) que permite asignar a una variable un valor u otro en funcion de que una de las condiciones se cumpla. 

const auth = (req, res, next) => {
    try {
        let token = req.headers['authorization'];
        if (!token) {
            throw new Error('No estas logueado');
            //El codigo de arriba sirve justamente para guardar el token generado por el usuario al momento de loguearse.
            //En Headers se encuentra la parte de authorization, donde existe un value, dentro del value se coloca el token generado. Una vez hecho eso despues existe el condicional if que dice que si no hay ningún token, entonces habrá un error.
        }

        token = token.replace('Bearer ', '');
        //replace sirve para modificar el valor del token. En el caso del Bearer, que es el primer argumento, esta palabra se va a colocar delante de lo que dia el token, osea sería: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.. Peeeero, después están las dos comillas simples que lo que hacen es remplaazar la palabra Bearer por un espacio.
        jwt.verify(token, 'Secret', (err, user) => {
            if (err) {
                throw new Error('Token Invalido');
            }
        });
        next();
    } 
    catch(e) {
        res.status(403).send({
            message: e.message
        });
    }
}

auth.unless = unless; //Llamo al framework del express unless
app.use(
    auth.unless({
        path: [{
                url: '/login',
                methods: ['POST', 'GET']
            },
            {
                url: '/registro',
                methods: ['POST']
            }
        ]
    }));


app.use(auth()); //Es la funcion que permite interponer el middleware

app.use(express.json()); //Permite recibir post y put en metodo JSON.


//:::::::::SISTEMA DE AUTENTICACION::::::::::::::::::
//Es el login - Paradoja de la pulserita.

//Paso 1: Registracion : Se utiliza el metodo HTTP POST.

app.post('/registro', async (req, res) => {
    try {
        if (!req.body.usuario || !req.body.clave || !req.body.email || !req.body.celu) {
            throw new Error('Faltan Datos necesarios para el login');
        }

        let query = await query('SELECT * FROM usuario WHERE usuario = ?', [req.body.usuario]);
        if (query.length > 0) {
            throw new Error('Ese usuario ya existe');
        }

        //Encriptacion de clave (Si o si tiene que estar encriptada ya que es informacion sensible);

        const claveEncriptada = await bcrypt.hash(req.body.clave, 10)

        //Guardar el usuario con la clave encriptada

        const usuario = {
            usuario: req.body.usuario,
            clave: claveEncriptada,
            email: req.body.email,
            celu: req.body.celu
        }

        await query('INSERT INTO usuario (usuario, clave, email, celu) VALUES(?, ?, ?, ?)' [usuario, clave, email, celu]);
        res.status(200).send({
            message: "Se registró correctamente"
        });
    } catch (e) {
        res.status(403).send({
            message: e.message
        });
    }
});

//Paso 2: Login

app.post('/login', async (req, res) => {
    try {
        if (!req.body.usuario || !req.body.clave) {
            throw new Error('No enviaste los datos necesarios')
        }

        //Paso 1: Encontrar el usuario
        // let query = 'SELECT * FROM usuarios WHERE usuario = ?';
        // let respond = await qy(query, [req.body.usuario]);
        // res.status(200).send(respond)
        // if (respond.length == 0) {
        // //     throw new Error ('Usuario no encontrado');
        // //
        // //Paso 2: Verificar la clave
        // //const claveEncriptada = "asdasdasd";

        // if(!bcrypt.compareSync(req.body.clave, claveEncriptada)) {
        //     throw new Error ('Falló el Login');
        // }

        //Paso 3: Manejo de la sesion
        const tokenData = {
            nombre: 'Guido',
            apellido: 'Bonaccorso',
            user_id: 1
        }

        //Generacion real del token que se va a generar
        const token = jwt.sign(tokenData, 'Secret', {
            expiresIn: 60 * 60 * 24 //24 horas.
        })
        res.send({
            token
        });
        //Secret se utiliza tambien como cadena de caracteres para la generacion del token.


    } catch (e) {
        res.status(413).send({
            message: e.message
        });
    }
})



//:::::::::MANEJO DE SESIONES::::::::::::::::::::::::
//Es aquello que me va a permitir conservar la informacion de esa autenticacion, evitando tener que preguntar todo el tiempo de la contrasena.





app.listen(port, () => {
    console.log('Servidor escuchando en el puerto', port);
});