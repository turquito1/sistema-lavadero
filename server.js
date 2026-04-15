const crypto = require('crypto');
const express = require('express');
const mysql = require('mysql2');
const path = require('path');
require('dotenv').config({ quiet: true });

const app = express();
const HORA_REGEX = /^([01]\d|2[0-3]):[0-5]\d$/;
const FECHA_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const OWNER_COOKIE_NAME = 'lavadero_owner_session';
const CLIENT_COOKIE_NAME = 'lavadero_client_session';
const OWNER_SESSION_TTL_SECONDS = 60 * 60 * 12;
const CLIENT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

const OWNER_USER = process.env.OWNER_USER || '';
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || '';
const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    process.env.OWNER_SESSION_SECRET ||
    process.env.DB_PASSWORD ||
    'lavadero-session-secret';

function esOrigenLocalPermitido(origin) {
    if (!origin) {
        return false;
    }

    try {
        const url = new URL(origin);
        return ['localhost', '127.0.0.1'].includes(url.hostname);
    } catch (error) {
        return false;
    }
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (esOrigenLocalPermitido(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }

    return next();
});
app.use(express.static(path.join(__dirname, 'public')));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const dbPromise = db.promise();
let schemaReadyPromise = null;

function asegurarEsquemaClientes() {
    if (!schemaReadyPromise) {
        schemaReadyPromise = dbPromise.query(
            `
                CREATE TABLE IF NOT EXISTS clientes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    nombre VARCHAR(50) NOT NULL,
                    apellido VARCHAR(50) NOT NULL,
                    barrio VARCHAR(100) NOT NULL,
                    manzana VARCHAR(10) NOT NULL,
                    lote VARCHAR(10) NOT NULL,
                    telefono VARCHAR(20) NOT NULL,
                    email VARCHAR(100) NOT NULL,
                    password_salt VARCHAR(64) NOT NULL,
                    password_hash VARCHAR(128) NOT NULL,
                    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_clientes_email (email)
                )
            `
        )
            .then(() => {
                console.log('Tabla clientes lista.');
            })
            .catch((error) => {
                schemaReadyPromise = null;
                throw error;
            });
    }

    return schemaReadyPromise;
}

db.connect((err) => {
    if (err) {
        console.error('Error conectando a la base de datos:', err);
        return;
    }

    console.log('Conectado a la base de datos del lavadero.');
    asegurarEsquemaClientes().catch((error) => {
        console.error('Error preparando la tabla clientes:', error);
    });
});

function esFechaValida(fecha) {
    return FECHA_REGEX.test(fecha || '');
}

function esHoraValida(hora) {
    return HORA_REGEX.test(hora || '');
}

function normalizarEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function esEmailValido(email) {
    return EMAIL_REGEX.test(normalizarEmail(email));
}

function crearFechaLocal(fecha, hora) {
    const [anio, mes, dia] = fecha.split('-').map(Number);
    const [horas, minutos] = hora.split(':').map(Number);
    return new Date(anio, mes - 1, dia, horas, minutos, 0, 0);
}

function sumarDias(fecha, cantidadDias) {
    const copia = new Date(fecha);
    copia.setDate(copia.getDate() + cantidadDias);
    return copia;
}

function formatearFechaISO(fecha) {
    const anio = fecha.getFullYear();
    const mes = String(fecha.getMonth() + 1).padStart(2, '0');
    const dia = String(fecha.getDate()).padStart(2, '0');
    return `${anio}-${mes}-${dia}`;
}

function parseCookies(header = '') {
    return header
        .split(';')
        .map((fragmento) => fragmento.trim())
        .filter(Boolean)
        .reduce((cookies, fragmento) => {
            const separador = fragmento.indexOf('=');

            if (separador === -1) {
                return cookies;
            }

            const nombre = fragmento.slice(0, separador);
            const valor = fragmento.slice(separador + 1);
            cookies[nombre] = decodeURIComponent(valor);
            return cookies;
        }, {});
}

function compararSeguro(valorA, valorB) {
    const bufferA = Buffer.from(valorA || '', 'utf8');
    const bufferB = Buffer.from(valorB || '', 'utf8');

    if (bufferA.length !== bufferB.length) {
        return false;
    }

    return crypto.timingSafeEqual(bufferA, bufferB);
}

function crearPasswordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return { salt, hash };
}

function validarPassword(password, salt, hashEsperado) {
    const hashActual = crypto.scryptSync(password, salt, 64).toString('hex');
    return compararSeguro(hashActual, hashEsperado);
}

function serializarCookie(nombre, valor, opciones = {}) {
    const partes = [`${nombre}=${encodeURIComponent(valor)}`];

    if (opciones.path) {
        partes.push(`Path=${opciones.path}`);
    }

    if (typeof opciones.maxAge === 'number') {
        partes.push(`Max-Age=${opciones.maxAge}`);
    }

    if (opciones.httpOnly) {
        partes.push('HttpOnly');
    }

    if (opciones.sameSite) {
        partes.push(`SameSite=${opciones.sameSite}`);
    }

    if (opciones.secure) {
        partes.push('Secure');
    }

    return partes.join('; ');
}

function firmarSesion(tipo, identificador, ttlSegundos) {
    const expiraEn = Date.now() + ttlSegundos * 1000;
    const payload = `${tipo}|${identificador}|${expiraEn}`;
    const firma = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
    return Buffer.from(`${payload}|${firma}`, 'utf8').toString('base64url');
}

function leerSesionFirmada(req, cookieName, tipoEsperado) {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[cookieName];

    if (!token) {
        return null;
    }

    try {
        const contenido = Buffer.from(token, 'base64url').toString('utf8');
        const [tipo, identificador, expiraEn, firma] = contenido.split('|');

        if (!tipo || !identificador || !expiraEn || !firma || tipo !== tipoEsperado) {
            return null;
        }

        if (Number(expiraEn) < Date.now()) {
            return null;
        }

        const payload = `${tipo}|${identificador}|${expiraEn}`;
        const firmaEsperada = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');

        if (!compararSeguro(firma, firmaEsperada)) {
            return null;
        }

        return { identificador };
    } catch (error) {
        return null;
    }
}

function guardarSesion(res, cookieName, token, ttlSegundos) {
    const cookie = serializarCookie(cookieName, token, {
        path: '/',
        maxAge: ttlSegundos,
        httpOnly: true,
        sameSite: 'Lax',
        secure: process.env.NODE_ENV === 'production'
    });

    res.setHeader('Set-Cookie', cookie);
}

function borrarSesion(res, cookieName) {
    const cookie = serializarCookie(cookieName, '', {
        path: '/',
        maxAge: 0,
        httpOnly: true,
        sameSite: 'Lax',
        secure: process.env.NODE_ENV === 'production'
    });

    res.setHeader('Set-Cookie', cookie);
}

function guardarSesionPropietario(res, usuario) {
    guardarSesion(
        res,
        OWNER_COOKIE_NAME,
        firmarSesion('owner', usuario, OWNER_SESSION_TTL_SECONDS),
        OWNER_SESSION_TTL_SECONDS
    );
}

function leerSesionPropietario(req) {
    const sesion = leerSesionFirmada(req, OWNER_COOKIE_NAME, 'owner');

    if (!sesion || sesion.identificador !== OWNER_USER) {
        return null;
    }

    return { usuario: sesion.identificador };
}

function guardarSesionCliente(res, clienteId) {
    guardarSesion(
        res,
        CLIENT_COOKIE_NAME,
        firmarSesion('client', clienteId, CLIENT_SESSION_TTL_SECONDS),
        CLIENT_SESSION_TTL_SECONDS
    );
}

function leerSesionCliente(req) {
    const sesion = leerSesionFirmada(req, CLIENT_COOKIE_NAME, 'client');

    if (!sesion) {
        return null;
    }

    const clienteId = Number(sesion.identificador);

    if (!Number.isInteger(clienteId) || clienteId <= 0) {
        return null;
    }

    return { clienteId };
}

async function buscarClientePorId(clienteId) {
    await asegurarEsquemaClientes();

    const [rows] = await dbPromise.query(
        `
            SELECT
                id,
                nombre,
                apellido,
                barrio,
                manzana,
                lote,
                telefono,
                email
            FROM clientes
            WHERE id = ?
            LIMIT 1
        `,
        [clienteId]
    );

    return rows[0] || null;
}

async function obtenerClienteAutenticado(req) {
    const sesion = leerSesionCliente(req);

    if (!sesion) {
        return null;
    }

    const cliente = await buscarClientePorId(sesion.clienteId);
    return cliente || null;
}

function requireOwner(req, res, next) {
    const sesion = leerSesionPropietario(req);

    if (!sesion) {
        return res.status(401).json({
            status: 'error',
            message: 'Inicia sesion como propietario.'
        });
    }

    req.owner = sesion;
    return next();
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/propietario', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'propietario.html'));
});

app.get('/admin/session', (req, res) => {
    const sesion = leerSesionPropietario(req);

    if (!sesion) {
        return res.status(401).json({
            status: 'error',
            authenticated: false
        });
    }

    return res.json({
        status: 'ok',
        authenticated: true,
        username: sesion.usuario
    });
});

app.post('/admin/login', (req, res) => {
    const usuario = (req.body.usuario || '').trim();
    const password = String(req.body.password || '');

    if (!OWNER_USER || !OWNER_PASSWORD) {
        return res.status(500).json({
            status: 'error',
            message: 'Faltan las credenciales del propietario en el archivo .env.'
        });
    }

    if (!compararSeguro(usuario, OWNER_USER) || !compararSeguro(password, OWNER_PASSWORD)) {
        return res.status(401).json({
            status: 'error',
            message: 'Usuario o password incorrectos.'
        });
    }

    guardarSesionPropietario(res, usuario);

    return res.json({
        status: 'ok',
        username: usuario
    });
});

app.post('/admin/logout', (req, res) => {
    borrarSesion(res, OWNER_COOKIE_NAME);
    return res.json({ status: 'ok' });
});

app.get('/auth/session', async (req, res) => {
    try {
        const cliente = await obtenerClienteAutenticado(req);

        if (!cliente) {
            borrarSesion(res, CLIENT_COOKIE_NAME);
            return res.status(401).json({
                status: 'error',
                authenticated: false
            });
        }

        return res.json({
            status: 'ok',
            authenticated: true,
            cliente
        });
    } catch (error) {
        console.error('Error obteniendo sesion del cliente:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos verificar tu sesion.'
        });
    }
});

app.post('/auth/register', async (req, res) => {
    const nombre = (req.body.nombre || '').trim();
    const apellido = (req.body.apellido || '').trim();
    const barrio = (req.body.barrio || '').trim();
    const manzana = (req.body.manzana || req.body.mz || '').trim();
    const lote = (req.body.lote || '').trim();
    const telefono = (req.body.telefono || '').trim();
    const email = normalizarEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!nombre || !apellido || !barrio || !manzana || !lote || !telefono || !email || !password) {
        return res.status(400).json({
            status: 'error',
            message: 'Completa todos los campos obligatorios para crear tu cuenta.'
        });
    }

    if (!esEmailValido(email)) {
        return res.status(400).json({
            status: 'error',
            message: 'Ingresa un email valido.'
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            status: 'error',
            message: 'La password debe tener al menos 6 caracteres.'
        });
    }

    try {
        await asegurarEsquemaClientes();

        const [existente] = await dbPromise.query(
            'SELECT id FROM clientes WHERE email = ? LIMIT 1',
            [email]
        );

        if (existente.length > 0) {
            return res.status(409).json({
                status: 'error',
                message: 'Ya existe una cuenta con ese email.'
            });
        }

        const { salt, hash } = crearPasswordHash(password);
        const [resultado] = await dbPromise.query(
            `
                INSERT INTO clientes (
                    nombre,
                    apellido,
                    barrio,
                    manzana,
                    lote,
                    telefono,
                    email,
                    password_salt,
                    password_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [nombre, apellido, barrio, manzana, lote, telefono, email, salt, hash]
        );

        guardarSesionCliente(res, resultado.insertId);

        return res.status(201).json({
            status: 'ok',
            cliente: {
                id: resultado.insertId,
                nombre,
                apellido,
                barrio,
                manzana,
                lote,
                telefono,
                email
            }
        });
    } catch (error) {
        console.error('Error registrando cliente:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos crear tu cuenta.'
        });
    }
});

app.post('/auth/login', async (req, res) => {
    const email = normalizarEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!email || !password) {
        return res.status(400).json({
            status: 'error',
            message: 'Ingresa email y password.'
        });
    }

    try {
        await asegurarEsquemaClientes();

        const [rows] = await dbPromise.query(
            `
                SELECT
                    id,
                    nombre,
                    apellido,
                    barrio,
                    manzana,
                    lote,
                    telefono,
                    email,
                    password_salt,
                    password_hash
                FROM clientes
                WHERE email = ?
                LIMIT 1
            `,
            [email]
        );

        const cliente = rows[0];

        if (!cliente || !validarPassword(password, cliente.password_salt, cliente.password_hash)) {
            return res.status(401).json({
                status: 'error',
                message: 'Email o password incorrectos.'
            });
        }

        guardarSesionCliente(res, cliente.id);

        return res.json({
            status: 'ok',
            cliente: {
                id: cliente.id,
                nombre: cliente.nombre,
                apellido: cliente.apellido,
                barrio: cliente.barrio,
                manzana: cliente.manzana,
                lote: cliente.lote,
                telefono: cliente.telefono,
                email: cliente.email
            }
        });
    } catch (error) {
        console.error('Error iniciando sesion del cliente:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos iniciar tu sesion.'
        });
    }
});

app.post('/auth/logout', (req, res) => {
    borrarSesion(res, CLIENT_COOKIE_NAME);
    return res.json({ status: 'ok' });
});

app.get('/turnos', async (req, res) => {
    const { desde, hasta } = req.query;

    if (!esFechaValida(desde) || !esFechaValida(hasta)) {
        return res.status(400).json({
            status: 'error',
            message: 'Debes indicar un rango de fechas valido.'
        });
    }

    try {
        const [rows] = await dbPromise.query(
            `
                SELECT
                    DATE_FORMAT(fecha, '%Y-%m-%d') AS fecha,
                    TIME_FORMAT(hora, '%H:%i') AS hora,
                    estado
                FROM turnos
                WHERE fecha BETWEEN ? AND ?
                  AND estado <> 'cancelado'
            `,
            [desde, hasta]
        );

        return res.json({
            status: 'ok',
            turnos: rows
        });
    } catch (error) {
        console.error('Error obteniendo turnos:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos cargar los turnos.'
        });
    }
});

app.get('/admin/turnos', requireOwner, async (req, res) => {
    const hoy = new Date();
    const desde = req.query.desde || formatearFechaISO(hoy);
    const hasta = req.query.hasta || formatearFechaISO(sumarDias(hoy, 30));

    if (!esFechaValida(desde) || !esFechaValida(hasta)) {
        return res.status(400).json({
            status: 'error',
            message: 'Debes indicar un rango de fechas valido.'
        });
    }

    try {
        const [rows] = await dbPromise.query(
            `
                SELECT
                    id,
                    DATE_FORMAT(fecha, '%Y-%m-%d') AS fecha,
                    TIME_FORMAT(hora, '%H:%i') AS hora,
                    nombre,
                    apellido,
                    barrio,
                    manzana,
                    lote,
                    telefono,
                    email,
                    estado
                FROM turnos
                WHERE fecha BETWEEN ? AND ?
                  AND estado <> 'cancelado'
                ORDER BY fecha ASC, hora ASC
            `,
            [desde, hasta]
        );

        return res.json({
            status: 'ok',
            turnos: rows
        });
    } catch (error) {
        console.error('Error obteniendo turnos admin:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos cargar las reservas.'
        });
    }
});

app.post('/reservar', async (req, res) => {
    let cliente = null;

    try {
        cliente = await obtenerClienteAutenticado(req);
    } catch (error) {
        console.error('Error leyendo sesion del cliente al reservar:', error);
    }

    const nombre = (req.body.nombre || cliente?.nombre || '').trim();
    const apellido = (req.body.apellido || cliente?.apellido || '').trim();
    const barrio = (req.body.barrio || cliente?.barrio || '').trim();
    const manzana = (req.body.manzana || req.body.mz || cliente?.manzana || '').trim();
    const lote = (req.body.lote || cliente?.lote || '').trim();
    const telefono = (req.body.telefono || cliente?.telefono || '').trim();
    const email = normalizarEmail(req.body.email || cliente?.email || '');
    const fecha = (req.body.fecha || '').trim();
    const hora = (req.body.hora || '').trim();

    if (!nombre || !apellido || !barrio || !manzana || !lote || !telefono || !fecha || !hora) {
        return res.status(400).json({
            status: 'error',
            message: 'Completa todos los datos obligatorios.'
        });
    }

    if (email && !esEmailValido(email)) {
        return res.status(400).json({
            status: 'error',
            message: 'El email tiene un formato invalido.'
        });
    }

    if (!esFechaValida(fecha) || !esHoraValida(hora)) {
        return res.status(400).json({
            status: 'error',
            message: 'La fecha o la hora tienen un formato invalido.'
        });
    }

    const fechaTurno = crearFechaLocal(fecha, hora);

    if (Number.isNaN(fechaTurno.getTime()) || fechaTurno < new Date()) {
        return res.status(400).json({
            status: 'error',
            message: 'No puedes reservar un turno pasado.'
        });
    }

    const horaDB = `${hora}:00`;

    try {
        const [existente] = await dbPromise.query(
            `
                SELECT id
                FROM turnos
                WHERE fecha = ?
                  AND hora = ?
                  AND estado <> 'cancelado'
                LIMIT 1
            `,
            [fecha, horaDB]
        );

        if (existente.length > 0) {
            return res.status(409).json({
                status: 'error',
                message: 'Ese horario ya fue reservado por otra persona.'
            });
        }

        const [resultado] = await dbPromise.query(
            `
                INSERT INTO turnos (
                    fecha,
                    hora,
                    nombre,
                    apellido,
                    barrio,
                    manzana,
                    lote,
                    telefono,
                    email,
                    estado
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pendiente')
            `,
            [fecha, horaDB, nombre, apellido, barrio, manzana, lote, telefono, email || null]
        );

        return res.status(201).json({
            status: 'ok',
            id: resultado.insertId
        });
    } catch (error) {
        console.error('Error reservando turno:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos guardar la reserva.'
        });
    }
});

app.post('/admin/liberar-turno', requireOwner, async (req, res) => {
    const id = Number(req.body.id);

    if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
            status: 'error',
            message: 'Debes indicar un turno valido.'
        });
    }

    try {
        const [resultado] = await dbPromise.query(
            `
                UPDATE turnos
                SET estado = 'cancelado'
                WHERE id = ?
                  AND estado <> 'cancelado'
            `,
            [id]
        );

        if (resultado.affectedRows === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'Ese turno ya no estaba disponible para liberar.'
            });
        }

        return res.json({
            status: 'ok'
        });
    } catch (error) {
        console.error('Error liberando turno:', error);
        return res.status(500).json({
            status: 'error',
            message: 'No pudimos liberar el turno.'
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor listo en http://localhost:${PORT}`);
});
