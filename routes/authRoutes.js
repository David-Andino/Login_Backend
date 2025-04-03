const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");

const router = express.Router();

// 🔹 Obtener todos los usuarios
router.get("/users", (req, res) => {
    db.query("SELECT id, nombre, rol, sistemas_permitidos FROM usuarios", (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results.map(user => ({
            ...user,
            sistemas_permitidos: Array.isArray(user.sistemas_permitidos) 
                ? user.sistemas_permitidos 
                : JSON.parse(user.sistemas_permitidos)
        })));
    });
});

// 🔹 Obtener un usuario por ID

router.get("/user/:id", (req, res) => {
    const { id } = req.params;
    db.query("SELECT id, nombre, rol, sistemas_permitidos FROM usuarios WHERE id = ?", [id], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (results.length === 0) return res.status(404).json({ message: "Usuario no encontrado" });
        
        const user = results[0];
        user.sistemas_permitidos = Array.isArray(user.sistemas_permitidos) 
            ? user.sistemas_permitidos 
            : JSON.parse(user.sistemas_permitidos);
        res.json(user);
    });
});

// 🔹 Registrar usuario
router.post("/register", async (req, res) => {
    const { nombre, password, rol, sistemas_permitidos } = req.body;

    db.query("SELECT * FROM usuarios WHERE nombre = ?", [nombre], async (err, results) => {
        if (results.length > 0) {
            return res.status(400).json({ message: "El usuario ya existe" });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const sql = "INSERT INTO usuarios (nombre, password_hash, rol, sistemas_permitidos) VALUES (?, ?, ?, ?)";
        db.query(sql, [nombre, passwordHash, rol, JSON.stringify(sistemas_permitidos)], (err) => {
            if (err) return res.status(500).json({ error: err });
            res.status(201).json({ message: "Usuario registrado con éxito" });
        });
    });
});

// 🔹 Iniciar sesión
router.post("/login", (req, res) => {
    const { nombre, password } = req.body;

    db.query("SELECT * FROM usuarios WHERE nombre = ?", [nombre], async (err, results) => {
        if (results.length === 0) {
            return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
        }

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
        }

        user.sistemas_permitidos = Array.isArray(user.sistemas_permitidos) 
                ? user.sistemas_permitidos 
                : JSON.parse(user.sistemas_permitidos);

        const token = jwt.sign(
            { id: user.id, nombre: user.nombre, rol: user.rol, sistemas_permitidos: user.sistemas_permitidos },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );

        res.json({ token });
    });
});

// 🔹 Editar usuario
router.put("/update/:id", async (req, res) => {
    const { id } = req.params;
    const { nombre, password, rol, sistemas_permitidos } = req.body;

    let passwordHash = null;
    if (password) {
        passwordHash = await bcrypt.hash(password, 10);
    }

    const sql = passwordHash
        ? "UPDATE usuarios SET nombre = ?, password_hash = ?, rol = ?, sistemas_permitidos = ? WHERE id = ?"
        : "UPDATE usuarios SET nombre = ?, rol = ?, sistemas_permitidos = ? WHERE id = ?";

    const values = passwordHash
        ? [nombre, passwordHash, rol, JSON.stringify(sistemas_permitidos), id]
        : [nombre, rol, JSON.stringify(sistemas_permitidos), id];

    db.query(sql, values, (err, result) => {
        if (err) return res.status(500).json({ error: err });
        res.json({ message: "Usuario actualizado correctamente" });
    });
});

// 🔹 Eliminar usuario
router.delete("/delete/:id", (req, res) => {
    const { id } = req.params;

    db.query("DELETE FROM usuarios WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: err });
        res.json({ message: "Usuario eliminado correctamente" });
    });
});

// 🔹 Verificar Token
router.get("/verify-token", (req, res) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(401).json({ message: "Acceso denegado. Token requerido" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Token inválido" });
        res.json(decoded);
    });
});

module.exports = router;
