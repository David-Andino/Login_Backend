const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");

const router = express.Router();

// 🔹 Obtener todos los usuarios
router.get("/users", async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, nombre, rol, sistemas_permitidos FROM usuarios");
        const formattedResults = results.map(user => ({
            ...user,
            sistemas_permitidos: Array.isArray(user.sistemas_permitidos) 
                ? user.sistemas_permitidos 
                : JSON.parse(user.sistemas_permitidos)
        }));
        res.json(formattedResults);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🔹 Obtener un usuario por ID
router.get("/user/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query(
            "SELECT id, nombre, rol, sistemas_permitidos FROM usuarios WHERE id = ?", 
            [id]
        );
        
        if (results.length === 0) {
            return res.status(404).json({ message: "Usuario no encontrado" });
        }
        
        const user = results[0];
        user.sistemas_permitidos = Array.isArray(user.sistemas_permitidos) 
            ? user.sistemas_permitidos 
            : JSON.parse(user.sistemas_permitidos);
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🔹 Registrar usuario
router.post("/register", async (req, res) => {
    const { nombre, password, rol, sistemas_permitidos } = req.body;
    
    try {
        // Verificar si el usuario ya existe
        const [existingUsers] = await db.query(
            "SELECT * FROM usuarios WHERE nombre = ?", 
            [nombre]
        );
        
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: "El usuario ya existe" });
        }

        // Hash de la contraseña
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Insertar nuevo usuario
        await db.query(
            "INSERT INTO usuarios (nombre, password_hash, rol, sistemas_permitidos) VALUES (?, ?, ?, ?)",
            [nombre, passwordHash, rol, JSON.stringify(sistemas_permitidos)]
        );
        
        res.status(201).json({ message: "Usuario registrado con éxito" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🔹 Iniciar sesión
router.post("/login", async (req, res) => {
    const { nombre, password } = req.body;
    
    try {
        // Buscar usuario
        const [results] = await db.query(
            "SELECT * FROM usuarios WHERE nombre = ?", 
            [nombre]
        );
        
        if (results.length === 0) {
            return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
        }

        const user = results[0];
        
        // Verificar contraseña
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Usuario o contraseña incorrectos" });
        }

        // Formatear sistemas permitidos
        user.sistemas_permitidos = Array.isArray(user.sistemas_permitidos) 
            ? user.sistemas_permitidos 
            : JSON.parse(user.sistemas_permitidos);

        // Generar token JWT
        const token = jwt.sign(
            { 
                id: user.id, 
                nombre: user.nombre, 
                rol: user.rol, 
                sistemas_permitidos: user.sistemas_permitidos 
            },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🔹 Editar usuario
router.put("/update/:id", async (req, res) => {
    const { id } = req.params;
    const { nombre, password, rol, sistemas_permitidos } = req.body;
    
    try {
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

        await db.query(sql, values);
        
        res.json({ message: "Usuario actualizado correctamente" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🔹 Eliminar usuario
router.delete("/delete/:id", async (req, res) => {
    const { id } = req.params;
    
    try {
        await db.query("DELETE FROM usuarios WHERE id = ?", [id]);
        res.json({ message: "Usuario eliminado correctamente" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🔹 Verificar Token
router.get("/verify-token", async (req, res) => {
    const token = req.headers["authorization"];
    
    if (!token) {
        return res.status(401).json({ message: "Acceso denegado. Token requerido" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json(decoded);
    } catch (err) {
        res.status(401).json({ message: "Token inválido" });
    }
});

module.exports = router;