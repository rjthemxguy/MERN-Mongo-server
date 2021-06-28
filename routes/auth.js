const express = require("express");
const router = express.Router();
const {check, validationResult} = require("express-validator/check");
const bcrypt = require("bcryptjs");
const jwt= require("jsonwebtoken");
const auth = require("../middleware/auth");
const config = require("config");


const User = require("../models/User");



router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});


router.post('/', [
    check("email", "Please provide and email address").isEmail(),
    check("password", "Password required").exists()
] , async (req, res) => {

    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }

    const {email, password} = req.body;

    try {
        let user = await User.findOne({email});

        if(!user) {
            return res.status(400).json("Invalid Credentials");
        }

    const isMatch = await bcrypt.compare(password, user.password);

    if(!isMatch) {
        return res.status(400).json("Invalid Credentials");
    }

    const payload = {
        user: {
        id: user.id
        }
    }

    jwt.sign(payload, config.get("jwtSecret"), {
        expiresIn: '1d'
    }, (err, token) => {
        if(err) throw err;
        res.json({token})
    });

    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
    
});

module.exports = router;