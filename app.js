require("dotenv").config();
require("./config/database").connect();
const User = require("./model/user");
const express = require("express");
const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth")

app.use(express.json());



app.post("/register", async(req,res)=>{
try {
    const {first_name, last_name, email, password}= req.body;

    if(!(email && password && first_name && last_name)){
        res.status(400).send("all inputs are required....");
    }

    const oldUser = await User.findOne({ email });

    if(oldUser){
        return res.status(409).send("User Alredy exist. Please Login");
    }

    encryptedPassword = await bcrypt.hash(password,10);

    const user = await User.create({
        first_name,
        last_name,
        email: email.toLowerCase(),
        password: encryptedPassword,
    });

    const token = jwt.sign(
        {user_id:user._id,email},
        process.env.TOKEN_KEY,
        {
            expiresIn: "2h",
        }
    );

    user.token = token;

    res.status(201).json(user);

} catch (err) {
    console.log(err);
}
});

app.post("/login", async(req,res)=>{

    try {
        const { email , password} = req.body

        if(!(email && password)){
            res.status(400).send("all input is required...");
        }
        const user = await User.findOne({email});

        if(user && (await bcrypt.compare(password,user.password))){
            const token = jwt.sign(
                { user_id: user._id, email},
                process.env.TOKEN_KEY,
                {
                    expiresIn: "2hr",
                }
            );
            user.token = token;

            res.status(200).json(user);
        }
        res.status(400).send("Invalid Credentials");
    } catch (error) {
        console.log(error);
    }


})

app.get("/welcome", auth, (req,res)=>{
    res.status(200).send("welcome");
})



module.exports = app;