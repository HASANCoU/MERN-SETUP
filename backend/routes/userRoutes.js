import bcrypt from "bcryptjs";
import express from "express";
import jwt from "jsonwebtoken";
import User from "../models/User.js";


const router = express.Router();


//Register User
router.post("/register", async (req,res)=>{
    const {email, password} = req.body;

    if(!email || !password){
        return  res.status(400).json({message: "Please provide email and password"});
    }

    try{
        const userExists = await User.findOne({email});
        if(userExists){
            return res.status(409).json({message: "User already exists"});
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = await User.create({
            email,
            password: hashedPassword
        })
        res.status(201).json({message: "User registered successfully", user: {
            email: user.email
        }});
    } catch (err){
        res.status(500).json({message: "Server error"   });
    }
});

//Get All Users
router.get("/users",async (req,res)=>{
    try{
        const users = await User.find().select("-password");
        res.status(200).json(users);
    } catch (err){
        res.status(500).json({message: "Server error"});
    }
});

//Login User
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Please provide email and password" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES || "7d" }
    );

    return res.json({
      message: "Login successful",
      token,
      user: { id: user._id, email: user.email }
    });
} catch (err) {
    console.log(err);
    return res.status(500).json({ message: err.message });
  }
});

export default router;