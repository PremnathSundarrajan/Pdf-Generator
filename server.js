const express=require('express');
const app =express();
const mongoose=require('mongoose');
const puppeteer = require('puppeteer');
const path=require('path');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const {isEmail}=require('validator');
const cookieParser = require('cookie-parser');
require('dotenv').config();

app.use(cookieParser());
app.use(express.static(path.join(__dirname,'public')));
app.use(express.json());
const cors = require('cors');
app.use(cors());
mongoose.connect('mongodb://localhost:27017/appdb');
const userschema= new mongoose.Schema({
    name:String,
    email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        validate:[isEmail,'please enter valid email']

    },
    password:{
        type:String,
        
    }
});



    userschema.pre('save', async function(next){
        if(!this.isModified('password')){
            return next();

        }
        try{
            const hashedpassword= await bcrypt.hash(this.password,10);
            this.password=hashedpassword;
            next();
        }catch(err){
            next(err);
        }

    })
   const User= mongoose.model('User',userschema); 
const handleErrors=(err)=>{
    console.log(err.message,err.code);
}

const authentication= (req,res,next)=>{
  
    const token= req.cookies.accesstoken;
    if(!token){
        return   res.status(401).json({error:'Login First'});
    }
    jwt.verify(token,process.env.ACCESS_TOKEN,(err,user)=>{
        if(err){
            return res.status(400).json({error:'Token is invalid'});
        }
            req.user=user;
            next();
        
    })
}

app.post('/register',async(req,res)=>{
     const name= req.body.name;
    const email=req.body.email;
    const password=req.body.password;
    if(await User.findOne({name:name})){
        res.status(400).json({message:'Already registered in this name'});
    }
    try{
      
    const user={name,email,password};
    const newuser=new User(user);
    await newuser.save();
    const accesstoken= await jwt.sign({name:name},process.env.ACCESS_TOKEN);
    res.cookie('accesstoken',accesstoken,{httpOnly:true,maxAge:24*60*60*1000}); 
    res.status(200).json({accesstoken});
    }
   catch(err){
    handleErrors(err);
    res.status(400).send('user failed')
   }
    

});

app.post('/login',async(req,res)=>{
    const name=req.body.name;
    const email=req.body.email;
    const password=req.body.password;
    const user = await User.findOne({name:name,email:email});
    if(!user){
       return res.status(400).json({message:'Invalid or Register First'});
    }
    else{
        if(await bcrypt.compare(password,user.password)){
            const accesstoken= await jwt.sign({name:name},process.env.ACCESS_TOKEN);
            res.cookie('accesstoken',accesstoken,{httpOnly:true,maxAge:24*60*60*1000});
            res.status(200).json({accesstoken});
        }
        else{
            res.status(400).json({message:'Failed or Incorrect Password'});
        }
    }
    
})

app.post('/logout',(req,res)=>{
    try{
        res.clearCookie('accesstoken');
    res.status(200).json({message:'successful'});
    }catch{
        res.status(400).json({message:'failed'});
    }
    
})


app.post('/generate',authentication,async(req,res)=>{

    const msg= req.body.msg;
 

    const browser = await puppeteer.launch();
    const page= await browser.newPage();
    
    await page.setContent(`
        <html lang="en">
<head>
   
    <link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins&family=Roboto:ital,wght@0,100..900;1,100..900&display=swap" rel="stylesheet">
    <style>
        body {
  font-family: "Poppins", sans-serif;
  font-weight: 400;
  font-style: normal;
  
}
  pre{
  font-family: "Poppins", sans-serif;
  font-weight: 400;
  font-style: normal;
  }
  </style>
</head>
<body>
        <center
        <h1> ${req.user.name}</h1>
        </center>
        
        <pre>${msg}</pre> 
        </body>
        </html>`
        
        
    );

    const pdfBuffer= await page.pdf({format:'A4'});
    await browser.close();

    res.set({
        'Content-Type':'application/pdf',
        'Content-Disposition':'attachment; filename:"generated.pdf"'
    });

    res.send(pdfBuffer);
    
});



app.listen(3000,()=>{
    console.log('server is running');
})

