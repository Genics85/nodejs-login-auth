const express       =require("express");
const session       =require("express-session");
const exphbs        =require("express-handlebars");
const mongoose      =require("mongoose");
const passport      =require("passport");
const localStrategy =require("passport-local").Strategy;
const bcrypt        =require("bcrypt");
const user          =require("./models/user.js");

const app=express();
const port=5000;

mongoose.connect("mongodb://localhost:27017/login-auth",{
    useNewUrlParser:true,
    useUnifiedTopology:true
});

//Middlewares
app.engine("hbs",exphbs.engine({ extname:".hbs"}));
app.set("view engine","hbs");
app.use(express.static(__dirname+"/public"));
app.use(session({
    secret:"idonthaveanysecret",
    resave:false,
    saveUninitialized:true
}));
app.use(express.urlencoded({extended:false}));
app.use(express.json());

//passport
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user,done){
    done(null,user.id)
});

passport.deserializeUser(function(id,done){
    user.findById(id,function(err,user){
        done(err,user);
    });
});
passport.use((new localStrategy(function (username,password,done){
    user.findOne({username:username},function(err,user){
        if(err) return done(err);
        if(!user) return done(null,false,{message:"Incorrect user name"});
        bcrypt.compare(password,user.password, function(err,res){
            if(err) return done(err);
            if(res==false) return done (null,false,{message:"incorrect password."});
            
            return done(null,user);
        })
    })
})));

//login checker
function isLoggedIn(req,res,next){
    if(req.isAuthenticated()) return next();
    res.redirect("/login");
}

//logout checker
function isLoggedOut(req,res,next){
    if(!req.isAuthenticated()) return next();
    res.redirect("/");
}
//ROUTES
app.get('/',isLoggedIn,function (req,res){
    res.render("index",{title:"Home"})
});

app.post("/login",passport.authenticate("local",{
    successRedirect:"/",
    failureRedirect:"/login?error=true"
}))
app.get("/login",isLoggedOut,function (req,res){
    const response={
        title:"Login",
        error:req.query.error
    }
    res.render("login",response)
})

app.get("/logout",(req,res,next)=>{
    req.logout(function(err){
        if(err)return next(err);
        res.redirect("/");
    }); 
})

//seting up an admin user

app.get("/setup",async (req,res)=>{
    const exists= await user.exists({username:"admin"});

    if(exists){
        res.redirect("/login")
        return;
    }
    bcrypt.genSalt(10,function(err,salt){
        if(err) return next(err);
        bcrypt.hash("pass",salt,function(err,hash){
            if(err) return next(err);

            const newAdmin=new user({
                username:"Genics",
                password:hash
            })
            newAdmin.save();
            res.redirect("/login");
            
        })
    })
})

app.listen(port,()=>{
    console.log(`listening on port ${port}`);
})