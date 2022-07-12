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

app.get('/',function (req,res){
    res.render("index",{title:"Home"})
});

app.get("/login",function (req,res){
    res.render("login",{title:"Login"})
})

app.listen(port,()=>{
    console.log(`listening on port ${port}`);
})