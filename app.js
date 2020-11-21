//jshint esversion:6
require('dotenv').config()
//const md5=require('md5');
const bcrypt=require('bcrypt');
//const saltrounds=10;
const express=require('express');
//var encrypt = require('mongoose-encryption');
const ejs=require('ejs');
const bodyParser=require('body-parser');
const app=express();
const mongoose=require('mongoose');
const sesion=require('express-session');
const passportLocalMongoose=require('passport-local-mongoose');
const passport = require('passport');
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static('public'));
app.set('view engine','ejs');
app.use(sesion({
    secret:'sessionsignature',
    resave:false,
    saveUninitialized:false,
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect('mongodb://localhost:27017/userDB',{ useNewUrlParser: true,useUnifiedTopology: true });
mongoose.set('useCreateIndex', true)
const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleid:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret:process.env.ENCRYPTION_KEY, encryptedFields:["password"]});
const User=mongoose.model('user',userSchema);

passport.use(User.createStrategy());
 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENTSECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    passReqToCallback: true
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ googleid: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get('/',function(req,res){
    res.render('home');
});
app.get( '/auth/google/secret',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));
app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));
app.get('/login',function(req,res){
    res.render('login');
});
app.get('/register',function(req,res){
    res.render('register');
});

app.get('/logout',function(req,res){
    req.logout(),
    res.redirect('/');
});

app.get('/secrets',function(req,res){
    User.find({secret:{$ne:null}},function(err,allSecretsLists){
        if(err){
            console.log(err);
        }
        else{
            if(req.isAuthenticated){
                res.render('secrets',{list:allSecretsLists});
            }
            else{
                res.render('register');
            }
        }
    });
});

app.post('/register',function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect('/register',{allUsers:User});
        }
        else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            });
        }
    });
});
app.post('/login',function(req,res){
    const checkuser=new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(checkuser,function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            }); 
        }
    });
});
app.get('/submit',function(req,res){
    res.render('submit');
});
app.post('/submit',function(req,res){
    User.findById(req.user.id,function(err,foundUser){
        if(err)
        console.log(err);
        if(foundUser){
            foundUser.secret=req.body.secret;
            foundUser.save(()=>console.log('successfully added secret'));
        }
    });
    res.redirect('/secrets');
});


app.listen(3000,()=>{console.log("server is running on port 3000");});