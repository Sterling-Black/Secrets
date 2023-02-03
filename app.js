require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// lvl 2 encryption
// const encrypt = require("mongoose-encryption");
// lvl 3 hashing
// const md5 = require("md5");
// lvl 4 hashing and salting with rounds
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
// lvl 5 cookies and sessions
// level 6 Login with google
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy
const findOrCreate =  require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));

app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));


app.use(session({
    secret: 'ThisIsOurLittleSecret',
    resave: false,
    saveUninitialized: true
}));
  
app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', false);
mongoose.connect(process.env.MONGODB_URL,{useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// level 2 
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
});
  
passport.deserializeUser(function(user, cb) {
process.nextTick(function() {
    return cb(null, user);
});
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secretblogs.onrender.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "https://secretblogs.onrender.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", (req,res)=>{
    res.render("home");
});







app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });






app.get("/login", (req,res)=>{
    res.render("login");
});

app.get("/register", (req,res)=>{
    res.render("register");
});

app.get("/logout", (req,res)=>{
    req.logout(function(err) {
        if (err) { 
            console.log(err); 
        }
        res.redirect('/');
      });
});

app.get("/secrets",(req,res)=>{

    User.find({"secret": {$ne: null}}, (err, foundUsers)=>{
        if(err){
            console.log(err);
        }else if(foundUsers){
            res.render("secrets",{
                usersWithSecrets: foundUsers
            });
        }
    });
    
});

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
})




app.post("/register", (req,res)=>{
    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    })
    
});

app.post("/login",(req,res)=>{
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id, ( err, foundUser)=>{
        if(err){
            console.log(err);
        }else if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save(()=>{
                    res.redirect("/secrets")
            })
        }
    });
});


app.listen(process.env.PORT||3000,()=>{
    console.log("Server started on port 3000");
})