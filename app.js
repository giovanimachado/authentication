//jshint esversion:6
// Level 6 - Google OAuth 2.0 Authentication
// Level 5 - Cookies and Sessions
// Level 4 - Hashing and Salting with bcrypt
// Level 3 - Hashing with md5
// Level 2 - Encryption
// Level 1 - Username and Password Only

require("dotenv").config(); // Implement enviromental variables
const express = require("express");
const bodyParser = require("body-parser");
const findOrCreate = require("mongoose-findorcreate");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
  secret: process.env.MYSECRET,
  resave: false,
  saveUninitialized: true
}));
// initialize the passport package
app.use(passport.initialize());
// use passport to manage sessions
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{
  useNewUrlParser: true,
  useUnifiedTopology: true}
);
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// this plugin is going to hash and salt the password
userSchema.plugin(passportLocalMongoose);

// this plugin is going to use the findOr Create package i the userSchema
userSchema.plugin(findOrCreate);

// userSchema.plugin(encryption,{secret: process.env.MYSECRET, encryptedFields: ["password"]}); // Implement Level 2

const User = new mongoose.model("User", userSchema);

// Use passport to create a local login stategy
passport.use(User.createStrategy());

// Serialize and deserialize using passport
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Set up google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    // Reference: https://stackoverflow.com/questions/20431049/what-is-function-user-findorcreate-doing-and-when-is-it-called-in-passport/41355218#41355218
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/register", function(req, res){
  res.render("register");
});

// Route to adress the POST request to be made by
// form in register.ejs
app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()){
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
      if (err){
        console.log(err);
      } else {
          if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
          }
        }
      });
    } else {
        res.redirect("/login");
      }
});

app.get("/submit", function(req, res){
  // Only loggeg users
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  // Passport manages what user is using the session
  // console.log(req.user.id);
  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.listen(3000, function(){
  console.log("Server running on port 3000");
});
