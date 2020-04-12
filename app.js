//jshint esversion:6
// Level 6 - Google OAuth 2.0 Authentication
// Level 5 - Cookies and Sessions
// Level 4 - Hashing and Salting with bcrypt
// Level 3 - Hashing with md5
// Level 2 - Encryption
// Level 1 - Username and Password Only

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encryption = require("mongoose-encryption");

const app = express();

console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/userDB",{
  useNewUrlParser: true,
  useUnifiedTopology: true}
);

// For level 1 auth, It is used a simple JS Object
// const userSchema = {
//   email: String,
//   password: String
// };

// For level 2 auth, It is used a mongoose.Schema object
// It is created form  mongoose.Schema class
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});


userSchema.plugin(encryption,{secret: process.env.MYSECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});


//Level 1 authentication
app.post("/login", function(req, res){
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, function(error, foundUser){
    if (error){
      console.log(error);
    } else {
      if (foundUser){
        if (foundUser.password === password){
          res.render("secrets");
        }
      }
    }
  });
});

app.get("/register", function(req, res){
  res.render("register");
});

// Route to adress the POST request to be made by
// form in register.ejs
app.post("/register", function(req, res){
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });

  newUser.save(function(err){
    if (!err){
      res.render("secrets");
    } else {
      console.log(err);
    }
  });
});

app.listen(3000, function(){
  console.log("Server running on port 3000");
});
