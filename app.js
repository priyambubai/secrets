//------ Requiring Modules ------//
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const findOrCreate = require("mongoose-findorcreate");


//------ Initializing Express App ------//
const app = express();

//------ Use Body Parser ------//
app.use(bodyParser.urlencoded({ extended: true }));

//------ Use EJS ------//
app.set("view engine", "ejs");

//------ Use Public Folder ------//
app.use(express.static("public"));

//------ Use Express-Session ------//
app.use(session({
    secret: "Our little secret!",
    resave: false,
    saveUninitialized: false
}));

//------ Use Passport ------//
app.use(passport.initialize());
app.use(passport.session());

//-------- Connecting to MongoDB Server ---------//
mongoose.connect("mongodb+srv://admin-priyam:" + process.env.MONGODB_PASSWORD + "@cluster0.4e7tz9k.mongodb.net/userDB")

//--------- Defining new Schema ---------//
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

//------ Level 5 Authentication ------//
userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);


//--------- Create Models ---------//
const User = mongoose.model("User", userSchema);

//------ Passport-Local-Mongoose Strategy ------//
passport.use(User.createStrategy());

//------ Serialize User (Passport Docs) ------//
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.email
        });
    });
});

//------ Deserialize User (Passport Docs) ------//
passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

//------ Use Google Strategy and Find/Create User ------//
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"

},
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile);
        User.findOrCreate({ googleId: profile.id, email: profile._json.email }, function (err, user) {
            return cb(err, user);
        });
    }
));

//------ Use Facebook Strategy and Find/Create User ------//
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'email']
},
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile);
        User.findOrCreate({ facebookId: profile.id, email: profile._json.email }, function (err, user) {
            return cb(err, user);
        });
    }
));

//------ GET Request home route (/) ------//
app.get("/", function (req, res) {
    res.render("home");
})

//------ Google OAuth ------//
app.route("/auth/google")
    .get(
        passport.authenticate("google", { scope: ["profile", "email"] })
    );

//------ Facebook OAuth ------//
app.route("/auth/facebook")
    .get(
        passport.authenticate("facebook")
    );

//------ Google OAuth Callback Route ------//
app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

//------ Facebook OAuth Callback Route ------//
app.get("/auth/facebook/secrets",
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

//------ GET/POST Request register route (/register) ------//
app.route("/register")
    .get(function (req, res) {
        res.render("register");
    })
    .post(function (req, res) {
        User.register({ username: req.body.username }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                })
            }

            const authenticate = User.authenticate();
            authenticate(req.body.username, req.body.password, function (err, result) {
                if (err) {
                    console.log(err);
                }
            })
        })
    })

//------ GET/POST Request login route (/login) ------//
app.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function (err) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                })
            }
        })
    })

//------ GET Request logout route (/logout) ------//    
app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
            res.redirect("/logout");
        } else {
            res.redirect("/");
        }
    })
})

//------ GET Request secrets route (/secrets) ------// 
app.get("/secrets", function (req, res) {
    User.find({ secret: { $ne: null } })
        .then(foundUsers => {
            res.render("secrets", { userSecrets: foundUsers });
        })
        .catch(err => {
            console.log(err);
        })
})

//------ GET/POST Request submit route (/submit) ------//
app.route("/submit")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post(function (req, res) {
        console.log(req.body.secret);
        console.log(req.user);
        User.findById(req.user.id)
            .then(foundUser => {
                if (foundUser) {
                    foundUser.secret = req.body.secret;
                    foundUser.save();
                    res.redirect("/secrets");
                } else {
                    res.redirect("/login");
                }
            })
            .catch(err => {
                console.log(err);
            })
    })

//------ Connecting to Port ------//
app.listen(process.env.PORT || 3000, function () {
    console.log("Server started at port 3000.");
})