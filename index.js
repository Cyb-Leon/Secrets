import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import { configDotenv } from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";

configDotenv();

const app = express();
const port = process.env.serverPort;
//hash salt
const saltRounds = 5;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: process.env.sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

//database connection
const SecretesDB = new pg.Client({
  user: process.env.gresUsr,
  host: process.env.gresHOST,
  database: process.env.gresDB,
  password: process.env.gresPSW,
  port: process.env.gressPORT,
});
SecretesDB.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

//get page which requires authentication.
app.get("/secrets", async (req, res) => {
  console.log(req.user);
  const user = req.user;
  if (req.isAuthenticated()) {
    try {
      const result = await SecretesDB.query("SELECT secret FROM users WHERE email = $1", [user.email])

      //check if there is any secret
      if (result.rows[0].secret) {
        res.render("secrets.ejs",{secret: result.rows[0].secret});
      } else {
        res.render("secrets.ejs",{secret: "You should submit a secret!"});
      }
    } catch (error) {
      console.log("error pulling data:" + error);
    }
  } else {
    res.redirect("/login");
  }
});

//google auth
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  /**
   * check if the user exists and redirect user to login
   * if user does not exist  - store new user to database
   **/
  try {
    const isUserExists = await SecretesDB.query(
      "SELECT * FROM users WHERE email = $1",
      [username]
    );

    //check if row is empty
    if (isUserExists.rowCount == 0) {
      //create a hashed password
      bcrypt.hash(password, saltRounds, async (error, hash) => {
        //check if any errors during the hashing process of password.
        if (error) {
          console.log("error trying to hash password:", error);
          res.send("something wrong with the hash process");
        } else {
          //if no errors - store hashed password
          const newUser = await SecretesDB.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [username, hash]
          );
          //render scerets page
          const user = newUser.rows[0];
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/secrets");
          });
        }
      });
    } else {
      console.log("this user is on the db"); // redirect user to login page
      res.redirect("/login");
    }
  } catch (error) {
    //problem with the database connection / entry
    console.log(error);
  }
});

app.post("/login",
  passport.authenticate("local", {
    //set options
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

//submit a secret - only if authenticated
app.get("/submit", (req, res) => {

  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect('/login');
  }
});

//
app.post("/submit", async (req, res) => {
  const postSecret = req.body.secret;
  const user = req.user;

  try {
     await SecretesDB.query(
      "UPDATE users SET secret = $1 WHERE email = $2",
      [postSecret, user.email]
    );

    res.redirect("/secrets");
  } catch (error) {
    console.log(error);
    res.send("error updating");
  }
});

app.get("/logout", (req, res) => {
  req.logout((error) => {
    if (error) console.log(error);
    res.redirect("/login");
  });
});

//Creating the strategy for auth verification via sessions
passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const isUserExists = await SecretesDB.query(
        "SELECT * FROM users WHERE email = $1",
        [username]
      );

      //if rowCount is 0 - user does not exist, therefore not registered
      if (isUserExists.rowCount != 0) {
        //we get user that exists and check their data with the given data for /login
        const user = isUserExists.rows[0];
        const storedHashpsw = user.password;

        //decrypt and compare
        bcrypt.compare(password, storedHashpsw, (error, isCorrectPsw) => {
          if (error) {
            return cb(error);
          } else {
            //if password is correct - render secrets.
            if (isCorrectPsw == true) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        console.log("You are not registered to Secrets.");
        return cb("You are not registered to Secrets: User not found");
      }
    } catch (error) {
      console.log(error);
      //db issue catch
      return cb(error);
    }
  })
);

//create the googleStrategy OAuth
passport.use("google",
  new GoogleStrategy(
    {
      clientID: process.env.googleOAuth_CLIENT_IDKEY,
      clientSecret: process.env.googleOAuth_CLIENT_SECRET_KEY,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const result = await SecretesDB.query(
          "SELECT * FROM users WHERE email = $1",
          [profile.email]
        );
        if (result.rowCount === 0) {
          const newUser = await SecretesDB.query(
            "INSERT INTO users (email,password) VALUES ($1,$2)",
            [profile.email, "google"]
          );
          cb(null, newUser.rows[0]);
        } else {
          //you exists
          cb(null, result.rows[0]);
        }
      } catch (error) {
        cb(error);
      }
    }
  )
);

//serialzeUser - save data of logged in user to localStorage
passport.serializeUser((user, cb) => {
  cb(null, user);
});

//deserialzeUser - access data of logged in user from localStorage
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
