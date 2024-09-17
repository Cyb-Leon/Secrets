import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import { configDotenv } from "dotenv";

configDotenv();

const app = express();
const port = process.env.serverPort;

//database connection
const SecretesDB = new pg.Client({
  user: process.env.gresUsr,
  host: process.env.gresHOST,
  database: process.env.gresDB,
  password: process.env.gresPSW,
  port: process.env.gressPORT,
});
SecretesDB.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  /**
   * check if the user exists and redirect user to login
   * if user does not exist  - store new user to database
   **/
  try {
    const isUserExists = await SecretesDB.query(
      "SELECT * FROM users WHERE email = $1 AND password = $2",
      [username, password]
    );

    //check if row is empty
    if (isUserExists.rowCount == 0) {
      //const newUser = await SecretesDB;
      const newUser = await SecretesDB.query(
        "INSERT INTO users (email, password) VALUES ($1, $2)",
        [username, password]
      );
      console.log(`New user has been Registered ${newUser}`);
      res.render("secrets.ejs");
    } else {
      console.log("this user is on the db");
      res.render("secrets.ejs");
    }
  } catch (error) {
    //problem with the database connection / entry
    console.log(error);
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const isUserExists = await SecretesDB.query(
      "SELECT * FROM users WHERE email = $1",
      [username, password]
    );

    //if rowCount is 0 - user does not exist, therefore not registered
    if(isUserExists.rowCount != 0){
      res.render("secrets.ejs");
    }else{
     console.log("You are not registered to Secrets.");
      res.send("You are not registered to Secrets.");
    }
  } catch (error) {
    console.log(error);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
