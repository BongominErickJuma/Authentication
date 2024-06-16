import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

const createAuthenticationTable = `
    CREATE TABLE IF NOT EXISTS authentication (
	id serial primary key,
	username varchar(255),
	email varchar(255),
	phone varchar(255),
	password varchar(255)
    );
`;
db.query(createAuthenticationTable, (err) => {
  if (err) {
    console.error("Error creating users table:", err);
  } else {
    console.log("Users table created successfully!");
  }
});

let errorMessages = "";
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/");
  }
}

app.get("/", (req, res) => {
  res.render("index.ejs", {
    title: "login",
    errorMessages,
  });
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs", { title: "Sign Up", errorMessages });
});

app.get("/home", isLoggedIn, (req, res) => {
  if (req.isAuthenticated()) {
    res.render("home.ejs", { title: "Home Page" });
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.post("/signup", async (req, res) => {
  const { username, email, phone, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    errorMessages = "Passwords do not match";
    res.redirect("/signup");
    return;
  }

  try {
    const result = await db.query(
      "SELECT * FROM authentication WHERE email = $1",
      [email]
    );

    if (result.rows.length > 0) {
      res.redirect("/");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("error hashing password");
        } else {
          const result = await db.query(
            "INSERT INTO  authentication (username, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING *",
            [username, email, phone, hash]
          );

          const user = result.rows[0];
          req.login(user, (err) => {
            res.redirect("/home");
          });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/",
  })
);

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query(
        "SELECT * FROM authentication WHERE email = $1",
        [username]
      );

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;

        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              errorMessages = "Wrong  password";
              return cb(null, false);
            }
          }
        });
      } else {
        errorMessages = "User not found";
        return cb(null, false);
      }
    } catch (error) {
      console.log(error);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
