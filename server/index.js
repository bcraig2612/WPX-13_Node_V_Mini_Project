require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');


const app = express();


app.use(express.json());


let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;


app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);


massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
  console.log('DB is Connected');
});


app.post('/auth/signup', async (req, res) => {
  // destructure email and password from the body or the request
  const { email, password } = req.body;
  // set db = to req.app.get("db") so we have access to the database instance set up when we connected with massive
  const db = req.app.get('db')
  // before allowing someone to sign-up, we first want to see if they are already in the database, if so, we dont want them     to sign up again so we send an error
  const userFound = await db.check_user_exists([email]);
   // database calls always return an array, so if we check the length of the returned array, it will tell us if a user is      found i.e. 1 = user found, 0 = no user 
  if (userFound[0]) {
    // error message if email isn't found
    return res.status(400).send('Email already exists');
  }
  // allow user to signup if no user was found
  // pass declared saltRounds to the genSalt function to get a unique salt value to be used when hashing our users password
  const salt = bcrypt.genSaltSync(10);
  // use the unique salt value and the password passed from req.body to generate a hashed password for the user
  const hash = bcrypt.hashSync(password, salt);
  // insert the email address and the hashed password into the database
  const createdUser = await db.create_customer([email, hash])
  // return newly created user and set them to a session.user so they can begin their unique user experience
  req.session.user = { id: createdUser[0].id, email: createdUser[0].email }
  // send session to the front
  res.status(200).send(req.session.user)
});


app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db = req.app.get('db')
  const userFound = await db.check_user_exists([email]);
  if (!userFound[0]) {
    return res.status(400).send('Incorrect email/password. Please try again.');
  }
  const result = bcrypt.compareSync(password, userFound[0].user_password)
  if (result) {
    req.session.user = { id: userFound[0].id, email: userFound[0].user_password }
    res.status(200).send(req.session.user)
  } else {
    return res.status(400).send('Incorrect email/password. Please try again.');
  }
});


app.get('/auth/logout', (req, res) => {  
  req.session.destroy();
  res.sendStatus(200);
});


app.get('/auth/user', (req, res) => {
  if (req.session.user) {
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('please log in')
  }
});

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
