const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const credentials = req.body;
  if (credentials) {
    const rounds = process.env.BCRYPT_ROUNDS || 8;
    const hash = bcryptjs.hashSync(credentials.password, rounds);
    credentials.password = hash;
    credentials.role_name = req.role_name;
    Users.add(credentials)
      .then((user) => {
        res.status(201).json(user);
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password and the password shoud be alphanumeric",
    });
  }
  // router.post("/register", validateRoleName, (req, res, next) => {
  //   const { username, password, role_name } = req.body;

  //   const hash = bcryptjs.hashSync(password, 10);
  //   const userForDb = { username, password: hash, role_name };

  //   Users.add(userForDb)
  //     .then((user) => {
  //       res.status(201).json(user);
  //     })
  //     .catch(next);
  // });

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  if (req.body) {
    Users.findBy({ username: username })
      .then(([user]) => {
        // compare the password the hash stored in the database
        if (user && bcryptjs.compareSync(password, user.password)) {
          // issue token
          const token = buildToken(user);
          res.status(200).json({ message: `${username} is back`, token });
        } else {
          res.status(401).json({ message: "Invalid credentials" });
        }
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password and the password shoud be alphanumeric",
    });
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});
function buildToken(user) {
  const payload = {
    // claims
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const config = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, config);
}

module.exports = router;
