const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");
const bcrypt = require("bcryptjs");

router.post("/register", validateRoleName, (req, res, next) => {
  const credentials = req.body;

  if (credentials) {
    const rounds = process.env.BCRYPT_ROUNDS || 8;

    const hash = bcrypt.hashSync(credentials.password, rounds);

    credentials.password = hash;

    Users.add(credentials)
      .then((user) => {
        res.status(201).json(user);
      })
      .catch((err) => {
        res.status(500).json({ message: err.message, stack: err.stack });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password, password must be alphanumeric",
    });
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  if (req.body) {
    const { username, password } = req.body;

    Users.findBy({ username: username })
      .then(([user]) => {
        if (user && bcrypt.compareSync(password, user.password)) {
          const token = buildToken(user);
          res.status(200).json({ message: `${user.username} is back!`, token });
        } else {
          res.status(401).json({ message: "Invalid Credentials" });
        }
      })
      .catch((err) => {
        res.status(500).json({ message: err.message, stack: err.stack });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password, password must be alphanumeric",
    });
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const configuration = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, configuration);
}

module.exports = router;
