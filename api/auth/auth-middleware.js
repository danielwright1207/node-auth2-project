const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const { findBy } = require("../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    res.status(401).json({ message: "Token required" });
  } else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: "Token invalid" });
      } else {
        req.decodedJwt = decoded;
        next();
      }
    });
  }
};

const only = (role_name) => (req, res, next) => {
  const decodedToken = req.decodedJwt;
  console.log(decodedToken);
  if (decodedToken.role_name !== role_name) {
    res.status(403).json({ message: "This is not for you" });
  } else {
    next();
  }
};

const checkUsernameExists = (req, res, next) => {
  const { username } = req.body;
  const checkUser = findBy({ username }).first();
  if (checkUser.username === username) {
    res.status(401).json({ message: "Invalid credentials" });
  } else {
    next();
  }
};

const validateRoleName = (req, res, next) => {
  const role = req.body.role_name;
  if (!role || role.trim() === "") {
    req.body.role_name = "student";
    next();
  } else if (role.trim() === "admin") {
    res.status(422).json({ message: "Role name can not be admin" });
  } else if (role.trim().length > 32) {
    res
      .status(422)
      .json({ message: "Role name can not be longer than 32 chars" });
  } else {
    req.body.role_name = role.trim();
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
