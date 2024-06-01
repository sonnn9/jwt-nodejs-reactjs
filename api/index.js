const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cors = require('cors');

app.use(cors());
app.use(express.json());

const SecretKey = "mySecretKey";
const RefreshSecretKey = "myRefreshSecretKey"

const users = [
  {
    id: "1",
    username: "admin",
    password: "123456",
    isAdmin: true,
  },
  {
    id: "2",
    username: "son",
    password: "123456",
    isAdmin: false,
  },
];

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
  //take the refresh token from the user
  const refreshToken = req.body.token;

  //send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("You are not authenticated!");
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is not valid!");
  }
  jwt.verify(refreshToken, RefreshSecretKey, (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });

  //if everything is ok, create new access token, refresh token and send to user
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, SecretKey , {
    expiresIn: "50s",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, RefreshSecretKey );
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    //Generate an access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json("Username or password incorrect!");
  }
});


// Middleware trong Express.js được sử dụng để xác thực các yêu cầu HTTP dựa trên mã token JWT (JSON Web Token). 
// Middleware này sẽ kiểm tra xem yêu cầu có chứa token hợp lệ hay không trước khi cho phép tiến hành đến bước xử lý tiếp theo
const verify = (req, res, next) => {
  const authHeader = req.headers.authorization; //Middleware sẽ lấy giá trị của tiêu đề authorization từ yêu cầu HTTP.
  if (authHeader) { // Checking if Authorization Header Exists
    const token = authHeader.split(" ")[1];

    jwt.verify(token, SecretKey, (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted.");
  } else {
    res.status(403).json("You are not allowed to delete this user!");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("You logged out successfully.");
});

app.listen(5000, () => console.log("Backend server is running!"));

