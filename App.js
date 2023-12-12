const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require('cookie-parser');
const bcrypt = require("bcrypt");
const mysql = require("mysql");
const morgan = require("morgan");
const cors = require("cors");
const redis = require("redis");
const { createAccessToken, createRefreshToken, validateRefreshToken, validateAccessToken, getAccessTokenPayload} = require("./util.js");
require("dotenv").config({ path: "config/.env" });

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));

const redisClient = redis.createClient({
  url: `redis://${process.env.REDIS_USERNAME}:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}/0`,
  legacyMode: true,
});

redisClient.on("connect", () => {
  console.info("Redis connected!");
});
redisClient.on("error", (err) => {
  console.error("Redis Client Error", err);
});
redisClient.connect().then();
const redisCli = redisClient.v4;

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL에 연결되었습니다");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) throw err;

      if (
        results.length > 0 &&
        (await bcrypt.compare(password, results[0].password))
      ) {
        const id = results[0].id;
        const accessToken = createAccessToken(id);
        const refreshtoken = createRefreshToken();
        res.cookie("accessToken", accessToken, { httpOnly: true });
        res.cookie("refreshToken", refreshtoken);
        redisClient.set(id, refreshtoken, (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: "저장실패" });
          }
        });
        res.status(200).send({ message: "로그인 성공" });
      } else {
        res
          .status(40)
          .send({ message: "아이디 또는 비밀번호가 잘못되었습니다" });
      }
    }
  );
});
app.post("/signup", async (req, res) => {
  try {
    const { username, password, name, address, phone, email } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      username,
      password: hashedPassword,
      name,
      address,
      phone,
      email,
    };

    db.query("INSERT INTO users SET ?", user, (err, results) => {
      if (err) throw err;
      res.status(200).send({ message: "회원가입 성공" });
    });
  } catch (err) {
    res.status(500).send({ message: "서버 에러" });
  }
});

app.get("/getToken", (req, res) => {
  const accessToken = req.cookies.accessToken;
  const refreshToken = req.cookies.refreshToken;
  const { id } = getAccessTokenPayload(accessToken);

  if (!accessToken || !refreshToken) return res.status(400).json({ message: "token이 존재하지 않습니다."})

  const isAccessTokenValidate = validateAccessToken(accessToken);
  const isRefreshTokenValidate = validateRefreshToken(refreshToken);

  if (!isRefreshTokenValidate) return res.status(419).json({ message: "Refresh Token 만료"});

  if (!isAccessTokenValidate) {
    const redisRefreshToken = redisCli.get(id);
    if (!redisRefreshToken || redisRefreshToken !== refreshToken) return res.status(419).json({ message: 'Refresh Token의 정보가 서버에 존재하지 않습니다.'});
    const newAccressToken = createAccessToken(id);
    res.cookie('accessToken', newAccressToken);
    return res.json({ message: 'Access Token을 새롭게 발급하였습니다.'})
  }
  return res.json({ message: `${id}의 Payload를 가진 Token이 성공적으로 인증되었습니다.` });
})


app.post("/logout", (req, res) => {
  const refreshToken = req.cookies['refreshToken'];
  const accessToken = req.cookies['accessToken'];
  const { id } = getAccessTokenPayload(accessToken);

  if (!refreshToken) {
    return res.sendStatus(403);
  }

  redisClient.del(id, (err, reply) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "로그아웃 실패" });
    }
    if(reply == 1) {
      console.info('로그아웃 성공');
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.status(200).send({ message: "로그아웃 성공" });
    } else {
      console.error('해당 토큰이 존재하지 않습니다');
      res.status(400).send({ message: "로그아웃 실패, 해당 토큰이 존재하지 않습니다" });
    }
  });
});

app.get('/notice', (req, res) => {
  db.query("SELECT * FROM Notice", (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send('Server Error');
    } else {
      res.json(results);
    }
  });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`서버가 ${PORT}번 포트에서 실행 중입니다`);
});
