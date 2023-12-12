const jwt = require("jsonwebtoken");
require("dotenv").config({ path: "config/.env" });

function createAccessToken(id) {
  const accessToken = jwt.sign({ id: id }, process.env.SECRET_KEY, {
    expiresIn: "1h",
  });
  return accessToken;
}

function createRefreshToken() {
  const refreshToken = jwt.sign({}, process.env.SECRET_KEY, {
    expiresIn: "14d",
  });
  return refreshToken;
}

function validateRefreshToken(refreshToken) {
  try {
    jwt.verify(refreshToken, process.env.SECRET_KEY);
    return true;
  } catch (error) {
    return false;
  }
}
function validateAccessToken(accessToken) {
    try {
      jwt.verify(accessToken, process.env.SECRET_KEY);
      return true;
    } catch (error) {
      return false;
    }
  }

function getAccessTokenPayload(accessToken) {
    try {
        const payload = jwt.verify(accessToken, process.env.SECRET_KEY);
        console.log(payload);
        return payload;
    } catch (error) {
        return null;
    }
}

module.exports = { createAccessToken, createRefreshToken, validateRefreshToken, validateAccessToken, getAccessTokenPayload };
