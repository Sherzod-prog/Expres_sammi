import jwt from "jsonwebtoken";

const generateJWToken = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
  return accessToken;
};

export { generateJWToken };
