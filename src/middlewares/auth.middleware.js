import { asyncHandler } from "../utils/asyncHandler.js";
import apiError from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken";
const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      throw new apiError(401, "unauthorized user");
    }
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );
    if (!user) {
      throw new apiError(401, "unauthorized user");
    }
    req.user = req.user||user;
    next();
  } catch (error) {
    throw new apiError(401, error.message||"INVALID ACCESS TOKEN", error);
  }
});
export default verifyJWT