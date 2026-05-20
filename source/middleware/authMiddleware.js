import mongoose from "mongoose";
import User from "../models/User.js";
import express from "express";
import jwt from "jsonwebtoken";

const authMiddleware = async (req, res, next) => {
  try {
    const cookieToken = req.cookies.token;

    if (!cookieToken) {
      return res.status(401).send("Access denied");
    }
    const token = cookieToken;
    // const token = cookieToken.split(" ")[1];

    if (!token) {
      return res.status(401).send("Invalid token");
    }

    // console.log(`This is the decoded jwt ${decoded}`);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }
    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: "Verify your account",
      });
    }

    if (user.isSuspended) {
      return res.status(403).json({
        success: false,
        message: "Account suspended",
      });
    }
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).send("Unauthorized");
  }
};

export default authMiddleware;
