import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import userRoutes from "./source/routes/userRoutes.js";

dotenv.config();

const app = express();

app.use(
  cors({
    origin: "https://globle-igahu0e0i-linusharshils-projects.vercel.app",
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI);

mongoose.connection.once("open", () => {
  console.log("mongodb connected successfully");
});

app.get("/", (req, res) => {
  res.send("api running");
});

app.use("/api/users", userRoutes);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`server started at ${PORT}`);
});
