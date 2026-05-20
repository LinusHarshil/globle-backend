import mongoose from "mongoose";
import express from "express";

const courseSchema = new mongoose.Schema({
  title: String,
  price: Number,
  description: String,
  thumbnail: String,
  enrolled: Number,
  isFree: Boolean,
});
const Course = mongoose.model("Course", courseSchema);
export default Course;
