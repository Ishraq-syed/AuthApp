const express = require("express");
const router = express.Router();
const usersController = require("../controllers/usersController");
const authController = require("../controllers/authController");

// GET /api/users/
router.get("/", authController.protect, usersController.getAllUsers);

// DELETE /api/users/:id
router.delete(
  "/:id",
  authController.protect,
  authController.restrictTo("admin"),
  usersController.deleteUser,
);

router.get("/me", authController.protect, usersController.getMe);

module.exports = router;
