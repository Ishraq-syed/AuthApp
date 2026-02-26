const User = require("../models/userModel");

exports.deleteUser = async (req, res) => {
  try {
    // allow only admins to delete users
    if (!req.user || req.user.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: admins only" });
    }
    const { id } = req.params;
    if (!id) return res.status(400).json({ message: "Missing user id" });

    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({
      message: "User deleted",
      user: { id: user._id, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json({ users });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.getMe = async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ message: "Not logged in" });
    const userObj = req.user.toObject ? req.user.toObject() : { ...req.user };
    delete userObj.password;
    res.json({ user: userObj });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};
