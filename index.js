require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mqtt = require("mqtt");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const MQTT_URL = process.env.MQTT_URL || "mqtt://localhost:1883";

// ====== MONGO CONNECT ======
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {});
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  }
}
connectDB();
// ===========================

app.use(cors());
app.use(express.json());

// ====== USER MODEL ======
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true },
    passwordHash: { type: String, required: true },

    // Email verification
    isVerified: { type: Boolean, default: false },
    verificationCode: { type: String },
    verificationCodeExpires: { type: Date },

    // Login OTP
    loginOtpCode: { type: String },
    loginOtpExpires: { type: Date },

    // Forgot password
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
// ========================

// ====== DEVICE MODEL ======
const deviceSchema = new mongoose.Schema(
  {
    deviceId: { type: String, unique: true, required: true }, // e.g. "living-room"
    name: { type: String, required: true }, // display name
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    }, // user that owns this device
  },
  { timestamps: true }
);

const Device = mongoose.model("Device", deviceSchema);
// ==========================

// ====== HELPERS ======
function generateSixDigitCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function addMinutes(date, minutes) {
  return new Date(date.getTime() + minutes * 60000);
}

function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}
// =====================

// ====== AUTH MIDDLEWARE ======
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.substring(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { userId, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
// =============================

// ====== AUTH ROUTES ======

// REGISTER (no auto-login, requires email verification)
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email & password required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const verificationCode = generateSixDigitCode();
    const verificationCodeExpires = addMinutes(new Date(), 15); // 15 mins

    const user = await User.create({
      email,
      passwordHash,
      isVerified: false,
      verificationCode,
      verificationCodeExpires,
    });

    // TODO: send email with this verificationCode to user.email
    console.log(
      `📧 [DEV] Verification code for ${email}: ${verificationCode}`
    );

    res.json({
      message:
        "User registered. Please verify your email using the code sent.",
      devVerificationCode: verificationCode, // for dev/testing
    });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// VERIFY EMAIL
app.post("/auth/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) {
      return res
        .status(400)
        .json({ error: "Email & verification code are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.isVerified) {
      return res.json({ message: "Already verified" });
    }

    if (
      !user.verificationCode ||
      !user.verificationCodeExpires ||
      user.verificationCode !== code
    ) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    if (user.verificationCodeExpires < new Date()) {
      return res.status(400).json({ error: "Verification code expired" });
    }

    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpires = undefined;
    await user.save();

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: "15d" } // 15 days
    );

    res.json({
      message: "Email verified successfully",
      token,
      user: { id: user._id, email: user.email },
    });
  } catch (err) {
    console.error("Verify email error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// LOGIN (password)
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "Email & password required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    if (!user.isVerified) {
      return res.status(403).json({ error: "Email not verified" });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: "15d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user._id, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// REQUEST LOGIN OTP
app.post("/auth/request-otp", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal user existence
      return res.json({
        message:
          "If this email is registered, an OTP has been sent (check console in dev).",
      });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: "Email not verified" });
    }

    const otp = generateSixDigitCode();
    user.loginOtpCode = otp;
    user.loginOtpExpires = addMinutes(new Date(), 10); // 10 mins
    await user.save();

    // TODO: send email with otp
    console.log(`📧 [DEV] Login OTP for ${email}: ${otp}`);

    res.json({
      message:
        "If this email is registered, an OTP has been sent (check console in dev).",
    });
  } catch (err) {
    console.error("Request OTP error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// LOGIN WITH OTP
app.post("/auth/login-otp", async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) {
      return res.status(400).json({ error: "Email & OTP code are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid OTP" });

    if (!user.isVerified) {
      return res.status(403).json({ error: "Email not verified" });
    }

    if (
      !user.loginOtpCode ||
      !user.loginOtpExpires ||
      user.loginOtpCode !== code
    ) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    if (user.loginOtpExpires < new Date()) {
      return res.status(400).json({ error: "OTP expired" });
    }

    // Clear OTP
    user.loginOtpCode = undefined;
    user.loginOtpExpires = undefined;
    await user.save();

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: "15d" }
    );

    res.json({
      message: "Login with OTP successful",
      token,
      user: { id: user._id, email: user.email },
    });
  } catch (err) {
    console.error("Login OTP error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// FORGOT PASSWORD
app.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({
        message:
          "If this email is registered, a reset link has been sent (check console in dev).",
      });
    }

    const resetToken = generateResetToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = addMinutes(new Date(), 60); // 1 hour
    await user.save();

    const resetLink = `https://your-app-url/reset-password?token=${resetToken}`;

    // TODO: send email with resetLink
    console.log(
      `📧 [DEV] Password reset link for ${email}: ${resetLink}`
    );

    res.json({
      message:
        "If this email is registered, a reset link has been sent (check console in dev).",
    });
  } catch (err) {
    console.error("Forgot password error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) {
      return res
        .status(400)
        .json({ error: "Reset token and new password are required" });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});
// =========================

// ====== MQTT CLIENT + STATUS CACHE ======
const mqttClient = mqtt.connect(MQTT_URL);
const lastStatuses = {}; // { [deviceId]: { light, fan, ... } }

let io; // will be assigned after server is created

function subscribeDeviceTopics(deviceId) {
  const topic = `home/${deviceId}/status`;
  mqttClient.subscribe(topic, (err) => {
    if (err) {
      console.error("Failed to subscribe to", topic, err.message);
    } else {
      console.log("Subscribed to", topic);
    }
  });
}

mqttClient.on("connect", async () => {
  console.log("✅ MQTT connected to", MQTT_URL);

  try {
    const allDevices = await Device.find({});
    allDevices.forEach((d) => subscribeDeviceTopics(d.deviceId));
  } catch (err) {
    console.error("Error loading devices for MQTT subscription:", err.message);
  }
});

mqttClient.on("error", (err) => {
  console.error("MQTT error:", err.message);
});

mqttClient.on("message", (topic, message) => {
  const parts = topic.split("/");
  // Expecting: home/{deviceId}/status
  if (parts.length === 3 && parts[0] === "home" && parts[2] === "status") {
    const deviceId = parts[1];
    try {
      const payload = JSON.parse(message.toString());
      lastStatuses[deviceId] = payload;
      console.log("Status update from", deviceId, "->", payload);

      // 🔥 Emit realtime update to Socket.IO clients
      if (io) {
        io.emit("status_update", {
          deviceId,
          ...payload,
        });
      }
    } catch (e) {
      console.error("Invalid JSON on MQTT status for", deviceId, e.message);
    }
  }
});
// ========================================

// Health check (public)
app.get("/", (req, res) => {
  res.send(
    "✅ Automation Server (auth + MQTT + Socket.IO + multi-device + DB) is running"
  );
});

// ---------- DEVICE ROUTES (DB-BASED) ----------

// CREATE DEVICE (for now via Postman; later via app)
// body: { deviceId: "living-room", name: "Living Room Node" }
app.post("/devices", authMiddleware, async (req, res) => {
  try {
    const { deviceId, name } = req.body || {};
    const trimmedId = (deviceId || "").trim();

    if (!trimmedId || !name) {
      return res
        .status(400)
        .json({ error: "deviceId and name are required" });
    }

    const existing = await Device.findOne({ deviceId: trimmedId });
    if (existing) {
      return res
        .status(409)
        .json({ error: "Device with this ID already exists" });
    }

    const device = await Device.create({
      deviceId: trimmedId,
      name,
      owner: req.user.userId,
    });

    // Subscribe to MQTT topics for this new device
    subscribeDeviceTopics(device.deviceId);

    res.status(201).json({
      id: device.deviceId,
      name: device.name,
    });
  } catch (err) {
    console.error("Create device error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// LIST DEVICES (for logged-in user)
app.get("/devices", authMiddleware, async (req, res) => {
  try {
    const devices = await Device.find({ owner: req.user.userId }).sort({
      createdAt: 1,
    });

    const publicDevices = devices.map((d) => ({
      id: d.deviceId,
      name: d.name,
    }));

    res.json(publicDevices);
  } catch (err) {
    console.error("List devices error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// STATUS OF ONE DEVICE (FROM CACHE)
app.get("/devices/:id/status", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const device = await Device.findOne({
      deviceId: id,
      owner: req.user.userId,
    });
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }

    const status = lastStatuses[id];
    if (!status) {
      return res
        .status(404)
        .json({ error: "No status yet for this device (MQTT not received)" });
    }

    res.json({
      deviceId: device.deviceId,
      name: device.name,
      ...status,
    });
  } catch (err) {
    console.error("Get device status error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// CONTROL ONE DEVICE
// body: { device: "light" | "fan", state: "on" | "off" }
app.post("/devices/:id/control", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const deviceDoc = await Device.findOne({
      deviceId: id,
      owner: req.user.userId,
    });
    if (!deviceDoc) {
      return res.status(404).json({ error: "Device not found" });
    }

    const { device, state } = req.body || {};

    if (!["light", "fan"].includes(device)) {
      return res.status(400).json({ error: "Unknown relay device" });
    }
    if (!["on", "off"].includes(state)) {
      return res.status(400).json({ error: "Unknown state" });
    }

    const topic = `home/${deviceDoc.deviceId}/cmd`;
    const payload = JSON.stringify({ [device]: state });

    mqttClient.publish(topic, payload, (err) => {
      if (err) {
        console.error(`MQTT publish error to ${topic}:`, err.message);
        return res
          .status(500)
          .json({ error: "Failed to publish MQTT command" });
      }

      // We rely on MQTT + Socket.IO for actual status update
      res.json({
        ok: true,
        deviceId: deviceDoc.deviceId,
        name: deviceDoc.name,
        command: { device, state },
      });
    });
  } catch (err) {
    console.error("Control device error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// BACKWARD COMPATIBLE OLD ROUTES (/status, /control)
// Use the *first* device of current user
app.get("/status", authMiddleware, async (req, res) => {
  try {
    const firstDevice = await Device.findOne({
      owner: req.user.userId,
    }).sort({ createdAt: 1 });

    if (!firstDevice) {
      return res.status(500).json({ error: "No devices configured" });
    }

    const status = lastStatuses[firstDevice.deviceId];
    if (!status) {
      return res
        .status(404)
        .json({ error: "No status yet for this device (MQTT not received)" });
    }

    res.json({
      deviceId: firstDevice.deviceId,
      name: firstDevice.name,
      ...status,
    });
  } catch (err) {
    console.error("Legacy /status error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/control", authMiddleware, async (req, res) => {
  try {
    const firstDevice = await Device.findOne({
      owner: req.user.userId,
    }).sort({ createdAt: 1 });

    if (!firstDevice) {
      return res.status(500).json({ error: "No devices configured" });
    }

    const { device, state } = req.body || {};

    if (!["light", "fan"].includes(device)) {
      return res.status(400).json({ error: "Unknown relay device" });
    }
    if (!["on", "off"].includes(state)) {
      return res.status(400).json({ error: "Unknown state" });
    }

    const topic = `home/${firstDevice.deviceId}/cmd`;
    const payload = JSON.stringify({ [device]: state });

    mqttClient.publish(topic, payload, (err) => {
      if (err) {
        console.error(`MQTT publish error to ${topic}:`, err.message);
        return res
          .status(500)
          .json({ error: "Failed to publish MQTT command" });
      }

      res.json({
        ok: true,
        deviceId: firstDevice.deviceId,
        name: firstDevice.name,
        command: { device, state },
      });
    });
  } catch (err) {
    console.error("Legacy /control error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});
// ---------------------------------------------

// ====== SOCKET.IO + SERVER STARTUP ======
const server = http.createServer(app);

io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

io.on("connection", (socket) => {
  console.log("🟢 Socket client connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("🔴 Socket client disconnected:", socket.id);
  });
});

server.listen(PORT, "0.0.0.0", async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  try {
    const allDevices = await Device.find({});
    console.log("📡 Registered devices in DB:");
    if (!allDevices.length) {
      console.log("   (none yet - create via POST /devices)");
    } else {
      allDevices.forEach((d) =>
        console.log(`   - ${d.deviceId} (${d.name}) owner=${d.owner}`)
      );
    }
  } catch (err) {
    console.error("Error loading devices on startup:", err.message);
  }
});
