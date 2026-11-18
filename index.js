import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();
const PORT = process.env.PORT || 5000;

// Allowed CORS origins
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5000",
  process.env.CLIENT_URL,
].filter(Boolean);

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(null, true);
    },
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}

const mongoClient = await connectToMongoDB();
const db = mongoClient.db("salonbook_db");
const usersCollection = db.collection("user");

// HTTPOnly Cookie Configuration
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
};

// JWT Verification Middleware for mutations
export const verifyJWT = async (req, res, next) => {
  // Check for JWT token in HTTPOnly cookies or Authorization header
  const token =
    req.cookies?.token ||
    (req.headers?.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.split(" ")[1]
      : null);

  // Check for better auth session cookie if token cookie not present
  const betterAuthToken =
    req.cookies?.["better-auth.session_token"] ||
    req.cookies?.["__Secure-better-auth.session_token"];

  if (!token && !betterAuthToken) {
    return res.status(401).json({
      success: false,
      message: "401 Unauthorized: Access token missing",
    });
  }

  if (token) {
    try {
      const secret =
        process.env.ACCESS_TOKEN_SECRET ||
        process.env.JWT_SECRET;
      const decoded = jwt.verify(token, secret);
      req.user = decoded;
      return next();
    } catch (err) {
      if (!betterAuthToken) {
        return res.status(401).json({
          success: false,
          message: "401 Unauthorized: Invalid or expired access token",
        });
      }
    }
  }

  // Fallback check for Better-Auth session in database
  if (betterAuthToken) {
    try {
      const sessionsCollection = db.collection("session");
      const sessionDoc = await sessionsCollection.findOne({
        token: betterAuthToken,
        expiresAt: { $gt: new Date() },
      });

      if (sessionDoc) {
        const usersCollection = db.collection("user");
        const userDoc = await usersCollection.findOne({
          _id: sessionDoc.userId,
        });
        req.user = {
          id: sessionDoc.userId,
          email: userDoc?.email || sessionDoc.userId,
          name: userDoc?.name,
        };
        return next();
      }
    } catch (sessionErr) {
      console.error("Session verification error:", sessionErr);
    }
  }

  return res.status(401).json({
    success: false,
    message: "401 Unauthorized: Access denied",
  });
};

// Issue JWT and store in HTTPOnly Cookie
app.post("/api/jwt", async (req, res) => {
  try {
    const user = req.body || {};
    if (!user.email) {
      return res.status(400).json({
        success: false,
        message: "User email is required to issue JWT",
      });
    }

    const secret = process.env.ACCESS_TOKEN_SECRET || process.env.JWT_SECRET;

    const token = jwt.sign(
      { email: user.email, name: user.name},
      secret,
      { expiresIn: "7d" }
    );

    res
      .cookie("token", token, cookieOptions)
      .status(200)
      .json({
        success: true,
        message: "JWT stored in HTTPOnly cookie successfully",
        token,
      });
  } catch (error) {
    console.error("Error creating JWT:", error);
    res.status(500).json({
      success: false,
      message: "Failed to issue JWT token",
      error: error.message,
    });
  }
});



// API check
app.get("/", (req, res) => {
  res.send("Server is online");
});

// Start server
if (process.env.VERCEL !== "1") {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

export default app;
