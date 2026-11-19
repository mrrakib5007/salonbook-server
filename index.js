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
  "https://salonbookpro.vercel.app",
  "https://api-salonbookpro.vercel.app",
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
const servicesCollection = db.collection("services");
const categoriesCollection = db.collection("categories");

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



// ---------------- SERVICES APIs ---------------- //


// get active services with optional search, category, sort & limit
app.get("/api/services", async (req, res) => {
  try {
    const { category, search, sort, limit, status } = req.query;

    const query = {};

    // Filter active services
    if (status) {
      query.status = status;
    } else {
      query.status = "active";
    }

    // Filter by Category
    if (category && category !== "All") {
      query.category = category;
    }

    // Search by Service Name
    if (search && search.trim() !== "") {
      query.serviceName = { $regex: search.trim(), $options: "i" };
    }

    // Sorting
    let sortOptions = { createdAt: -1 };
    if (sort === "price_asc") {
      sortOptions = { price: 1 };
    } else if (sort === "price_desc") {
      sortOptions = { price: -1 };
    }

    let cursor = servicesCollection.find(query).sort(sortOptions);

    if (limit && !isNaN(Number(limit))) {
      cursor = cursor.limit(Number(limit));
    }

    const services = await cursor.toArray();

    res.status(200).json({
      success: true,
      count: services.length,
      data: services,
    });
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch services",
      error: error.message,
    });
  }
});

// get single service by ID
app.get("/api/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID format",
      });
    }

    const service = await servicesCollection.findOne({ _id: new ObjectId(id) });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found",
      });
    }

    res.status(200).json({
      success: true,
      data: service,
    });
  } catch (error) {
    console.error("Error fetching service details:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch service details",
      error: error.message,
    });
  }
});

// get categories list
app.get("/api/categories", async (req, res) => {
  try {
    const categories = await categoriesCollection
      .find()
      .sort({ order: 1 })
      .toArray();

    res.status(200).json({
      success: true,
      count: categories.length,
      data: categories,
    });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch categories",
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
