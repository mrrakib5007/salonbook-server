import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import multer from "multer";

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
const appointmentsCollection = db.collection("appointments");

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
    req.cookies?.["__Secure-better-auth.session_token"] ||
    req.headers?.["x-session-token"] ||
    (req.headers?.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.split(" ")[1]
      : null);

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
      const decodedToken = decodeURIComponent(betterAuthToken);
      const rawToken = decodedToken.includes(".")
        ? decodedToken.split(".")[0]
        : decodedToken;

      const sessionsCollection = db.collection("session");
      const sessionDoc = await sessionsCollection.findOne({
        token: { $in: [betterAuthToken, decodedToken, rawToken] },
        expiresAt: { $gt: new Date() },
      });

      if (sessionDoc) {
        const usersCollection = db.collection("user");
        let userDoc = null;
        if (sessionDoc.userId) {
          userDoc = await usersCollection.findOne({
            _id: sessionDoc.userId,
          });
          if (!userDoc && ObjectId.isValid(sessionDoc.userId)) {
            userDoc = await usersCollection.findOne({
              _id: new ObjectId(sessionDoc.userId),
            });
          }
        }
        req.user = {
          id: String(sessionDoc.userId),
          email: userDoc?.email || String(sessionDoc.userId),
          name: userDoc?.name,
          role: userDoc?.role || "user",
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

    let service = null;
    if (ObjectId.isValid(id)) {
      service = await servicesCollection.findOne({ _id: new ObjectId(id) });
    }
    if (!service) {
      service = await servicesCollection.findOne({ _id: id });
    }

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

// Create a new appointment booking (Protected)
app.post("/api/appointments", verifyJWT, async (req, res) => {
  try {
    const {
      serviceId,
      customerId,
      customerName,
      customerEmail,
      customerRole,
      appointmentDate,
      appointmentTime,
      message,
    } = req.body;

    // Rule: Admins cannot submit customer appointment requests
    const actualRole = req.user?.role || customerRole || "user";
    if (actualRole === "admin") {
      return res.status(403).json({
        success: false,
        message: "Administrators cannot book customer appointments.",
      });
    }

    if (!serviceId || !appointmentDate || !appointmentTime) {
      return res.status(400).json({
        success: false,
        message: "Service ID, appointment date, and time slot are required.",
      });
    }

    if (!ObjectId.isValid(serviceId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID format.",
      });
    }

    // Rule: Verify service exists and is active
    const service = await servicesCollection.findOne({ _id: new ObjectId(serviceId) });
    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    if (service.status !== "active") {
      return res.status(400).json({
        success: false,
        message: "This service is currently inactive and cannot be booked.",
      });
    }

    // Rule: Prevent duplicate active appointments for the same service, date, and time slot
    const serviceQueryId = ObjectId.isValid(serviceId)
      ? new ObjectId(serviceId)
      : serviceId;

    const existing = await appointmentsCollection.findOne({
      serviceId: serviceQueryId,
      appointmentDate,
      appointmentTime,
      appointmentStatus: { $ne: "Cancelled" },
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "This time slot is already booked for this service on the selected date. Please choose another time slot.",
      });
    }

    const newAppointment = {
      customerId: customerId || req.user?.id || "",
      customerName: customerName || req.user?.name || "Customer",
      customerEmail: customerEmail || req.user?.email || "",
      serviceId: new ObjectId(serviceId),
      serviceName: service.serviceName,
      serviceImage: service.image,
      category: service.category,
      price: service.price,
      duration: service.duration,
      appointmentDate,
      appointmentTime,
      message: message ? message.trim() : "",
      appointmentStatus: "Pending", // Default Status
      paymentStatus: "Unpaid",       // Default Payment Status
      createdAt: new Date(),
    };

    const result = await appointmentsCollection.insertOne(newAppointment);

    res.status(201).json({
      success: true,
      message: "Appointment request submitted successfully!",
      data: { ...newAppointment, _id: result.insertedId },
    });
  } catch (error) {
    console.error("Error creating appointment:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create appointment request.",
      error: error.message,
    });
  }
});

// Get booked slots for a specific date and service (Public availability check)
app.get("/api/appointments/booked-slots", async (req, res) => {
  try {
    const { date, serviceId } = req.query;
    if (!date) {
      return res.status(200).json({ success: true, bookedSlots: [] });
    }

    const query = {
      appointmentDate: date,
      appointmentStatus: { $ne: "Cancelled" },
    };

    if (serviceId) {
      query.serviceId = ObjectId.isValid(serviceId)
        ? new ObjectId(serviceId)
        : serviceId;
    }

    const appointments = await appointmentsCollection
      .find(query)
      .project({ appointmentTime: 1 })
      .toArray();

    const bookedSlots = appointments.map((a) => a.appointmentTime);
    res.status(200).json({ success: true, bookedSlots });
  } catch (error) {
    console.error("Error fetching booked slots:", error);
    res.status(500).json({ success: false, bookedSlots: [] });
  }
});

// Multer memory storage for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// Image upload API using ImgBB
app.post("/api/upload", upload.single("image"), async (req, res) => {
  try {
    const apiKey = process.env.IMGBB_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: "IMGBB_API_KEY is not configured on the server",
      });
    }

    let base64Image = null;

    if (req.file) {
      base64Image = req.file.buffer.toString("base64");
    } else if (req.body?.image) {
      base64Image = req.body.image.replace(/^data:image\/\w+;base64,/, "");
    }

    if (!base64Image) {
      return res.status(400).json({
        success: false,
        message: "No image file or image data provided",
      });
    }

    const imgbbForm = new FormData();
    imgbbForm.append("image", base64Image);

    const response = await fetch(`https://api.imgbb.com/1/upload?key=${apiKey}`, {
      method: "POST",
      body: imgbbForm,
    });

    const data = await response.json();

    if (!response.ok || !data.success || !data.data?.url) {
      return res.status(502).json({
        success: false,
        message: data?.error?.message || "Failed to upload image to ImgBB",
      });
    }

    res.status(200).json({
      success: true,
      url: data.data.url,
      display_url: data.data.display_url,
    });
  } catch (error) {
    console.error("Server image upload error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error during image upload",
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
