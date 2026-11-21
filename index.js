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
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-session-token"],
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
        if (userDoc?.isBlocked && userDoc?.role !== "admin") {
          return res.status(403).json({
            success: false,
            message: "Account Blocked: Your account has been restricted by an administrator. You cannot access protected platform features.",
            isBlocked: true,
          });
        }

        req.user = {
          id: String(sessionDoc.userId),
          email: userDoc?.email || String(sessionDoc.userId),
          name: userDoc?.name,
          role: userDoc?.role || "user",
          image: userDoc?.image || "",
          isBlocked: Boolean(userDoc?.isBlocked),
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




/* ========================================
     SERVICES APIs
======================================== */

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
      customerImage: req.user?.image || "",
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


/* ========================================
      Customer Dashboard
======================================== */

// Customer Dashboard Stats (Protected)
app.get("/api/customer/stats", verifyJWT, async (req, res) => {
  try {
    const userId = req.user?.id;
    const userEmail = req.user?.email;

    if (!userId && !userEmail) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: User identification missing",
      });
    }

    // Rule: Admins cannot access customer stats
    if (req.user?.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Administrators cannot access customer stats",
      });
    }

    // Match customer appointments by customerId or customerEmail
    const customerFilter = [];
    if (userId) {
      customerFilter.push({ customerId: userId });
      customerFilter.push({ customerId: String(userId) });
      if (ObjectId.isValid(userId)) {
        customerFilter.push({ customerId: new ObjectId(userId) });
      }
    }
    if (userEmail) {
      customerFilter.push({ customerEmail: userEmail });
    }

    const query = { $or: customerFilter };

    const [total, pending, confirmed, cancelled] = await Promise.all([
      appointmentsCollection.countDocuments(query),
      appointmentsCollection.countDocuments({ ...query, appointmentStatus: "Pending" }),
      appointmentsCollection.countDocuments({ ...query, appointmentStatus: "Confirmed" }),
      appointmentsCollection.countDocuments({ ...query, appointmentStatus: "Cancelled" }),
    ]);

    res.status(200).json({
      success: true,
      stats: {
        total,
        pending,
        confirmed,
        cancelled,
      },
    });
  } catch (error) {
    console.error("Error fetching customer dashboard stats:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch customer dashboard stats",
      error: error.message,
    });
  }
});

// Get All Appointments for Authenticated Customer (Protected)
app.get("/api/customer/appointments", verifyJWT, async (req, res) => {
  try {
    const userId = req.user?.id;
    const userEmail = req.user?.email;

    if (!userId && !userEmail) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: User identification missing",
      });
    }

    // Rule: Admins cannot access customer appointments
    if (req.user?.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Administrators cannot view customer appointments list",
      });
    }

    const customerFilter = [];
    if (userId) {
      customerFilter.push({ customerId: userId });
      customerFilter.push({ customerId: String(userId) });
      if (ObjectId.isValid(userId)) {
        customerFilter.push({ customerId: new ObjectId(userId) });
      }
    }
    if (userEmail) {
      customerFilter.push({ customerEmail: userEmail });
    }

    const query = { $or: customerFilter };

    const { status } = req.query;
    if (status && status !== "all" && ["Pending", "Confirmed", "Cancelled"].includes(status)) {
      query.appointmentStatus = status;
    }

    const appointments = await appointmentsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({
      success: true,
      appointments,
    });
  } catch (error) {
    console.error("Error fetching customer appointments:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch customer appointments",
      error: error.message,
    });
  }
});

// Cancel a Pending Appointment by Customer (Protected)
app.patch("/api/customer/appointments/:id/cancel", verifyJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user?.id;
    const userEmail = req.user?.email;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Appointment ID is required",
      });
    }

    if (req.user?.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Administrators cannot cancel customer appointment via this route",
      });
    }

    let appointment = null;
    if (ObjectId.isValid(id)) {
      appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
    }
    if (!appointment) {
      appointment = await appointmentsCollection.findOne({ _id: id });
    }

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found",
      });
    }

    // Verify ownership
    const isOwner =
      (userId && String(appointment.customerId) === String(userId)) ||
      (userEmail && appointment.customerEmail === userEmail);

    if (!isOwner) {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to cancel this appointment",
      });
    }

    // Rule: Customers can only cancel pending appointment requests
    if (appointment.appointmentStatus !== "Pending") {
      return res.status(400).json({
        success: false,
        message: `Cannot cancel an appointment with '${appointment.appointmentStatus}' status. Only pending requests can be cancelled.`,
      });
    }

    const filter = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { _id: id };
    await appointmentsCollection.updateOne(filter, {
      $set: {
        appointmentStatus: "Cancelled",
        cancelledAt: new Date(),
        cancelledBy: "customer",
      },
    });

    res.status(200).json({
      success: true,
      message: "Appointment request cancelled successfully.",
    });
  } catch (error) {
    console.error("Error cancelling customer appointment:", error);
    res.status(500).json({
      success: false,
      message: "Failed to cancel appointment request",
      error: error.message,
    });
  }
});

/* ========================================
      Admin Dashboard APIs
======================================== */

// GET Overview for Admin Dashboard
app.get("/api/admin/stats", verifyJWT, async (req, res) => {
  try {
    // Rule: Only Admin can access admin stats
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Admin access required",
      });
    }

    const [
      totalCustomers,
      totalActiveServices,
      totalAppointments,
      pendingAppointments,
      confirmedAppointments,
      totalSuccessfulPayments,
    ] = await Promise.all([
      usersCollection.countDocuments({ role: { $ne: "admin" } }),
      servicesCollection.countDocuments({ status: { $in: ["active", "Active"] } }),
      appointmentsCollection.countDocuments({}),
      appointmentsCollection.countDocuments({ appointmentStatus: "Pending" }),
      appointmentsCollection.countDocuments({ appointmentStatus: "Confirmed" }),
      appointmentsCollection.countDocuments({ paymentStatus: "Paid" }),
    ]);

    res.status(200).json({
      success: true,
      stats: {
        totalCustomers,
        totalActiveServices,
        totalAppointments,
        pendingAppointments,
        confirmedAppointments,
        totalSuccessfulPayments,
      },
    });
  } catch (error) {
    console.error("Error fetching admin stats:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch admin dashboard statistics",
      error: error.message,
    });
  }
});

// GET all services (Admin only)
app.get("/api/admin/services", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Admin access required",
      });
    }

    const { category, search, status, sort } = req.query;
    const query = {};

    // Status filter
    if (status && status !== "all" && status !== "All") {
      query.status = status.toLowerCase();
    }

    // Category filter
    if (category && category !== "all" && category !== "All") {
      query.category = category;
    }

    // Search by service name, category, or description
    if (search && search.trim()) {
      const searchRegex = { $regex: search.trim(), $options: "i" };
      query.$or = [
        { serviceName: searchRegex },
        { category: searchRegex },
        { description: searchRegex },
      ];
    }

    // Sort options
    let sortOptions = { createdAt: -1 };
    if (sort === "price_asc") {
      sortOptions = { price: 1 };
    } else if (sort === "price_desc") {
      sortOptions = { price: -1 };
    } else if (sort === "name_asc") {
      sortOptions = { serviceName: 1 };
    } else if (sort === "oldest") {
      sortOptions = { createdAt: 1 };
    }

    const services = await servicesCollection.find(query).sort(sortOptions).toArray();

    res.status(200).json({
      success: true,
      count: services.length,
      data: services,
    });
  } catch (error) {
    console.error("Error fetching admin services:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch services",
      error: error.message,
    });
  }
});

// create a new service (Admin only)
app.post("/api/admin/services", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Admin access required",
      });
    }

    const {
      serviceName,
      category,
      description,
      price,
      duration,
      image,
      status,
    } = req.body || {};

    // Required fields validation
    if (!serviceName || !serviceName.trim()) {
      return res.status(400).json({
        success: false,
        message: "Service name is required",
      });
    }

    if (!category || !category.trim()) {
      return res.status(400).json({
        success: false,
        message: "Service category is required",
      });
    }

    if (!description || !description.trim()) {
      return res.status(400).json({
        success: false,
        message: "Service description is required",
      });
    }

    const parsedPrice = Number(price);
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      return res.status(400).json({
        success: false,
        message: "Price must be a positive number",
      });
    }

    const parsedDuration = Number(duration);
    if (isNaN(parsedDuration) || parsedDuration <= 0) {
      return res.status(400).json({
        success: false,
        message: "Duration must be a positive number (in minutes)",
      });
    }

    if (!image || !image.trim()) {
      return res.status(400).json({
        success: false,
        message: "Service image is required",
      });
    }

    const finalStatus =
      status === "inactive" || status === "Inactive" ? "inactive" : "active";

    const newService = {
      serviceName: serviceName.trim(),
      category: category.trim(),
      description: description.trim(),
      price: parsedPrice,
      duration: Math.round(parsedDuration),
      image: image.trim(),
      status: finalStatus,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const insertResult = await servicesCollection.insertOne(newService);

    res.status(201).json({
      success: true,
      message: "Service created successfully!",
      data: {
        _id: insertResult.insertedId,
        ...newService,
      },
    });
  } catch (error) {
    console.error("Error creating service:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create service",
      error: error.message,
    });
  }
});

// update an existing service (Admin only)
app.put("/api/admin/services/:id", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Admin access required",
      });
    }

    const { id } = req.params;
    const {
      serviceName,
      category,
      description,
      price,
      duration,
      image,
      status,
    } = req.body || {};

    const updateFields = {
      updatedAt: new Date(),
    };

    if (serviceName !== undefined) {
      if (!serviceName.trim()) {
        return res.status(400).json({
          success: false,
          message: "Service name cannot be empty",
        });
      }
      updateFields.serviceName = serviceName.trim();
    }

    if (category !== undefined) {
      if (!category.trim()) {
        return res.status(400).json({
          success: false,
          message: "Service category cannot be empty",
        });
      }
      updateFields.category = category.trim();
    }

    if (description !== undefined) {
      if (!description.trim()) {
        return res.status(400).json({
          success: false,
          message: "Service description cannot be empty",
        });
      }
      updateFields.description = description.trim();
    }

    if (price !== undefined) {
      const parsedPrice = Number(price);
      if (isNaN(parsedPrice) || parsedPrice <= 0) {
        return res.status(400).json({
          success: false,
          message: "Price must be a positive number",
        });
      }
      updateFields.price = parsedPrice;
    }

    if (duration !== undefined) {
      const parsedDuration = Number(duration);
      if (isNaN(parsedDuration) || parsedDuration <= 0) {
        return res.status(400).json({
          success: false,
          message: "Duration must be a positive number (in minutes)",
        });
      }
      updateFields.duration = Math.round(parsedDuration);
    }

    if (image !== undefined && image.trim()) {
      updateFields.image = image.trim();
    }

    if (status !== undefined) {
      updateFields.status =
        status === "inactive" || status === "Inactive" ? "inactive" : "active";
    }

    // Support both ObjectId and plain string ID as per DB invariants
    let filter = { _id: id };
    if (ObjectId.isValid(id)) {
      filter = { $or: [{ _id: new ObjectId(id) }, { _id: id }] };
    }

    const updateResult = await servicesCollection.updateOne(filter, {
      $set: updateFields,
    });

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found",
      });
    }

    const updatedService = await servicesCollection.findOne(filter);

    res.status(200).json({
      success: true,
      message: "Service updated successfully!",
      data: updatedService,
    });
  } catch (error) {
    console.error("Error updating service:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update service",
      error: error.message,
    });
  }
});

// activate / deactivate service status (Admin only)
app.patch("/api/admin/services/:id/status", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Admin access required",
      });
    }

    const { id } = req.params;
    const { status } = req.body || {};

    if (!status || !["active", "inactive"].includes(status.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: "Status must be either 'active' or 'inactive'",
      });
    }

    const normalizedStatus = status.toLowerCase();

    // Support both ObjectId and plain string ID
    let filter = { _id: id };
    if (ObjectId.isValid(id)) {
      filter = { $or: [{ _id: new ObjectId(id) }, { _id: id }] };
    }

    const updateResult = await servicesCollection.updateOne(filter, {
      $set: {
        status: normalizedStatus,
        updatedAt: new Date(),
      },
    });

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found",
      });
    }

    res.status(200).json({
      success: true,
      message: `Service has been ${
        normalizedStatus === "active" ? "activated" : "deactivated"
      } successfully!`,
      status: normalizedStatus,
    });
  } catch (error) {
    console.error("Error updating service status:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update service status",
      error: error.message,
    });
  }
});

// remove a service (Admin only)
app.delete("/api/admin/services/:id", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Admin access required",
      });
    }

    const { id } = req.params;

    // Support both ObjectId and plain string ID
    let filter = { _id: id };
    if (ObjectId.isValid(id)) {
      filter = { $or: [{ _id: new ObjectId(id) }, { _id: id }] };
    }

    const deleteResult = await servicesCollection.deleteOne(filter);

    if (deleteResult.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Service deleted successfully!",
    });
  } catch (error) {
    console.error("Error deleting service:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete service",
      error: error.message,
    });
  }
});

/* ========================================
      Admin Manage Appointments APIs
======================================== */

// GET all appointments 
app.get("/api/admin/appointments", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { search, status, paymentStatus, sort } = req.query;
    const query = {};

    // Filter by Appointment Status
    if (
      status &&
      status !== "all" &&
      ["Pending", "Confirmed", "Cancelled"].includes(status)
    ) {
      query.appointmentStatus = status;
    }

    // Filter by Payment Status
    if (
      paymentStatus &&
      paymentStatus !== "all" &&
      ["Paid", "Unpaid"].includes(paymentStatus)
    ) {
      query.paymentStatus = paymentStatus;
    }

    // Search filter across customerName, customerEmail, and serviceName
    if (search && search.trim()) {
      const searchRegex = new RegExp(search.trim(), "i");
      query.$or = [
        { customerName: searchRegex },
        { customerEmail: searchRegex },
        { serviceName: searchRegex },
      ];
    }

    // Sorting
    let sortOption = { createdAt: -1 };
    if (sort === "oldest") {
      sortOption = { createdAt: 1 };
    } else if (sort === "date_asc") {
      sortOption = { appointmentDate: 1, appointmentTime: 1 };
    } else if (sort === "date_desc") {
      sortOption = { appointmentDate: -1, appointmentTime: -1 };
    } else if (sort === "price_desc") {
      sortOption = { price: -1 };
    } else if (sort === "price_asc") {
      sortOption = { price: 1 };
    }

    const appointments = await appointmentsCollection
      .find(query)
      .sort(sortOption)
      .toArray();

    // Look up user profiles to enrich customerImage if available
    const customerEmails = [
      ...new Set(appointments.map((a) => a.customerEmail).filter(Boolean)),
    ];
    const customerIds = [
      ...new Set(appointments.map((a) => a.customerId).filter(Boolean)),
    ];

    const orClauses = [];
    if (customerEmails.length > 0) {
      orClauses.push({ email: { $in: customerEmails } });
    }
    if (customerIds.length > 0) {
      orClauses.push({ _id: { $in: customerIds } });
      const validObjIds = customerIds
        .filter((id) => ObjectId.isValid(id))
        .map((id) => new ObjectId(id));
      if (validObjIds.length > 0) {
        orClauses.push({ _id: { $in: validObjIds } });
      }
    }

    let matchedUsers = [];
    if (orClauses.length > 0) {
      matchedUsers = await usersCollection.find({ $or: orClauses }).toArray();
    }

    const userMapByEmail = new Map();
    const userMapById = new Map();
    for (const u of matchedUsers) {
      if (u.email) userMapByEmail.set(u.email, u);
      if (u._id) userMapById.set(String(u._id), u);
    }

    const enrichedAppointments = appointments.map((appt) => {
      const u =
        (appt.customerEmail && userMapByEmail.get(appt.customerEmail)) ||
        (appt.customerId && userMapById.get(String(appt.customerId)));
      return {
        ...appt,
        customerImage: appt.customerImage || u?.image || "",
      };
    });

    res.status(200).json({
      success: true,
      appointments: enrichedAppointments,
      total: enrichedAppointments.length,
    });
  } catch (error) {
    console.error("Error fetching admin appointments:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch appointments.",
      error: error.message,
    });
  }
});

// GET single appointment details by ID
app.get("/api/admin/appointments/:id", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { id } = req.params;
    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Appointment ID is required.",
      });
    }

    let appointment = null;
    if (ObjectId.isValid(id)) {
      appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
    }
    if (!appointment) {
      appointment = await appointmentsCollection.findOne({ _id: id });
    }

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found.",
      });
    }

    let customerImage = appointment.customerImage || "";
    if (!customerImage && (appointment.customerEmail || appointment.customerId)) {
      const orClauses = [];
      if (appointment.customerEmail) orClauses.push({ email: appointment.customerEmail });
      if (appointment.customerId) {
        orClauses.push({ _id: appointment.customerId });
        if (ObjectId.isValid(appointment.customerId)) {
          orClauses.push({ _id: new ObjectId(appointment.customerId) });
        }
      }
      if (orClauses.length > 0) {
        const userDoc = await usersCollection.findOne({ $or: orClauses });
        if (userDoc?.image) {
          customerImage = userDoc.image;
        }
      }
    }

    res.status(200).json({
      success: true,
      appointment: {
        ...appointment,
        customerImage,
      },
    });
  } catch (error) {
    console.error("Error fetching single appointment:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch appointment details.",
      error: error.message,
    });
  }
});

// Confirm a Pending Appointment
app.patch("/api/admin/appointments/:id/confirm", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { id } = req.params;
    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Appointment ID is required.",
      });
    }

    let appointment = null;
    if (ObjectId.isValid(id)) {
      appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
    }
    if (!appointment) {
      appointment = await appointmentsCollection.findOne({ _id: id });
    }

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found.",
      });
    }

    // Rule: Only pending appointments can be confirmed
    if (appointment.appointmentStatus !== "Pending") {
      return res.status(400).json({
        success: false,
        message: `Only pending appointments can be confirmed. Current status is '${appointment.appointmentStatus}'.`,
      });
    }

    const now = new Date();
    await appointmentsCollection.updateOne(
      { _id: appointment._id },
      {
        $set: {
          appointmentStatus: "Confirmed",
          confirmedAt: now,
          updatedAt: now,
        },
      }
    );

    const updated = await appointmentsCollection.findOne({ _id: appointment._id });

    res.status(200).json({
      success: true,
      message: "Appointment confirmed successfully!",
      appointment: updated,
    });
  } catch (error) {
    console.error("Error confirming appointment:", error);
    res.status(500).json({
      success: false,
      message: "Failed to confirm appointment.",
      error: error.message,
    });
  }
});

// Cancel an Appointment
app.patch("/api/admin/appointments/:id/cancel", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { id } = req.params;
    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Appointment ID is required.",
      });
    }

    let appointment = null;
    if (ObjectId.isValid(id)) {
      appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
    }
    if (!appointment) {
      appointment = await appointmentsCollection.findOne({ _id: id });
    }

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found.",
      });
    }

    // Rule: If already cancelled, do not cancel again
    if (appointment.appointmentStatus === "Cancelled") {
      return res.status(400).json({
        success: false,
        message: "This appointment has already been cancelled.",
      });
    }

    const now = new Date();
    await appointmentsCollection.updateOne(
      { _id: appointment._id },
      {
        $set: {
          appointmentStatus: "Cancelled",
          cancelledAt: now,
          updatedAt: now,
        },
      }
    );

    const updated = await appointmentsCollection.findOne({ _id: appointment._id });

    res.status(200).json({
      success: true,
      message: "Appointment cancelled successfully. The time slot is now available again.",
      appointment: updated,
    });
  } catch (error) {
    console.error("Error cancelling appointment:", error);
    res.status(500).json({
      success: false,
      message: "Failed to cancel appointment.",
      error: error.message,
    });
  }
});

/* ========================================
      Admin Manage Users APIs
======================================== */

// GET all registered customers
app.get("/api/admin/users", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { search, status, sort } = req.query;
    const query = { role: { $ne: "admin" } };

    // Filter by Account Status (Active vs Blocked)
    if (status === "active") {
      query.isBlocked = { $ne: true };
    } else if (status === "blocked") {
      query.isBlocked = true;
    }

    // Search filter across name and email
    if (search && search.trim()) {
      const searchRegex = new RegExp(search.trim(), "i");
      query.$or = [
        { name: searchRegex },
        { email: searchRegex },
      ];
    }

    // Sorting
    let sortOption = { createdAt: -1 };
    if (sort === "oldest") {
      sortOption = { createdAt: 1 };
    } else if (sort === "name_asc") {
      sortOption = { name: 1 };
    } else if (sort === "name_desc") {
      sortOption = { name: -1 };
    }

    const users = await usersCollection
      .find(query)
      .sort(sortOption)
      .toArray();

    // Calculate appointment counts for each customer
    const userEmails = users.map((u) => u.email).filter(Boolean);
    const userIds = users.map((u) => String(u._id)).filter(Boolean);

    const appointments = await appointmentsCollection
      .find({
        $or: [
          { customerEmail: { $in: userEmails } },
          { customerId: { $in: userIds } },
        ],
      })
      .project({ customerEmail: 1, customerId: 1, appointmentStatus: 1 })
      .toArray();

    const countsMap = new Map();
    for (const appt of appointments) {
      const email = appt.customerEmail;
      const id = String(appt.customerId);
      if (email) countsMap.set(email, (countsMap.get(email) || 0) + 1);
      if (id && id !== email) countsMap.set(id, (countsMap.get(id) || 0) + 1);
    }

    const sanitizedUsers = users.map((u) => ({
      _id: String(u._id),
      name: u.name || "Customer",
      email: u.email || "",
      image: u.image || "",
      role: u.role || "user",
      isBlocked: Boolean(u.isBlocked),
      phone: u.phone || u.phoneNumber || "",
      createdAt: u.createdAt || null,
      totalBookings: countsMap.get(u.email) || countsMap.get(String(u._id)) || 0,
    }));

    res.status(200).json({
      success: true,
      users: sanitizedUsers,
      total: sanitizedUsers.length,
    });
  } catch (error) {
    console.error("Error fetching admin users:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch users list.",
      error: error.message,
    });
  }
});

// GET single customer details by ID
app.get("/api/admin/users/:id", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { id } = req.params;
    if (!id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    let userDoc = await usersCollection.findOne({ _id: id });
    if (!userDoc && ObjectId.isValid(id)) {
      userDoc = await usersCollection.findOne({ _id: new ObjectId(id) });
    }

    if (!userDoc) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    // Get user's appointment statistics
    const customerFilter = [{ customerEmail: userDoc.email }];
    if (userDoc._id) customerFilter.push({ customerId: String(userDoc._id) });

    const totalCount = await appointmentsCollection.countDocuments({
      $or: customerFilter,
    });

    res.status(200).json({
      success: true,
      user: {
        _id: String(userDoc._id),
        name: userDoc.name || "Customer",
        email: userDoc.email || "",
        image: userDoc.image || "",
        role: userDoc.role || "user",
        isBlocked: Boolean(userDoc.isBlocked),
        phone: userDoc.phone || userDoc.phoneNumber || "",
        createdAt: userDoc.createdAt || null,
        blockedAt: userDoc.blockedAt || null,
        totalBookings: totalCount,
      },
    });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch user details.",
      error: error.message,
    });
  }
});

// Block a customer account
app.patch("/api/admin/users/:id/block", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { id } = req.params;
    if (!id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    let filter = { _id: id };
    let userDoc = await usersCollection.findOne(filter);
    if (!userDoc && ObjectId.isValid(id)) {
      filter = { _id: new ObjectId(id) };
      userDoc = await usersCollection.findOne(filter);
    }

    if (!userDoc) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    if (userDoc.role === "admin") {
      return res.status(403).json({
        success: false,
        message: "Administrator accounts cannot be blocked.",
      });
    }

    const now = new Date();
    await usersCollection.updateOne(filter, {
      $set: {
        isBlocked: true,
        blockedAt: now,
        updatedAt: now,
      },
    });

    res.status(200).json({
      success: true,
      message: `Customer ${userDoc.name || userDoc.email} has been blocked successfully.`,
      isBlocked: true,
    });
  } catch (error) {
    console.error("Error blocking user:", error);
    res.status(500).json({
      success: false,
      message: "Failed to block user.",
      error: error.message,
    });
  }
});

// Unblock a customer account
app.patch("/api/admin/users/:id/unblock", verifyJWT, async (req, res) => {
  try {
    if (req.user?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Administrator privileges required.",
      });
    }

    const { id } = req.params;
    if (!id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    let filter = { _id: id };
    let userDoc = await usersCollection.findOne(filter);
    if (!userDoc && ObjectId.isValid(id)) {
      filter = { _id: new ObjectId(id) };
      userDoc = await usersCollection.findOne(filter);
    }

    if (!userDoc) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    const now = new Date();
    await usersCollection.updateOne(filter, {
      $set: {
        isBlocked: false,
        unblockedAt: now,
        updatedAt: now,
      },
    });

    res.status(200).json({
      success: true,
      message: `Customer ${userDoc.name || userDoc.email} has been unblocked successfully.`,
      isBlocked: false,
    });
  } catch (error) {
    console.error("Error unblocking user:", error);
    res.status(500).json({
      success: false,
      message: "Failed to unblock user.",
      error: error.message,
    });
  }
});

/* ========================================
      User Profile APIs
======================================== */

// GET authenticated user profile
app.get("/api/user/profile", verifyJWT, async (req, res) => {
  try {
    const userId = req.user?.id;
    const userEmail = req.user?.email;

    if (!userId && !userEmail) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: User identification missing",
      });
    }

    let userDoc = null;
    if (userId) {
      userDoc = await usersCollection.findOne({ _id: userId });
      if (!userDoc && ObjectId.isValid(userId)) {
        userDoc = await usersCollection.findOne({ _id: new ObjectId(userId) });
      }
    }
    if (!userDoc && userEmail) {
      userDoc = await usersCollection.findOne({ email: userEmail });
    }

    if (!userDoc) {
      return res.status(404).json({
        success: false,
        message: "User profile not found",
      });
    }

    res.status(200).json({
      success: true,
      user: {
        _id: userDoc._id,
        name: userDoc.name || "",
        email: userDoc.email || "",
        image: userDoc.image || "",
        phone: userDoc.phone || userDoc.phoneNumber || "",
        createdAt: userDoc.createdAt || null,
      },
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch user profile",
      error: error.message,
    });
  }
});

// Update user profile information
app.patch("/api/user/profile", verifyJWT, async (req, res) => {
  try {
    const userId = req.user?.id;
    const userEmail = req.user?.email;

    if (!userId && !userEmail) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: User identification missing",
      });
    }

    // Permitted fields only: name, image, and optional phone
    const { name, image, phone } = req.body || {};

    if (name !== undefined && typeof name === "string" && !name.trim()) {
      return res.status(400).json({
        success: false,
        message: "Name cannot be empty",
      });
    }

    const updateFields = {
      updatedAt: new Date(),
    };

    if (typeof name === "string") updateFields.name = name.trim();
    if (typeof image === "string") updateFields.image = image.trim();
    if (typeof phone === "string") updateFields.phone = phone.trim();

    let filter = null;
    if (userId) {
      const exists = await usersCollection.findOne({ _id: userId });
      if (exists) filter = { _id: userId };
      else if (ObjectId.isValid(userId)) {
        const existsObj = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (existsObj) filter = { _id: new ObjectId(userId) };
      }
    }
    if (!filter && userEmail) {
      filter = { email: userEmail };
    }

    if (!filter) {
      return res.status(404).json({
        success: false,
        message: "User account not found for profile update",
      });
    }

    const updateResult = await usersCollection.updateOne(filter, { $set: updateFields });

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "User account not found",
      });
    }

    const updatedUser = await usersCollection.findOne(filter);

    res.status(200).json({
      success: true,
      message: "Profile updated successfully!",
      user: {
        name: updatedUser?.name || "",
        image: updatedUser?.image || "",
        phone: updatedUser?.phone || updatedUser?.phoneNumber || "",
      },
    });
  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update profile",
      error: error.message,
    });
  }
});



/* ========================================
      Image upload api
======================================== */

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
