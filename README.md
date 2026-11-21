# SalonBook - Server Backend API

A robust, secure RESTful API backend service built with **Express.js 5** (ES Module) and **MongoDB Atlas** for the **SalonBook** appointment booking platform. The server manages authentication verification, salon service catalogs, slot availability and conflict handling, appointment lifecycle operations, ImgBB image uploads, and Stripe webhook payment processing.

---

## Project Links

- **Live Website:** [https://salonbookpro.vercel.app](https://salonbookpro.vercel.app)
- **Live API Endpoint:** [https://api-salonbookpro.vercel.app](https://api-salonbookpro.vercel.app)
- **Client Repository:** [https://github.com/mrrakib5007/salonbook-client](https://github.com/mrrakib5007/salonbook-client)
- **Server Repository:** [https://github.com/mrrakib5007/salonbook-server](https://github.com/mrrakib5007/salonbook-server)

---

## Important Features

### Security and Role-Based Authorization
- **Unified Authentication Middleware (`verifyJWT`):** Validates custom JWT tokens and Better-Auth HMAC-signed session cookies (splitting signature token from raw MongoDB token).
- **Administrative Access Control (`verifyAdmin`):** Strict verification ensuring non-admins cannot mutate services, alter customer statuses, access financial audit logs, or perform privileged operations.
- **Customer Protection:** Non-admins cannot access admin endpoints; blocked users cannot perform protected actions.

### Salon Service Management
- **Public Service APIs:** Paginated and filtered retrieval by category, search keywords, and price/duration sorting.
- **Admin Service Controls:** Complete CRUD functionality: create service, update service metadata, toggle `status: "active" | "inactive"`, and delete service offerings.

### Smart Slot Scheduling and Conflict Resolution
- **Service-Scoped Availability:** Slot availability checks (`/api/appointments/booked-slots`) are scoped by specific `serviceId` and `appointmentDate`.
- **Duplicate Booking Prevention:** Requests attempting to book already reserved slots return an immediate `HTTP 409 Conflict`.
- **Cancellation Slot Recovery:** Cancelled appointments immediately free up that specific time slot for new bookings.
- **Admin Protection:** Admins are prohibited from booking appointments (`HTTP 403 Forbidden`).

### Stripe Checkout and Webhook Integration
- **Stripe Dynamic Checkout Sessions:** Creates authenticated Stripe Checkout sessions using modern Dynamic Payment Methods.
- **Verified Webhooks:** Listens to `checkout.session.completed` events using Stripe signature verification and raw buffer parsing to prevent forgery.
- **Immutable Financial Records:** Automatically persists transaction logs in the `transactions` collection (`stripeSessionId`, `amount`, `currency`, `appointmentId`, `customerId`). Records cannot be modified manually.

### Media Uploads and Profile Management
- **ImgBB Cloud Gateway:** Multipart form upload endpoint (`POST /api/upload`) using Multer to securely host images on ImgBB.
- **Profile Endpoint:** Safe updates for user name, profile photo, and phone number without exposing sensitive fields (role, blocked status).

---

## Technology Stack

- **Node.js:** JavaScript Runtime (ES Module syntax: `"type": "module"`)
- **Express.js:** Web Application & REST API Framework
- **MongoDB Node Driver 7.8:** Native Database Client for MongoDB Atlas
- **Stripe Node SDK 23.2:** Payment Gateway & Checkout Sessions
- **JSON Web Token (JWT):** Token Signing & Verification
- **Cookie-Parser:** HTTP Cookie Parsing
- **Multer:** Multipart Form Data & File Handling
- **Cors & Dotenv:** Cross-Origin Resource Sharing & Environment Configuration

---

## Installation Instructions

### Prerequisites
- **Node.js**: `v20.x` or higher
- **MongoDB Atlas**: Cluster URI with read/write database permissions
- **Stripe Account**: Sandbox API Secret Key and Webhook Secret
- **ImgBB Account**: API Key for image hosting

### 1. Clone the Repository
```bash
git clone https://github.com/mrrakib5007/salonbook-server.git
cd salonbook-server
```

### 2. Install Dependencies
```bash
npm install
```

---

## Required Environment Variables

Create a `.env` file in the root of the `server` directory.

| Variable Name | Description |
|---|---|
| `PORT` | Local server port (e.g. `5000`) |
| `MONGODB_URI` | MongoDB Atlas database connection string |
| `CLIENT_URL` | Frontend origin URL for CORS policy (e.g. `http://localhost:3000`) |
| `JWT_SECRET` | Secret key used for signing application JWT tokens |
| `ACCESS_TOKEN_SECRET` | Secret key for access token validation |
| `IMGBB_API_KEY` | API Key for ImgBB image upload hosting |
| `STRIPE_SECRET_KEY` | Stripe Sandbox Secret Key (`sk_test_...`) |
| `STRIPE_PUBLISHABLE_KEY` | Stripe Sandbox Publishable Key (`pk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | Stripe Webhook Signing Secret (`whsec_...`) |

---

## How to Run Locally

### Start Development Server (with Nodemon)
```bash
npm run dev
```
The server will start listening on [http://localhost:5000](http://localhost:5000).

### Start Production Server
```bash
npm start
```

---

## Key API Endpoints Reference

### Public Endpoints
- `GET /` - API Healthcheck
- `GET /api/services` - Query salon services with search, category filter, and sorting
- `GET /api/services/:id` - Single service details
- `GET /api/categories` - List all service categories
- `GET /api/appointments/booked-slots` - Check booked slots for a service on a given date

### Customer Endpoints (Authenticated)
- `POST /api/appointments` - Book an appointment slot
- `GET /api/customer/stats` - Customer dashboard summary metrics
- `GET /api/customer/appointments` - Customer's appointments list
- `PATCH /api/customer/appointments/:id/cancel` - Cancel pending appointment
- `POST /api/customer/create-checkout-session` - Generate Stripe Checkout Session
- `POST /api/customer/verify-payment` - Verify post-payment status
- `GET /api/user/profile` - Get authenticated profile
- `PATCH /api/user/profile` - Update name, image, phone

### Admin Endpoints (Admin Authenticated)
- `GET /api/admin/overview-stats` - Salon overview metrics
- `GET /api/admin/services` - All services list (active & inactive)
- `POST /api/admin/services` - Create new service
- `PATCH /api/admin/services/:id` - Update service details
- `PATCH /api/admin/services/:id/status` - Toggle service active/inactive
- `DELETE /api/admin/services/:id` - Delete service
- `GET /api/admin/appointments` - Salon bookings list
- `PATCH /api/admin/appointments/:id/status` - Confirm or cancel appointment
- `GET /api/admin/users` - Registered customers list
- `PATCH /api/admin/users/:id/block` - Block customer
- `PATCH /api/admin/users/:id/unblock` - Unblock customer
- `GET /api/admin/transactions` - Verified Stripe transactions audit log

### System Endpoints
- `POST /api/upload` - Upload image to ImgBB (Multipart form `image`)
- `POST /api/webhook/stripe` - Stripe webhook event handler (`raw` buffer)

---

## License

This project is licensed under the [MIT License](LICENSE).
