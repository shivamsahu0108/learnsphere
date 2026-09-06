const express = require("express");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command
} = require("@aws-sdk/client-s3");

dotenv.config();

// ==================================================
// CLOUDFLARE R2 CONFIGURATION
// ==================================================

const hasR2Config = Boolean(
  process.env.R2_ACCOUNT_ID &&
  process.env.R2_ACCESS_KEY_ID &&
  process.env.R2_SECRET_ACCESS_KEY &&
  process.env.R2_BUCKET_NAME
);

const r2Client = hasR2Config
  ? new S3Client({
      region: "auto",
      endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
      }
    })
  : null;

const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || "";

if (!hasR2Config) {
  console.warn(
    "WARNING: Cloudflare R2 settings are incomplete. Media streaming and downloads will be disabled until configured."
  );
}

const app = express();

app.disable("x-powered-by");

// Set TRUST_PROXY=1 when production traffic reaches Node through one trusted reverse proxy.
const trustProxyValue = String(process.env.TRUST_PROXY || "0").trim();
if (trustProxyValue === "1") {
  app.set("trust proxy", 1);
}

// Lightweight security headers that do not interfere with the current inline HTML/JS design.
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  next();
});

const PORT = process.env.PORT || 5000;


// ==================================================
// MIDDLEWARE & CORS
// ==================================================

const configuredOrigins = (process.env.ALLOWED_ORIGINS ||
  "https://thelearnsphere.in,https://www.thelearnsphere.in,http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000,http://127.0.0.1:3000")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(
  cors((req, callback) => {
    const origin = req.header("Origin");
    const forwardedHost = req.header("x-forwarded-host");
    const rawHost = forwardedHost ? forwardedHost.split(",")[0].trim() : req.get("host");
    const hostWithoutPort = rawHost ? rawHost.split(":")[0] : "";

    // Non-browser requests (curl, server-to-server, health checks)
    if (!origin) {
      return callback(null, { origin: true });
    }

    // Configured allowed origins or wildcard
    if (configuredOrigins.includes(origin) || configuredOrigins.includes("*")) {
      return callback(null, {
        origin: true,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: false
      });
    }

    // Dynamic same-origin detection (e.g. deployed domain matches incoming origin host)
    try {
      const originUrl = new URL(origin);
      if (
        (rawHost && (originUrl.host === rawHost || originUrl.hostname === hostWithoutPort)) ||
        originUrl.hostname === "localhost" ||
        originUrl.hostname === "127.0.0.1"
      ) {
        return callback(null, {
          origin: true,
          methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
          allowedHeaders: ["Content-Type", "Authorization"],
          credentials: false
        });
      }
    } catch {
      // Invalid URL format
    }

    return callback(new Error("Origin is not allowed by CORS."));
  })
);

app.use(
  express.json({
    limit: "100kb"
  })
);


// ==================================================
// SIMPLE IN-MEMORY RATE LIMITING
// ==================================================

function createRateLimiter({ windowMs, max, message }) {
  const attempts = new Map();

  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of attempts) {
      if (entry.resetAt <= now) {
        attempts.delete(key);
      }
    }
  }, Math.min(windowMs, 60_000));

  cleanup.unref?.();

  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    let entry = attempts.get(key);

    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      attempts.set(key, entry);
    }

    entry.count += 1;

    if (entry.count > max) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader("Retry-After", retryAfter);
      return res.status(429).json({
        success: false,
        message
      });
    }

    next();
  };
}

const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many authentication attempts. Please try again later."
});

const enquiryRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many enquiries from this connection. Please try again later."
});

const adminSetupRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many admin setup attempts. Please try again later."
});

const mediaUrlRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: "Too many media access requests. Please try again later."
});


// ==================================================
// MONGODB CONNECTION
// ==================================================

let databaseReady = false;

mongoose.connection.on("connected", () => {
  databaseReady = true;
  console.log("MongoDB connected successfully");
});

mongoose.connection.on("disconnected", () => {
  databaseReady = false;
  console.error("MongoDB disconnected.");
});

mongoose.connection.on("error", error => {
  databaseReady = false;
  console.error("MongoDB connection error:", error.message);
});


// ==================================================
// USER SCHEMA
// ==================================================

const userSchema = new mongoose.Schema(
  {
    identifier: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true
    },

    passwordHash: {
      type: String,
      required: true
    },

    role: {
      type: String,
      enum: [
        "user",
        "admin"
      ],
      default: "user"
    },

    courseAccess: {
      pmp: {
        type: Boolean,
        default: false
      }
    }
  },

  {
    timestamps: true
  }
);


const User = mongoose.model(
  "User",
  userSchema
);


// ==================================================
// PMP PROGRESS SCHEMA
// ==================================================

const pmpProgressSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

        ref: "User",

        required: true,

        unique: true,

        index: true
      },

      videos: {
        type: [Number],
        default: []
      },

      pdfs: {
        type: [Number],
        default: []
      },

      exams: {
        type: [Number],
        default: []
      }
    },

    {
      timestamps: true
    }
  );


const PmpProgress =
  mongoose.model(
    "PmpProgress",
    pmpProgressSchema
  );


// ==================================================
// JWT TOKEN
// ==================================================

function createToken(user) {

  return jwt.sign(
    {
      userId:
        user._id.toString(),

      identifier:
        user.identifier,

      role:
        user.role
    },

    process.env.JWT_SECRET,

    {
      expiresIn: "7d"
    }
  );
}


// ==================================================
// NORMAL AUTHENTICATION
// ==================================================

function authenticateToken(
  req,
  res,
  next
) {

  const authHeader =
    req.headers.authorization;


  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ")
  ) {

    return res.status(401).json({
      success: false,
      message:
        "Authentication required."
    });

  }


  const token =
    authHeader.split(" ")[1];


  try {

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );


    req.user =
      decoded;


    next();

  } catch (error) {

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired authentication token."
    });

  }

}


// ==================================================
// PMP ACCESS MIDDLEWARE
// ==================================================

async function requirePmpAccess(
  req,
  res,
  next
) {

  try {

    const user =
      await User.findById(
        req.user.userId
      ).select("_id identifier role courseAccess");


    if (!user) {

      return res.status(404).json({
        success: false,
        message:
          "User not found."
      });

    }


    if (
      !user.courseAccess ||
      user.courseAccess.pmp !== true
    ) {

      return res.status(403).json({
        success: false,
        message:
          "You do not have access to the PMP course."
      });

    }


    req.userRecord =
      user;


    next();

  } catch (error) {

    console.error(
      "PMP authorization error:",
      error
    );


    return res.status(500).json({
      success: false,
      message:
        "Server error while checking course access."
    });

  }

}


// ==================================================
// ADMIN MIDDLEWARE
// ==================================================

async function requireAdmin(
  req,
  res,
  next
) {

  try {

    const user =
      await User.findById(
        req.user.userId
      ).select("_id identifier role courseAccess");


    if (!user) {

      return res.status(404).json({
        success: false,
        message:
          "User not found."
      });

    }


    if (
      user.role !== "admin"
    ) {

      return res.status(403).json({
        success: false,
        message:
          "Admin access required."
      });

    }


    req.userRecord =
      user;


    next();

  } catch (error) {

    console.error(
      "Admin authorization error:",
      error
    );


    return res.status(500).json({
      success: false,
      message:
        "Server error while checking admin access."
    });

  }

}


// ==================================================
// HEALTH CHECKS
// ==================================================

// Lightweight liveness probe for cloud load balancers / containers (Render, Railway, Docker, K8s)
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/healthz", (req, res) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString()
  });
});

// Comprehensive readiness & diagnostics probe
app.get(
  "/api/health",
  (req, res) => {

    const healthy = databaseReady;

    res.status(healthy ? 200 : 503).json({
      success: healthy,
      status: healthy ? "ok" : "degraded",
      message: healthy
        ? "Learnsphere backend is running."
        : "Learnsphere backend is running, but the database is unavailable.",
      database: healthy ? "connected" : "disconnected",
      r2Configured: Boolean(
        hasR2Config
      ),
      emailConfigured: Boolean(
        process.env.EMAIL_USER &&
        process.env.EMAIL_PASS &&
        process.env.RECEIVER_EMAIL
      )
    });

  }
);

// ==================================================
// CLOUDFLARE R2 CONNECTION TEST
// ==================================================

app.get(
  "/api/r2-test",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    if (!r2Client) {
      return res.status(503).json({
        success: false,
        message: "Cloudflare R2 is not configured on this server."
      });
    }

    try {

      const command =
        new ListObjectsV2Command({
          Bucket: R2_BUCKET_NAME,
          MaxKeys: 10
        });

      const result =
        await r2Client.send(command);

      return res.json({

        success: true,

        message:
          "Cloudflare R2 connection is working.",

        bucket:
          R2_BUCKET_NAME,

        objectCount:
          result.KeyCount || 0

      });

    } catch (error) {

      console.error(
        "R2 connection test error:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Could not connect to Cloudflare R2.",

        error:
          error.message

      });

    }

  }
);

// ==================================================
// PROTECTED TEST
// ==================================================

app.get(
  "/api/protected-test",

  authenticateToken,

  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.user.userId
        ).select(
          "-passwordHash"
        );


      if (!user) {

        return res.status(404).json({
          success: false,
          message:
            "User not found."
        });

      }


      return res.json({

        success: true,

        message:
          "You are authenticated.",

        user: {

          identifier:
            user.identifier,

          role:
            user.role,

          courseAccess:
            user.courseAccess

        }

      });

    } catch (error) {

      console.error(
        "Protected route error:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Server error."
      });

    }

  }
);


// ==================================================
// PMP ACCESS TEST
// ==================================================

app.get(
  "/api/pmp-test",

  authenticateToken,

  requirePmpAccess,

  async (req, res) => {

    return res.json({

      success: true,

      message:
        "PMP course access granted.",

      user: {

        identifier:
          req.userRecord.identifier,

        role:
          req.userRecord.role,

        courseAccess:
          req.userRecord.courseAccess

      }

    });

  }
);


// ==================================================
// PMP LECTURES
// ==================================================

const PMP_LECTURES = [

  {
    id: "pmp-lecture-1",
    number: 1,
    title: "PMP Exam Introduction and Overview",
    description:
      "Introduction and overview of the PMP examination.",
    filename:
      "pmp-exam-introduction-and-overview.mp4"
  },

  {
    id: "pmp-lecture-2",
    number: 2,
    title: "PMP Exam Passing Score & PMP Exam Report",
    description:
      "Understanding the PMP passing score and exam report.",
    filename:
      "pmp-exam-passing-score-and-exam-report.mp4"
  },

  {
    id: "pmp-lecture-3",
    number: 3,
    title: "The PMP Exam Content Outline",
    description:
      "Understanding the PMP Exam Content Outline.",
    filename:
      "pmp-exam-content-outline.mp4"
  },

  {
    id: "pmp-lecture-4",
    number: 4,
    title: "The PMBOK Guide - Overview",
    description:
      "Overview of the PMBOK Guide.",
    filename:
      "pmbok-guide-overview.mp4"
  },

  {
    id: "pmp-lecture-5",
    number: 5,
    title: "The PMBOK Guide - Principles 1",
    description:
      "PMBOK principles.",
    filename:
      "pmbok-guide-principles-1.mp4"
  },

  {
    id: "pmp-lecture-6",
    number: 6,
    title: "The PMBOK Guide - Principles 2",
    description:
      "PMBOK principles.",
    filename:
      "pmbok-guide-principles-2.mp4"
  },

  {
    id: "pmp-lecture-7",
    number: 7,
    title: "The PMBOK Guide - Principles 3",
    description:
      "PMBOK principles.",
    filename:
      "pmbok-guide-principles-3.mp4"
  },

  {
    id: "pmp-lecture-8",
    number: 8,
    title: "The PMBOK Guide - Performance",
    description:
      "PMBOK performance concepts.",
    filename:
      "pmbok-guide-performance.mp4"
  },

  {
    id: "pmp-lecture-9",
    number: 9,
    title: "The PMBOK Guide - Performance Domains",
    description:
      "PMBOK performance domains.",
    filename:
      "pmbok-guide-performance-domains.mp4"
  },

  {
    id: "pmp-lecture-10",
    number: 10,
    title: "The Agile Manifesto",
    description:
      "Introduction to the Agile Manifesto.",
    filename:
      "agile-manifesto.mp4"
  },

  {
    id: "pmp-lecture-11",
    number: 11,
    title: "PMP Exam Mindset Part 1",
    description:
      "PMP and PMI mindset.",
    filename:
      "pmp-exam-mindset-part-1.mp4"
  },

  {
    id: "pmp-lecture-12",
    number: 12,
    title: "PMP Exam Mindset Part 2",
    description:
      "Agile mindset.",
    filename:
      "pmp-exam-mindset-part-2.mp4"
  },

  {
    id: "pmp-lecture-13",
    number: 13,
    title: "PMP Exam Mindset Part 3",
    description:
      "Exam-taking mindset.",
    filename:
      "pmp-exam-mindset-part-3-exam-taking.mp4"
  },

  {
    id: "pmp-lecture-14",
    number: 14,
    title: "Certification Renewal and PDUs",
    description:
      "Certification renewal and PDUs.",
    filename:
      "certification-renewal-and-pdus.mp4"
  },

  {
    id: "pmp-lecture-15",
    number: 15,
    title: "PMP Exam Lessons Learned - Dana Domnisor",
    description:
      "PMP exam lessons learned.",
    filename:
      "pmp-exam-lessons-learned-dana-domnisor.mp4"
  },

  {
    id: "pmp-lecture-16",
    number: 16,
    title: "PMP Exam Lessons Learned - Sudip Roy",
    description:
      "PMP exam lessons learned.",
    filename:
      "pmp-exam-lessons-learned-sudip-roy.mp4"
  }

];


const PMP_PDFS = [
  "Agile Practice Guide.pdf",
  "PMBOK 6th edition.pdf",
  "PMBOK-7 infographic_A1_en.pdf",
  "PMBOK - 7.pdf",
  "PMP_Notes_Mapping_Prep2ECO.pdf"
];

const MEDIA_URL_EXPIRES_SECONDS = Math.min(
  Math.max(Number(process.env.MEDIA_URL_EXPIRES_SECONDS || 7200), 300),
  43_200
);

// ==================================================
// TEMPORARY R2 MEDIA URL
// ==================================================
// The backend authenticates the learner once and returns a short-lived,
// object-specific R2 URL. Large video/PDF bytes then travel directly
// between the learner and R2 instead of consuming Node.js bandwidth,
// memory and connections.
// ==================================================

app.get(
  "/api/pmp/media-url",
  mediaUrlRateLimiter,
  authenticateToken,
  requirePmpAccess,
  async (req, res) => {
    if (!r2Client) {
      return res.status(503).json({
        success: false,
        message: "Cloudflare R2 media storage is not configured on this server."
      });
    }

    try {
      const type = typeof req.query.type === "string"
        ? req.query.type
        : "";
      const filename = typeof req.query.filename === "string"
        ? req.query.filename
        : "";

      let objectKey = null;
      let contentType = null;

      if (type === "video") {
        const lecture = PMP_LECTURES.find(
          item => item.filename === filename
        );

        if (!lecture) {
          return res.status(404).json({
            success: false,
            message: "Video not found."
          });
        }

        objectKey = lecture.filename;
        contentType = "video/mp4";
      } else if (type === "pdf") {
        if (!PMP_PDFS.includes(filename)) {
          return res.status(404).json({
            success: false,
            message: "PDF not found."
          });
        }

        objectKey = filename;
        contentType = "application/pdf";
      } else {
        return res.status(400).json({
          success: false,
          message: "Invalid media type."
        });
      }

      const command = new GetObjectCommand({
        Bucket: R2_BUCKET_NAME,
        Key: objectKey,
        ResponseContentType: contentType,
        ResponseContentDisposition: "inline"
      });

      const url = await getSignedUrl(
        r2Client,
        command,
        { expiresIn: MEDIA_URL_EXPIRES_SECONDS }
      );

      return res.json({
        success: true,
        url,
        expiresIn: MEDIA_URL_EXPIRES_SECONDS,
        filename: objectKey
      });
    } catch (error) {
      console.error("PMP media URL error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Could not prepare the protected course media."
      });
    }
  }
);

// ==================================================
// GET PMP LECTURES
// ==================================================

app.get(
  "/api/pmp/lectures",

  authenticateToken,

  requirePmpAccess,

  async (req, res) => {

    return res.json({

      success: true,

      lectures:
        PMP_LECTURES.map(
          lecture => ({
            id: lecture.id,
            number: lecture.number,
            title: lecture.title,
            description:
              lecture.description
          })
        )

    });

  }
);


// ==================================================
// VIDEO AUTHENTICATION
// ==================================================

function authenticateVideoToken(
  req,
  res,
  next
) {

  let token = null;


  // ------------------------------------------
  // Authorization header
  // ------------------------------------------

  const authHeader =
    req.headers.authorization;


  if (
    authHeader &&
    authHeader.startsWith("Bearer ")
  ) {

    token =
      authHeader.split(" ")[1];

  }


  // ------------------------------------------
  // Query token
  // ------------------------------------------

  if (
    !token &&
    req.query.token
  ) {

    token =
      req.query.token;

  }


  // ------------------------------------------
  // No token
  // ------------------------------------------

  if (!token) {

    return res.status(401).json({

      success: false,

      message:
        "Authentication required."

    });

  }


  // ------------------------------------------
  // Verify token
  // ------------------------------------------

  try {

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );


    req.user =
      decoded;


    next();

  } catch (error) {

    console.error(
      "Video authentication error:",
      error.message
    );


    return res.status(401).json({

      success: false,

      message:
        "Invalid or expired authentication token."

    });

  }

}

// ==================================================
// PROTECTED PMP VIDEO FROM CLOUDFLARE R2
// ==================================================

app.get(

  "/api/pmp/video/:filename",

  authenticateVideoToken,

  requirePmpAccess,

  async (req, res) => {

    if (!r2Client) {
      return res.status(503).json({
        success: false,
        message: "Cloudflare R2 media storage is not configured on this server."
      });
    }

    try {

      // ------------------------------------------
      // Find requested lecture
      // ------------------------------------------

      const lecture =
        PMP_LECTURES.find(
          item =>
            item.filename ===
            req.params.filename
        );


      if (!lecture) {

        return res.status(404).json({

          success: false,

          message:
            "Video not found."

        });

      }


      const filename =
        lecture.filename;


      // ------------------------------------------
      // R2 object information
      // ------------------------------------------

      let headResult;

      try {

        headResult =
          await r2Client.send(

            new HeadObjectCommand({

              Bucket:
                R2_BUCKET_NAME,

              Key:
                filename

            })

          );

      } catch (error) {

        console.error(
          "R2 video not found:",
          filename,
          error.message
        );

        return res.status(404).json({

          success: false,

          message:
            "Video file does not exist in Cloudflare R2."

        });

      }


      const fileSize =
        Number(
          headResult.ContentLength || 0
        );


      const contentType =
        headResult.ContentType ||
        "video/mp4";


      if (!fileSize) {

        return res.status(404).json({

          success: false,

          message:
            "Video file is empty or unavailable."

        });

      }


      // ------------------------------------------
      // Browser Range request
      // ------------------------------------------

      const range =
        req.headers.range;


      // ------------------------------------------
      // No Range request
      // ------------------------------------------

      if (!range) {

        const command =
          new GetObjectCommand({

            Bucket:
              R2_BUCKET_NAME,

            Key:
              filename

          });


        const result =
          await r2Client.send(
            command
          );


        res.writeHead(

          200,

          {

            "Content-Length":
              fileSize,

            "Content-Type":
              contentType,

            "Accept-Ranges":
              "bytes",

            "Cache-Control":
              "private, no-store",

            "Content-Disposition":
              "inline"

          }

        );


        result.Body.on(
          "error",
          error => {

            console.error(
              "R2 video stream error:",
              error
            );

            if (
              !res.headersSent
            ) {

              res.status(500).end();

            } else {

              res.destroy();

            }

          }
        );


        req.on(
          "close",
          () => {

            if (
              result.Body &&
              typeof result.Body.destroy ===
                "function"
            ) {

              result.Body.destroy();

            }

          }
        );


        return result.Body.pipe(
          res
        );

      }


      // ------------------------------------------
      // Validate Range header
      // ------------------------------------------

      if (
        !range.startsWith("bytes=")
      ) {

        res.writeHead(

          416,

          {

            "Content-Range":
              `bytes */${fileSize}`

          }

        );

        return res.end();

      }


      const rangeParts =
        range
          .replace(
            "bytes=",
            ""
          )
          .split("-");


      let start =
        parseInt(
          rangeParts[0],
          10
        );


      let end =
        rangeParts[1]
          ? parseInt(
              rangeParts[1],
              10
            )
          : fileSize - 1;


      // ------------------------------------------
      // Suffix range
      // ------------------------------------------

      if (
        Number.isNaN(start) &&
        !Number.isNaN(end)
      ) {

        start =
          Math.max(
            fileSize - end,
            0
          );

        end =
          fileSize - 1;

      }


      // ------------------------------------------
      // Normalize end
      // ------------------------------------------

      if (
        end >= fileSize
      ) {

        end =
          fileSize - 1;

      }


      // ------------------------------------------
      // Validate range
      // ------------------------------------------

      if (

        Number.isNaN(start) ||

        Number.isNaN(end) ||

        start < 0 ||

        end < 0 ||

        start >= fileSize ||

        start > end

      ) {

        res.writeHead(

          416,

          {

            "Content-Range":
              `bytes */${fileSize}`

          }

        );

        return res.end();

      }


      // ------------------------------------------
      // Requested chunk size
      // ------------------------------------------

      const chunkSize =
        end - start + 1;


      // ------------------------------------------
      // Get requested range from R2
      // ------------------------------------------

      const command =
        new GetObjectCommand({

          Bucket:
            R2_BUCKET_NAME,

          Key:
            filename,

          Range:
            `bytes=${start}-${end}`

        });


      const result =
        await r2Client.send(
          command
        );


      // ------------------------------------------
      // Partial response
      // ------------------------------------------

      res.writeHead(

        206,

        {

          "Content-Range":
            `bytes ${start}-${end}/${fileSize}`,

          "Accept-Ranges":
            "bytes",

          "Content-Length":
            chunkSize,

          "Content-Type":
            contentType,

          "Cache-Control":
            "private, no-store",

          "Content-Disposition":
            "inline"

        }

      );


      // ------------------------------------------
      // Handle R2 stream errors
      // ------------------------------------------

      result.Body.on(
        "error",
        error => {

          console.error(
            "R2 range video stream error:",
            error
          );

          if (
            !res.headersSent
          ) {

            res.status(500).end();

          } else {

            res.destroy();

          }

        }
      );


      // ------------------------------------------
      // Stop R2 stream if browser disconnects
      // ------------------------------------------

      req.on(
        "close",
        () => {

          if (
            result.Body &&
            typeof result.Body.destroy ===
              "function"
          ) {

            result.Body.destroy();

          }

        }
      );


      return result.Body.pipe(
        res
      );


    } catch (error) {

      console.error(
        "Protected R2 video streaming error:",
        error
      );


      if (
        !res.headersSent
      ) {

        return res.status(500).json({

          success: false,

          message:
            "Could not stream the video."

        });

      }


      res.destroy();

    }

  }

);

// --------------------------------------------------
// PMP COURSE - PROTECTED PDF STREAM
// --------------------------------------------------

/*
  PDFs are stored in Cloudflare R2 with
  Public Access Disabled.

  The browser does NOT receive the R2
  credentials.

  User authentication:
      JWT token

  Course authorization:
      MongoDB courseAccess.pmp === true

  The PDF is then streamed through
  this backend route.
*/

app.get(
  "/api/pmp/pdf/:filename",
  authenticateVideoToken,
  requirePmpAccess,
  async (req, res) => {

    if (!r2Client) {
      return res.status(503).json({
        success: false,
        message: "Cloudflare R2 media storage is not configured on this server."
      });
    }

    try {

      // ------------------------------------------------
      // ONLY THESE 5 PDF FILES ARE ALLOWED
      // ------------------------------------------------

      const allowedPDFs = {

        "Agile Practice Guide.pdf":
          "Agile Practice Guide.pdf",

        "PMBOK 6th edition.pdf":
          "PMBOK 6th edition.pdf",

        "PMBOK-7 infographic_A1_en.pdf":
          "PMBOK-7 infographic_A1_en.pdf",

        "PMBOK - 7.pdf":
          "PMBOK - 7.pdf",

        "PMP_Notes_Mapping_Prep2ECO.pdf":
          "PMP_Notes_Mapping_Prep2ECO.pdf"
      };


      const filename =
        allowedPDFs[req.params.filename];


      // ------------------------------------------------
      // BLOCK UNKNOWN FILES
      // ------------------------------------------------

      if (!filename) {

        return res.status(404).json({

          success: false,

          message: "PDF not found."
        });
      }


      // ------------------------------------------------
      // R2 OBJECT KEY
      // ------------------------------------------------

      const objectKey =
        filename;


      // ------------------------------------------------
      // GET PDF INFORMATION FROM R2
      // ------------------------------------------------

      const headCommand =
        new HeadObjectCommand({

          Bucket:
            R2_BUCKET_NAME,

          Key:
            objectKey
        });


      const metadata =
        await r2Client.send(
          headCommand
        );


      const totalSize =
        Number(
          metadata.ContentLength || 0
        );


      const contentType =
        metadata.ContentType ||
        "application/pdf";


      // ------------------------------------------------
      // PRIVATE RESPONSE HEADERS
      // ------------------------------------------------

      res.setHeader(
        "Content-Type",
        contentType
      );

      res.setHeader(
        "Accept-Ranges",
        "bytes"
      );

      res.setHeader(
        "Cache-Control",
        "private, no-store"
      );

      res.setHeader(
        "Content-Disposition",
        `inline; filename="${filename.replace(/"/g, "")}"`
      );


      // ------------------------------------------------
      // CHECK RANGE REQUEST
      // ------------------------------------------------

      const range =
        req.headers.range;


      // ------------------------------------------------
      // NO RANGE
      // ------------------------------------------------

      if (!range) {

        const getCommand =
          new GetObjectCommand({

            Bucket:
              R2_BUCKET_NAME,

            Key:
              objectKey
          });


        const result =
          await r2Client.send(
            getCommand
          );


        res.status(200);


        res.setHeader(
          "Content-Length",
          totalSize
        );


        if (result.ContentType) {

          res.setHeader(
            "Content-Type",
            result.ContentType
          );
        }


        result.Body.pipe(res);


        req.on(
          "close",
          () => {

            if (
              result.Body &&
              typeof result.Body.destroy === "function"
            ) {

              result.Body.destroy();
            }
          }
        );


        return;
      }


      // ------------------------------------------------
      // PARSE RANGE
      // ------------------------------------------------

      const match =
        range.match(
          /^bytes=(\d*)-(\d*)$/
        );


      if (!match) {

        return res.status(416).setHeader(
          "Content-Range",
          `bytes */${totalSize}`
        ).end();
      }


      let start =
        match[1] === ""
          ? null
          : Number(match[1]);


      let end =
        match[2] === ""
          ? null
          : Number(match[2]);


      // ------------------------------------------------
      // SUFFIX RANGE
      // Example:
      // bytes=-500
      // ------------------------------------------------

      if (start === null) {

        const suffixLength =
          end;


        if (
          !Number.isInteger(
            suffixLength
          ) ||
          suffixLength <= 0
        ) {

          return res.status(416).setHeader(
            "Content-Range",
            `bytes */${totalSize}`
          ).end();
        }


        start =
          Math.max(
            totalSize -
            suffixLength,
            0
          );


        end =
          totalSize - 1;
      }


      // ------------------------------------------------
      // OPEN-ENDED RANGE
      // Example:
      // bytes=1000-
      // ------------------------------------------------

      if (end === null) {

        end =
          totalSize - 1;
      }


      // ------------------------------------------------
      // VALIDATE RANGE
      // ------------------------------------------------

      if (
        !Number.isInteger(start) ||
        !Number.isInteger(end) ||
        start < 0 ||
        end < start ||
        start >= totalSize
      ) {

        return res.status(416).setHeader(
          "Content-Range",
          `bytes */${totalSize}`
        ).end();
      }


      end =
        Math.min(
          end,
          totalSize - 1
        );


      const contentLength =
        end - start + 1;


      // ------------------------------------------------
      // GET RANGE FROM R2
      // ------------------------------------------------

      const getCommand =
        new GetObjectCommand({

          Bucket:
            R2_BUCKET_NAME,

          Key:
            objectKey,

          Range:
            `bytes=${start}-${end}`
        });


      const result =
        await r2Client.send(
          getCommand
        );


      // ------------------------------------------------
      // RANGE RESPONSE
      // ------------------------------------------------

      res.status(206);


      res.setHeader(
        "Content-Range",
        `bytes ${start}-${end}/${totalSize}`
      );


      res.setHeader(
        "Content-Length",
        contentLength
      );


      if (result.ContentType) {

        res.setHeader(
          "Content-Type",
          result.ContentType
        );
      }


      result.Body.pipe(res);


      req.on(
        "close",
        () => {

          if (
            result.Body &&
            typeof result.Body.destroy === "function"
          ) {

            result.Body.destroy();
          }
        }
      );

    } catch (error) {

      console.error(
        "Protected PMP PDF error:",
        error
      );


      if (
        error.name ===
        "NotFound" ||
        error.name ===
        "NoSuchKey"
      ) {

        return res.status(404).json({

          success: false,

          message:
            "PDF does not exist in Cloudflare R2."
        });
      }


      return res.status(500).json({

        success: false,

        message:
          "Could not load the PMP PDF."
      });
    }
  }
);

// ==================================================
// GET PMP PROGRESS
// ==================================================

app.get(

  "/api/pmp-progress",

  authenticateToken,

  requirePmpAccess,

  async (req, res) => {

    try {

      let progress =
        await PmpProgress.findOne({

          userId:
            req.user.userId

        }).lean();


      if (!progress) {

        progress = {

          videos: [],

          pdfs: [],

          exams: []

        };

      }


      return res.json({

        success: true,

        progress: {

          videos:
            Array.isArray(
              progress.videos
            )
              ? progress.videos
              : [],

          pdfs:
            Array.isArray(
              progress.pdfs
            )
              ? progress.pdfs
              : [],

          exams:
            Array.isArray(
              progress.exams
            )
              ? progress.exams
              : []

        }

      });

    } catch (error) {

      console.error(
        "Get PMP progress error:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Could not load PMP course progress."

      });

    }

  }

);


// ==================================================
// SAVE / UPDATE PMP PROGRESS
// ==================================================

app.put(

  "/api/pmp-progress",

  authenticateToken,

  requirePmpAccess,

  async (req, res) => {

    try {

      const {
        itemType,
        index
      } = req.body;


      const allowedTypes = {

        video: {
          field: "videos",
          min: 0,
          max: 15
        },

        pdf: {
          field: "pdfs",
          min: 0,
          max: 4
        },

        exam: {
          field: "exams",
          min: 1,
          max: 2
        }

      };


      const config =
        allowedTypes[itemType];


      if (!config) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid progress item type."

        });

      }


      if (
        !Number.isInteger(index) ||
        index < config.min ||
        index > config.max
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid progress item index."

        });

      }


      const progress =
        await PmpProgress.findOneAndUpdate(

          {
            userId:
              req.user.userId
          },

          {

            $setOnInsert: {

              userId:
                req.user.userId

            },

            $addToSet: {

              [config.field]:
                index

            }

          },

          {

  returnDocument: "after",

  upsert: true,

  setDefaultsOnInsert: true

}

        ).lean();


      return res.json({

        success: true,

        message:
          "PMP progress updated.",

        progress: {

          videos:
            progress.videos || [],

          pdfs:
            progress.pdfs || [],

          exams:
            progress.exams || []

        }

      });

    } catch (error) {

      console.error(
        "Update PMP progress error:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Could not update PMP progress."

      });

    }

  }

);


// ==================================================
// ADMIN TEST
// ==================================================

app.get(

  "/api/admin-test",

  authenticateToken,

  requireAdmin,

  async (req, res) => {

    return res.json({

      success: true,

      message:
        "Admin access granted.",

      user: {

        identifier:
          req.userRecord.identifier,

        role:
          req.userRecord.role

      }

    });

  }

);


// ==================================================
// ADMIN - GET ALL USERS
// ==================================================

app.get(

  "/api/admin/users",

  authenticateToken,

  requireAdmin,

  async (req, res) => {

    try {

      const users =
        await User.find()

          .select(
            "-passwordHash"
          )

          .sort({
            createdAt:
              -1
          });


      return res.json({

        success: true,

        users

      });

    } catch (error) {

      console.error(
        "Get users error:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Could not retrieve users."

      });

    }

  }

);


// ==================================================
// ADMIN - GRANT / REVOKE PMP ACCESS
// ==================================================

app.put(

  "/api/admin/users/:userId/pmp",

  authenticateToken,

  requireAdmin,

  async (req, res) => {

    try {

      const {
        userId
      } = req.params;


      const {
        allowed
      } = req.body;


      if (
        typeof allowed !==
        "boolean"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "The 'allowed' value must be true or false."

        });

      }


      const user =
        await User.findById(
          userId
        );


      if (!user) {

        return res.status(404).json({

          success: false,

          message:
            "User not found."

        });

      }


      user.courseAccess.pmp =
        allowed;


      await user.save();


      return res.json({

        success: true,

        message:

          allowed

            ? "PMP access granted successfully."

            : "PMP access revoked successfully.",

        user: {

          id:
            user._id,

          identifier:
            user.identifier,

          role:
            user.role,

          courseAccess:
            user.courseAccess

        }

      });

    } catch (error) {

      console.error(
        "PMP access update error:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Could not update PMP access."

      });

    }

  }

);

// ============================================================
// ADMIN: DELETE USER ACCOUNT
// ============================================================

app.delete(
  "/api/admin/users/:userId",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Validate MongoDB ObjectId
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID."
        });
      }

      // Admin cannot delete their own account
      if (userId === req.user.userId) {
        return res.status(400).json({
          success: false,
          message: "You cannot delete your own administrator account."
        });
      }

      // Find the user
      const user = await User.findById(userId)
        .select("_id identifier role");

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found."
        });
      }

      // Do not allow deleting another admin account
      if (user.role === "admin") {
        return res.status(403).json({
          success: false,
          message:
            "Administrator accounts cannot be deleted from this dashboard."
        });
      }

      // Delete the user's PMP progress first
      await PmpProgress.deleteOne({
        userId: user._id
      });

      // Delete the user account
      await User.deleteOne({
        _id: user._id
      });

      return res.json({
        success: true,
        message: "User account deleted successfully.",
        user: {
          id: user._id,
          identifier: user.identifier
        }
      });

    } catch (error) {

      console.error("Delete user error:", error);

      return res.status(500).json({
        success: false,
        message: "Could not delete the user account."
      });

    }
  }
);

// ==================================================
// VALIDATION
// ==================================================

function isEmail(
  value
) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(value);

}


function isValidMobile(
  value
) {

  if (typeof value !== "string") {
    return false;
  }

  const trimmed = value.trim();
  const digits = trimmed.replace(/\D/g, "");

  // Allow common international formatting, but require a real digit count.
  return (
    /^[+0-9()\s.-]+$/.test(trimmed) &&
    digits.length >= 7 &&
    digits.length <= 15
  );

}


function validateIdentifier(
  identifier
) {

  return (
    isEmail(identifier) ||
    isValidMobile(identifier)
  );

}


// ==================================================
// EMAIL TRANSPORTER
// ==================================================

const transporter =
  nodemailer.createTransport({

    service: "gmail",

    pool: true,
    maxConnections: 3,
    maxMessages: 100,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 60_000,

    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }

  });


// ==================================================
// EMAIL CONFIGURATION CHECK
// ==================================================

if (

  !process.env.EMAIL_USER ||

  !process.env.EMAIL_PASS ||

  !process.env.RECEIVER_EMAIL

) {

  console.warn(

    "WARNING: Email settings are incomplete. Check your .env file."

  );

}


// ==================================================
// SEND EMAIL
// ==================================================

async function sendNotificationEmail({
  subject,
  html
}) {

  try {

    await transporter.sendMail({

      from:
        `"Learnsphere Website" <${process.env.EMAIL_USER}>`,

      to:
        process.env.RECEIVER_EMAIL,

      subject,

      html

    });


    console.log(
      "Email notification sent:",
      subject
    );


    return true;

  } catch (error) {

    console.error(
      "Email sending error:",
      error.message
    );


    return false;

  }

}


// ==================================================
// REGISTER USER
// ==================================================

app.post(

  "/api/register",

  authRateLimiter,

  async (req, res) => {

    try {

      const {
        identifier,
        password
      } = req.body;


      const cleanIdentifier =

        typeof identifier ===
        "string"

          ? identifier
              .trim()
              .toLowerCase()

          : "";


      if (
        !cleanIdentifier ||
        !password
      ) {

        return res.status(400).json({

          message:
            "Email/mobile number and password are required."

        });

      }


      if (
        !validateIdentifier(
          cleanIdentifier
        )
      ) {

        return res.status(400).json({

          message:
            "Please enter a valid email address or mobile number."

        });

      }


      if (
        password.length < 8
      ) {

        return res.status(400).json({

          message:
            "Password must contain at least 8 characters."

        });

      }


      const existingUser =
        await User.findOne({

          identifier:
            cleanIdentifier

        });


      if (existingUser) {

        return res.status(409).json({

          message:
            "An account already exists with this email or mobile number."

        });

      }


      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      const newUser =
        await User.create({

          identifier:
            cleanIdentifier,

          passwordHash,

          role:
            "user",

          courseAccess: {

            pmp:
              false

          }

        });


      void sendNotificationEmail({

        subject:
          "New Learnsphere User Registration",

        html: `

          <div
            style="
              font-family:Arial,sans-serif;
              line-height:1.6
            "
          >

            <h2>
              New Learnsphere User Registration
            </h2>

            <p>
              A new user created an account.
            </p>

            <p>
              <strong>Email / Mobile:</strong>
              ${escapeHtml(
                cleanIdentifier
              )}
            </p>

            <p>
              <strong>Time:</strong>
              ${escapeHtml(
                new Date().toLocaleString()
              )}
            </p>

            <p>
              The user's password was not included.
            </p>

          </div>

        `

      });


      const token = createToken(newUser);

      return res.status(201).json({

        success: true,

        message:
          "Account created successfully.",

        token,

        user: {

          identifier:
            newUser.identifier,

          role:
            newUser.role,

          courseAccess: {
            pmp: false
          }

        }

      });

    } catch (error) {

      console.error(
        "Registration error:",
        error
      );


      if (
        error.code === 11000
      ) {

        return res.status(409).json({

          message:
            "An account already exists with this email or mobile number."

        });

      }


      return res.status(500).json({

        message:
          "Could not create account. Please try again."

      });

    }

  }

);


// ==================================================
// LOGIN USER
// ==================================================

app.post(

  "/api/login",

  authRateLimiter,

  async (req, res) => {

    try {

      const {
        identifier,
        password
      } = req.body;


      const cleanIdentifier =

        typeof identifier ===
        "string"

          ? identifier
              .trim()
              .toLowerCase()

          : "";


      if (
        !cleanIdentifier ||
        !password
      ) {

        return res.status(400).json({

          message:
            "Email/mobile number and password are required."

        });

      }


      const user =
        await User.findOne({

          identifier:
            cleanIdentifier

        });


      if (!user) {

        return res.status(401).json({

          message:
            "Invalid email/mobile number or password."

        });

      }


      const passwordMatches =
        await bcrypt.compare(

          password,

          user.passwordHash

        );


      if (!passwordMatches) {

        return res.status(401).json({

          message:
            "Invalid email/mobile number or password."

        });

      }


      const token =
        createToken(
          user
        );


      void sendNotificationEmail({

        subject:
          "Learnsphere User Login",

        html: `

          <div
            style="
              font-family:Arial,sans-serif;
              line-height:1.6
            "
          >

            <h2>
              Learnsphere User Login
            </h2>

            <p>
              A user successfully logged in.
            </p>

            <p>
              <strong>Email / Mobile:</strong>
              ${escapeHtml(
                cleanIdentifier
              )}
            </p>

            <p>
              <strong>Time:</strong>
              ${escapeHtml(
                new Date().toLocaleString()
              )}
            </p>

          </div>

        `

      });


      return res.json({

        success: true,

        message:
          "Login successful.",

        token,

        user: {

          identifier:
            user.identifier,

          role:
            user.role,

          courseAccess: {

            pmp:
              user.courseAccess?.pmp ||
              false

          }

        }

      });

    } catch (error) {

      console.error(
        "Login error:",
        error
      );


      return res.status(500).json({

        message:
          "Login failed. Please try again."

      });

    }

  }

);


// ==================================================
// ENQUIRY
// ==================================================

app.post(

  "/api/enquiry",

  enquiryRateLimiter,

  async (req, res) => {

    try {

      const {
        name,
        email,
        mobile,
        interest
      } = req.body;


      const cleanName =
        typeof name === "string"
          ? name.trim()
          : "";


      const cleanEmail =
        typeof email === "string"
          ? email.trim().toLowerCase()
          : "";


      const cleanMobile =
        typeof mobile === "string"
          ? mobile.trim()
          : "";


      const cleanInterest =
        typeof interest === "string"
          ? interest.trim()
          : "";


      if (

        !cleanName ||

        !cleanEmail ||

        !cleanMobile ||

        !cleanInterest

      ) {

        return res.status(400).json({

          message:
            "Please fill in all enquiry fields."

        });

      }


      if (
        !isEmail(
          cleanEmail
        )
      ) {

        return res.status(400).json({

          message:
            "Please enter a valid email address."

        });

      }


      if (
        !isValidMobile(
          cleanMobile
        )
      ) {

        return res.status(400).json({

          message:
            "Please enter a valid mobile number."

        });

      }


      const emailSent =
        await sendNotificationEmail({

          subject:
            `New Learnsphere Enquiry - ${cleanInterest}`,

          html: `

            <div
              style="
                font-family:Arial,sans-serif;
                line-height:1.7
              "
            >

              <h2>
                New Learnsphere Enquiry
              </h2>

              <p>
                A visitor submitted a new enquiry.
              </p>

              <p>
                <strong>Name:</strong>
                ${escapeHtml(cleanName)}
              </p>

              <p>
                <strong>Email:</strong>
                ${escapeHtml(cleanEmail)}
              </p>

              <p>
                <strong>Mobile:</strong>
                ${escapeHtml(cleanMobile)}
              </p>

              <p>
                <strong>Interested Field:</strong>
                ${escapeHtml(cleanInterest)}
              </p>

              <p>
                <strong>Submitted At:</strong>
                ${escapeHtml(
                  new Date().toLocaleString()
                )}
              </p>

            </div>

          `

        });


      if (!emailSent) {

        return res.status(500).json({

          message:
            "The enquiry could not be delivered by email. Please check the server email settings."

        });

      }


      return res.json({

        success: true,

        message:
          "Your enquiry has been sent successfully."

      });

    } catch (error) {

      console.error(
        "Enquiry error:",
        error
      );


      return res.status(500).json({

        message:
          "Could not send your enquiry. Please try again."

      });

    }

  }

);


// ==================================================
// ONE-TIME ADMIN SETUP
// ==================================================

app.post(

  "/api/setup-admin",

  adminSetupRateLimiter,

  async (req, res) => {

    if (process.env.ENABLE_ADMIN_SETUP !== "true") {
      return res.status(404).json({
        success: false,
        message: "Not found."
      });
    }

    try {

      const {
        setupSecret,
        identifier,
        password
      } = req.body;


      if (

        !setupSecret ||

        setupSecret !==
          process.env.ADMIN_SETUP_SECRET

      ) {

        return res.status(403).json({

          success: false,

          message:
            "Invalid admin setup secret."

        });

      }


      if (
        !identifier ||
        !password
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Admin email/mobile and password are required."

        });

      }


      const cleanIdentifier =
        identifier
          .trim()
          .toLowerCase();


      if (
        !validateIdentifier(
          cleanIdentifier
        )
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Please enter a valid email address or mobile number."

        });

      }


      if (
        password.length < 8
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Admin password must contain at least 8 characters."

        });

      }


      let user =
        await User.findOne({

          identifier:
            cleanIdentifier

        });


      if (user) {

        user.role =
          "admin";

        await user.save();

      } else {

        const passwordHash =
          await bcrypt.hash(
            password,
            12
          );


        user =
          await User.create({

            identifier:
              cleanIdentifier,

            passwordHash,

            role:
              "admin",

            courseAccess: {

              pmp:
                false

            }

          });

      }


      return res.json({

        success: true,

        message:
          "Admin account created successfully.",

        user: {

          identifier:
            user.identifier,

          role:
            user.role

        }

      });

    } catch (error) {

      console.error(
        "Admin setup error:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Could not create admin account."

      });

    }

  }

);


// ==================================================
// HTML ESCAPE HELPER
// ==================================================

function escapeHtml(
  value
) {

  return String(value)

    .replace(
      /&/g,
      "&amp;"
    )

    .replace(
      /</g,
      "&lt;"
    )

    .replace(
      />/g,
      "&gt;"
    )

    .replace(
      /"/g,
      "&quot;"
    )

    .replace(
      /'/g,
      "&#039;"
    );

}


// ==================================================
// FRONTEND STATIC ROUTING & SECURE PAGE SERVING
// ==================================================

const publicPages = {
  "/": "index.html",
  "/index": "index.html",
  "/index.html": "index.html",
  "/courses": "courses.html",
  "/courses.html": "courses.html",
  "/pmp-details": "pmp-details.html",
  "/pmp-details.html": "pmp-details.html",
  "/admin": "admin.html",
  "/admin.html": "admin.html"
};

for (const [routePath, fileName] of Object.entries(publicPages)) {
  app.get(routePath, (req, res) => {
    res.sendFile(path.join(__dirname, fileName));
  });
}

// Favicon handler
app.get("/favicon.ico", (req, res) => {
  res.status(204).end();
});

// Explicit 404 for unhandled API endpoints
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: `API endpoint ${req.method} ${req.originalUrl} not found.`
  });
});

// Explicit 404 for unhandled web routes (safely blocks direct access to .env, server.js, package.json, etc.)
app.use((req, res, next) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return next();
  }

  res.status(404).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - Page Not Found | Learnsphere</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #0f172a; color: #f8fafc; text-align: center; }
    .box { max-width: 480px; padding: 32px; }
    h1 { font-size: 5rem; margin: 0; color: #6366f1; font-weight: 800; }
    h2 { margin: 8px 0 16px; font-size: 1.5rem; }
    p { color: #94a3b8; font-size: 1.05rem; line-height: 1.6; margin-bottom: 24px; }
    a { display: inline-block; padding: 12px 28px; background: #4f46e5; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; transition: background .2s ease; }
    a:hover { background: #4338ca; }
  </style>
</head>
<body>
  <div class="box">
    <h1>404</h1>
    <h2>Page Not Found</h2>
    <p>The page or resource you are looking for does not exist or has been moved.</p>
    <a href="/">Return to Home</a>
  </div>
</body>
</html>`);
});


// ==================================================
// GLOBAL ERROR HANDLER
// ==================================================

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  const isCorsError =
    error &&
    error.message === "Origin is not allowed by CORS.";

  return res.status(isCorsError ? 403 : 500).json({
    success: false,
    message: isCorsError
      ? "Request origin is not allowed."
      : "An unexpected server error occurred."
  });
});


// ==================================================
// START SERVER
// ==================================================

const requiredEnvironment = [
  "MONGO_URI",
  "JWT_SECRET"
];

const optionalR2Environment = [
  "R2_ACCOUNT_ID",
  "R2_ACCESS_KEY_ID",
  "R2_SECRET_ACCESS_KEY",
  "R2_BUCKET_NAME"
];

function validateEnvironment() {
  const missing = requiredEnvironment.filter(
    key => !process.env[key] || !String(process.env[key]).trim()
  );

  if (missing.length) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`
    );
  }

  const missingR2 = optionalR2Environment.filter(
    key => !process.env[key] || !String(process.env[key]).trim()
  );

  if (missingR2.length) {
    console.warn(
      `WARNING: Cloudflare R2 variables not set: ${missingR2.join(", ")}. Media streaming features will be disabled.`
    );
  }

  if (String(process.env.JWT_SECRET).length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters long.");
  }

  if (process.env.ENABLE_ADMIN_SETUP === "true" && !process.env.ADMIN_SETUP_SECRET) {
    throw new Error(
      "ADMIN_SETUP_SECRET is required when ENABLE_ADMIN_SETUP=true."
    );
  }
}

async function startServer() {
  try {
    validateEnvironment();

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.RECEIVER_EMAIL) {
      console.warn(
        "WARNING: Email settings are incomplete. Login/registration can still work, but email notifications will not be delivered."
      );
    }

    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10_000,
      connectTimeoutMS: 10_000,
      maxPoolSize: Math.max(Number(process.env.MONGO_MAX_POOL_SIZE || 50), 5),
      minPoolSize: Math.max(Number(process.env.MONGO_MIN_POOL_SIZE || 5), 0),
      maxConnecting: Math.max(Number(process.env.MONGO_MAX_CONNECTING || 2), 1),
      waitQueueTimeoutMS: Math.max(Number(process.env.MONGO_WAIT_QUEUE_TIMEOUT_MS || 5_000), 1),
      maxIdleTimeMS: Math.max(Number(process.env.MONGO_MAX_IDLE_TIME_MS || 60_000), 0)
    });

    databaseReady = true;

    const server = app.listen(PORT, () => {
      console.log("");
      console.log("==========================================");
      console.log("Learnsphere backend is running!");
      console.log(`Server: http://localhost:${PORT}`);
      console.log(`Health: http://localhost:${PORT}/api/health`);
      console.log("MongoDB: connected");
      console.log("==========================================");
    });

    const shutdown = async signal => {
      console.log(`\nLearnsphere shutting down (${signal})...`);

      server.close(async () => {
        try {
          await mongoose.connection.close(false);
        } catch (error) {
          console.error("MongoDB shutdown error:", error.message);
        }

        try {
          transporter.close();
        } catch (error) {
          console.error("Email transporter shutdown error:", error.message);
        }

        process.exit(0);
      });

      setTimeout(() => process.exit(1), 15_000).unref();
    };

    process.once("SIGTERM", () => void shutdown("SIGTERM"));
    process.once("SIGINT", () => void shutdown("SIGINT"));
  } catch (error) {
    databaseReady = false;
    console.error("Learnsphere startup failed:", error.message);
    process.exit(1);
  }
}

startServer();
