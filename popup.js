const inputBox = document.getElementById("userInput");
const checkButton = document.getElementById("checkButton");
const resultBox = document.getElementById("result");
const riskTitle = document.getElementById("riskTitle");
const riskPercent = document.getElementById("riskPercent");
const confidencePercent = document.getElementById("confidencePercent");
const reasonList = document.getElementById("reasonList");

chrome.storage.local.get(["selectedTextToCheck"], (data) => {
  if (data.selectedTextToCheck) {
    inputBox.value = data.selectedTextToCheck;

    chrome.storage.local.remove("selectedTextToCheck");
  }
});

checkButton.addEventListener("click", () => {
  const input = inputBox.value.trim();

  if (!input) {
    showResult("No Input", 0, 0, ["Please paste or type something to check."], "medium");
    return;
  }

  const analysis = analyzeInput(input);
  showResult(
    analysis.label,
    analysis.risk,
    analysis.confidence,
    analysis.reasons,
    analysis.level
  );
});

function analyzeInput(input) {
  let risk = 0;
  let confidence = 30;
  const reasons = [];

  const type = detectInputType(input);

  if (type === "url") {
    const result = analyzeUrl(input);
    risk += result.risk;
    confidence += result.confidence;
    reasons.push(...result.reasons);
  } else if (type === "email") {
    const result = analyzeEmail(input);
    risk += result.risk;
    confidence += result.confidence;
    reasons.push(...result.reasons);
  } else if (type === "phone") {
    const result = analyzePhone(input);
    risk += result.risk;
    confidence += result.confidence;
    reasons.push(...result.reasons);
  } else {
    const result = analyzeText(input);
    risk += result.risk;
    confidence += result.confidence;
    reasons.push(...result.reasons);
  }

  const textResult = analyzeText(input);
  risk += Math.floor(textResult.risk / 2);

  for (const reason of textResult.reasons) {
    if (!reasons.includes(reason)) {
      reasons.push(reason);
    }
  }

  risk = Math.min(risk, 100);
  confidence = Math.min(confidence, 95);

  if (reasons.length === 0) {
    reasons.push("No major scam indicators were found.");
  }

  if (risk >= 70) {
    return {
      label: "High Scam Risk",
      level: "high",
      risk,
      confidence,
      reasons
    };
  }

  if (risk >= 35) {
    return {
      label: "Suspicious",
      level: "medium",
      risk,
      confidence,
      reasons
    };
  }

  return {
    label: "Low Scam Risk",
    level: "low",
    risk,
    confidence,
    reasons
  };
}

function detectInputType(input) {
  const trimmed = input.trim();

  if (/^https?:\/\//i.test(trimmed) || /^[a-z0-9.-]+\.[a-z]{2,}/i.test(trimmed)) {
    return "url";
  }

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return "email";
  }

  if (/^\+?[\d\s().-]{7,}$/.test(trimmed)) {
    return "phone";
  }

  return "text";
}

function analyzeUrl(input) {
  let risk = 0;
  let confidence = 35;
  const reasons = [];

  let urlText = input.trim();

  if (!/^https?:\/\//i.test(urlText)) {
    urlText = "https://" + urlText;
  }

  try {
    const url = new URL(urlText);
    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();
    const parts = hostname.split(".");
    const mainDomain = parts.slice(-2).join(".");

    confidence += 25;

    if (url.protocol === "http:") {
      risk += 20;
      reasons.push("The link does not use HTTPS.");
    }

    if (hostname.length > 35) {
      risk += 15;
      reasons.push("The domain name is unusually long.");
    }

    if (fullUrl.length > 90) {
      risk += 15;
      reasons.push("The full URL is unusually long.");
    }

    if ((hostname.match(/-/g) || []).length >= 3) {
      risk += 15;
      reasons.push("The domain contains many hyphens.");
    }

    if ((hostname.match(/\./g) || []).length >= 3) {
      risk += 15;
      reasons.push("The domain has many subdomains, which can hide the real website.");
    }

    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      risk += 25;
      reasons.push("The link uses an IP address instead of a normal domain.");
    }

    if (fullUrl.includes("@")) {
      risk += 25;
      reasons.push("The URL contains an @ symbol, which can hide the real destination.");
    }

    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"];
    if (shorteners.includes(hostname)) {
      risk += 25;
      reasons.push("The link uses a URL shortener, which can hide the real destination.");
    }

    const suspiciousTlds = [".xyz", ".top", ".click", ".work", ".zip", ".mov", ".country", ".stream", ".gq", ".tk"];
    for (const tld of suspiciousTlds) {
      if (hostname.endsWith(tld)) {
        risk += 18;
        reasons.push("The domain uses a commonly abused domain ending: " + tld);
      }
    }

    const suspiciousWords = [
      "verify", "urgent", "login", "claim", "prize", "gift", "free",
      "winner", "account", "security", "update", "wallet", "crypto",
      "password", "bank", "support", "limited"
    ];

    for (const word of suspiciousWords) {
      if (fullUrl.includes(word)) {
        risk += 8;
        reasons.push('The link contains the suspicious word "' + word + '".');
      }
    }

    const brandChecks = [
      { brand: "paypal", official: "paypal.com" },
      { brand: "amazon", official: "amazon.com" },
      { brand: "apple", official: "apple.com" },
      { brand: "microsoft", official: "microsoft.com" },
      { brand: "google", official: "google.com" },
      { brand: "netflix", official: "netflix.com" },
      { brand: "instagram", official: "instagram.com" },
      { brand: "facebook", official: "facebook.com" },
      { brand: "whatsapp", official: "whatsapp.com" }
    ];

    for (const item of brandChecks) {
      if (hostname.includes(item.brand) && mainDomain !== item.official) {
        risk += 35;
        reasons.push("The domain mentions " + item.brand + " but is not the official " + item.official + " domain.");
      }
    }

    if (/login|verify|secure|account|update/.test(hostname) && parts.length > 3) {
      risk += 15;
      reasons.push("The domain combines account-related words with multiple subdomains.");
    }
  } catch {
    risk += 35;
    confidence += 10;
    reasons.push("The link format appears invalid or unusual.");
  }

  return { risk, confidence, reasons };
}

function analyzeEmail(input) {
  let risk = 0;
  let confidence = 25;
  const reasons = [];

  const lower = input.toLowerCase();
  const domain = lower.split("@")[1] || "";

  if (!domain.includes(".")) {
    risk += 25;
    reasons.push("The email domain looks incomplete.");
  }

  const freeDomains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"];
  const officialWords = ["support", "security", "bank", "paypal", "amazon", "apple"];

  for (const word of officialWords) {
    if (lower.includes(word) && freeDomains.includes(domain)) {
      risk += 20;
      reasons.push("The email uses official-sounding words with a free email provider.");
    }
  }

  if (lower.includes("noreply") && freeDomains.includes(domain)) {
    risk += 20;
    reasons.push("The email uses 'noreply' with a free email provider.");
  }

  return { risk, confidence, reasons };
}

function analyzePhone(input) {
  let risk = 0;
  let confidence = 20;
  const reasons = [];

  const digits = input.replace(/\D/g, "");

  if (digits.length < 7) {
    risk += 25;
    reasons.push("The phone number is too short to be reliable.");
  }

  if (digits.length > 15) {
    risk += 20;
    reasons.push("The phone number is unusually long.");
  }

  if (/(\d)\1{5,}/.test(digits)) {
    risk += 15;
    reasons.push("The number contains repeated digits, which can be suspicious.");
  }

  return { risk, confidence, reasons };
}

function analyzeText(input) {
  let risk = 0;
  let confidence = 20;
  const reasons = [];

  const text = input.toLowerCase();

  const scamPhrases = [
    "urgent",
    "act now",
    "verify your account",
    "password",
    "otp",
    "one time password",
    "gift card",
    "you won",
    "winner",
    "claim your prize",
    "bank account",
    "credit card",
    "crypto",
    "investment",
    "delivery fee",
    "customs fee",
    "remote access",
    "click the link",
    "limited time"
  ];

  for (const phrase of scamPhrases) {
    if (text.includes(phrase)) {
      risk += 10;
      reasons.push('The message contains a scam-related phrase: "' + phrase + '".');
    }
  }

  if (/(http:\/\/|https:\/\/|www\.)/i.test(input)) {
    risk += 10;
    reasons.push("The message contains a link.");
  }

  if (/[A-Z]{8,}/.test(input)) {
    risk += 10;
    reasons.push("The message contains a lot of capital letters.");
  }

  if ((input.match(/!/g) || []).length >= 3) {
    risk += 10;
    reasons.push("The message uses repeated exclamation marks.");
  }

  return { risk, confidence, reasons };
}

function showResult(label, risk, confidence, reasons, level) {
  resultBox.className = "result " + level;
  resultBox.classList.remove("hidden");

  riskTitle.textContent = label;
  riskPercent.textContent = "Scam risk: " + risk + "%";
  confidencePercent.textContent = "Confidence in this result: " + confidence + "%";

  reasonList.innerHTML = "";

  for (const reason of reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonList.appendChild(li);
  }
}