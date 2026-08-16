(() => {
  "use strict";

  // =========================================================
  // AI PHISHING DETECTOR - CONTENT SCRIPT
  // =========================================================

  // Trusted domains that should not receive an injected warning.
  // The backend/popup can still analyze these URLs normally.
  const TRUSTED_DOMAINS = [
    "github.com",
    "google.com",
    "google.co.in",
    "microsoft.com",
    "microsoftonline.com",
    "amazon.com",
    "amazon.in",
    "python.org",
    "apple.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "paypal.com",
    "netflix.com"
  ];

  const OVERLAY_ID = "ai-phishing-detector-warning-overlay";

  // =========================================================
  // DOMAIN HELPERS
  // =========================================================

  function getHostname() {
    try {
      return window.location.hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function isTrustedDomain(hostname) {
    if (!hostname) {
      return false;
    }

    return TRUSTED_DOMAINS.some(domain => {
      return (
        hostname === domain ||
        hostname.endsWith("." + domain)
      );
    });
  }

  // =========================================================
  // PROTECTED / INTERNAL PAGES
  // =========================================================

  function isBrowserInternalPage() {
    const protocol = window.location.protocol;

    return (
      protocol === "chrome:" ||
      protocol === "edge:" ||
      protocol === "about:" ||
      protocol === "file:"
    );
  }

  // =========================================================
  // PREVENT DUPLICATE OVERLAYS
  // =========================================================

  function overlayAlreadyExists() {
    return Boolean(
      document.getElementById(OVERLAY_ID)
    );
  }

  // =========================================================
  // REMOVE EXISTING OVERLAY
  // =========================================================

  function removeExistingOverlay() {
    const existing =
      document.getElementById(OVERLAY_ID);

    if (existing) {
      existing.remove();
    }
  }

  // =========================================================
  // CREATE WARNING OVERLAY
  // =========================================================

  function createWarningOverlay(data) {

    // Never create duplicate warnings.
    if (overlayAlreadyExists()) {
      return;
    }

    const overlay =
      document.createElement("div");

    overlay.id = OVERLAY_ID;

    const score =
      Number(data?.threat_score || 0);

    const status =
      data?.status || "PHISHING";

    const reasons =
      Array.isArray(data?.reasons)
        ? data.reasons
        : [];

    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.zIndex = "2147483647";
    overlay.style.background =
      "rgba(0, 0, 0, 0.72)";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.fontFamily =
      "Arial, sans-serif";

    const panel =
      document.createElement("div");

    panel.style.width = "min(760px, 90vw)";
    panel.style.maxHeight = "85vh";
    panel.style.overflowY = "auto";
    panel.style.background = "#ffffff";
    panel.style.borderRadius = "14px";
    panel.style.padding = "30px";
    panel.style.boxShadow =
      "0 20px 60px rgba(0,0,0,0.4)";
    panel.style.textAlign = "left";

    const title =
      document.createElement("h1");

    title.textContent =
      "🚨 PHISHING WEBSITE DETECTED 🚨";

    title.style.marginTop = "0";
    title.style.color = "#d93025";
    title.style.fontSize = "28px";

    const message =
      document.createElement("p");

    message.textContent =
      "This website has been flagged as potentially dangerous. Do not enter passwords, payment information, or other sensitive data.";

    message.style.fontSize = "18px";
    message.style.lineHeight = "1.6";

    const scoreBox =
      document.createElement("div");

    scoreBox.style.padding = "20px";
    scoreBox.style.margin =
      "20px 0";
    scoreBox.style.background =
      "#f5f5f5";
    scoreBox.style.borderRadius =
      "10px";

    const scoreTitle =
      document.createElement("strong");

    scoreTitle.textContent =
      `Threat Score: ${score}/100`;

    scoreTitle.style.fontSize =
      "24px";

    scoreBox.appendChild(scoreTitle);

    const reasonsTitle =
      document.createElement("h3");

    reasonsTitle.textContent =
      "Why was this flagged?";

    const reasonsList =
      document.createElement("ul");

    reasons.forEach(reason => {

      const li =
        document.createElement("li");

      li.textContent = reason;
      li.style.marginBottom = "8px";

      reasonsList.appendChild(li);
    });

    const leaveButton =
      document.createElement("button");

    leaveButton.textContent =
      "Leave This Site Immediately";

    leaveButton.style.width = "100%";
    leaveButton.style.padding = "15px";
    leaveButton.style.border = "none";
    leaveButton.style.borderRadius = "8px";
    leaveButton.style.background =
      "#d93025";
    leaveButton.style.color =
      "#ffffff";
    leaveButton.style.fontSize =
      "18px";
    leaveButton.style.fontWeight =
      "bold";
    leaveButton.style.cursor =
      "pointer";

    leaveButton.addEventListener(
      "click",
      () => {
        window.history.back();
      }
    );

    const continueButton =
      document.createElement("button");

    continueButton.textContent =
      "I understand the risks, continue anyway";

    continueButton.style.display =
      "block";
    continueButton.style.margin =
      "18px auto 0";
    continueButton.style.border =
      "none";
    continueButton.style.background =
      "transparent";
    continueButton.style.textDecoration =
      "underline";
    continueButton.style.cursor =
      "pointer";
    continueButton.style.fontSize =
      "15px";

    continueButton.addEventListener(
      "click",
      () => {
        removeExistingOverlay();
      }
    );

    panel.appendChild(title);
    panel.appendChild(message);
    panel.appendChild(scoreBox);
    panel.appendChild(reasonsTitle);
    panel.appendChild(reasonsList);
    panel.appendChild(leaveButton);
    panel.appendChild(continueButton);

    overlay.appendChild(panel);

    document.documentElement.appendChild(
      overlay
    );
  }

  // =========================================================
  // ANALYSIS MESSAGE FROM BACKGROUND SCRIPT
  // =========================================================

  chrome.runtime.onMessage.addListener(
    (message) => {

      if (!message) {
        return;
      }

      if (
        message.type !==
        "PHISHING_ANALYSIS_RESULT"
      ) {
        return;
      }

      const hostname =
        getHostname();

      // Trusted domains never receive
      // the content warning overlay.
      if (
        isTrustedDomain(hostname)
      ) {
        removeExistingOverlay();
        return;
      }

      const data =
        message.data || {};

      const score =
        Number(data.threat_score || 0);

      const status =
        data.status || "";

      // Only show the blocking warning
      // for genuinely dangerous results.
      if (
        status === "PHISHING" ||
        score >= 70
      ) {
        createWarningOverlay(data);
      }
    }
  );

  // =========================================================
  // INITIAL PAGE CHECK
  // =========================================================

  function initialize() {

    if (isBrowserInternalPage()) {
      return;
    }

    const hostname =
      getHostname();

    // IMPORTANT:
    // Trusted domains are ignored by the
    // content warning system.
    if (
      isTrustedDomain(hostname)
    ) {
      return;
    }

    // Do not perform automatic DOM-based
    // phishing detection here.
    //
    // The backend + popup/background
    // pipeline is responsible for analysis.
  }

  initialize();

})();