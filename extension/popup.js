document.addEventListener('DOMContentLoaded', function () {

  // =========================================================
  // UI ELEMENTS
  // =========================================================

  const currentUrlElement = document.getElementById('current-url');
  const loadingElement = document.getElementById('loading');
  const resultElement = document.getElementById('result');

  const errorElement = document.getElementById('error');
  const errorMessageElement = document.getElementById('error-message');
  const retryBtn = document.getElementById('retry-btn');

  const statusBadge = document.getElementById('status-badge');
  const statusIcon = document.getElementById('status-icon');
  const statusText = document.getElementById('status-text');

  const threatScoreElement = document.getElementById('threat-score');
  const scoreBarFill = document.getElementById('score-bar-fill');

  const reasonsList = document.getElementById('reasons-list');

  const demoModeToggle =
    document.getElementById('demo-mode-toggle');


  // =========================================================
  // STATE
  // =========================================================

  let activeUrl = "";
  let activeTabId = null;


  // =========================================================
  // INITIALIZE
  // =========================================================

  init();


  function init() {

    // Restore Demo Mode
    demoModeToggle.checked =
      localStorage.getItem('demoMode') === 'true';


    // Save Demo Mode to Chrome storage
    if (chrome.storage && chrome.storage.local) {

      chrome.storage.local.set({
        demoMode: demoModeToggle.checked
      });

    }


    // Demo Mode change
    demoModeToggle.addEventListener(
      'change',
      function (event) {

        const enabled =
          event.target.checked;


        localStorage.setItem(
          'demoMode',
          enabled
        );


        if (
          chrome.storage &&
          chrome.storage.local
        ) {

          chrome.storage.local.set({
            demoMode: enabled
          });

        }


        if (activeUrl) {

          startAnalysis(activeUrl);

        }

      }
    );


    // Retry
    retryBtn.addEventListener(
      'click',
      function () {

        if (activeUrl) {

          startAnalysis(activeUrl);

        }

      }
    );


    // Get active tab
    chrome.tabs.query(
      {
        active: true,
        currentWindow: true
      },
      function (tabs) {

        if (
          !tabs ||
          tabs.length === 0
        ) {

          showError(
            "Could not detect active tab."
          );

          return;

        }


        activeUrl =
          tabs[0].url || "";


        activeTabId =
          tabs[0].id;


        currentUrlElement.textContent =
          activeUrl;


        // =====================================================
        // INTERNAL BROWSER PAGES
        // =====================================================

        if (
          activeUrl.startsWith("chrome://") ||
          activeUrl.startsWith("edge://") ||
          activeUrl.startsWith("about:") ||
          activeUrl.startsWith("file://")
        ) {

          showInternalPageStatus();

          setBadge(
            "SAFE",
            "#2ecc71"
          );

          return;

        }


        startAnalysis(activeUrl);

      }
    );

  }


  // =========================================================
  // START ANALYSIS
  // =========================================================

  function startAnalysis(url) {

    // Reset UI
    errorElement.classList.add('hidden');

    resultElement.classList.add('hidden');

    loadingElement.classList.remove('hidden');


    const isDemoMode =
      demoModeToggle.checked;


    // =========================================================
    // PRODUCTION FLASK BACKEND
    // =========================================================

    const API_URL =
      'https://phishing-detector-3o4g.onrender.com/predict';


    // =========================================================
    // SEND REQUEST
    // =========================================================

    fetch(
      API_URL,
      {
        method: 'POST',

        headers: {
          'Content-Type': 'application/json'
        },

        body: JSON.stringify({
          url: url,
          demo_mode: isDemoMode
        })
      }
    )


    // =========================================================
    // PROCESS RESPONSE
    // =========================================================

    .then(
      async function (response) {

        let data = {};


        // Try to read JSON regardless
        // of HTTP status code
        try {

          data = await response.json();

        }
        catch (error) {

          data = {};

        }


        // =====================================================
        // HTTP 400 - SECURITY BLOCK
        // =====================================================

        if (response.status === 400) {

          displayBlocked(
            data.reason ||
            data.error ||
            "URL rejected for security reasons."
          );

          return null;

        }


        // =====================================================
        // HTTP 429 - RATE LIMIT
        // =====================================================

        if (response.status === 429) {

          throw new Error(
            data.error ||
            "Too many requests. Please wait and try again."
          );

        }


        // =====================================================
        // OTHER SERVER ERRORS
        // =====================================================

        if (!response.ok) {

          throw new Error(
            data.error ||
            `Backend returned HTTP ${response.status}.`
          );

        }


        // =====================================================
        // APPLICATION ERROR
        // =====================================================

        if (data.error) {

          throw new Error(
            data.error
          );

        }


        return data;

      }
    )


    // =========================================================
    // DISPLAY RESULT
    // =========================================================

    .then(
      function (data) {

        // HTTP 400 already handled
        if (!data) {

          return;

        }


        displayResults(data);

      }
    )


    // =========================================================
    // ERROR HANDLING
    // =========================================================

    .catch(
      function (error) {

        console.error(
          "AI Phishing Detector Error:",
          error
        );


        if (
          error.message.includes(
            "Failed to fetch"
          )
        ) {

          showError(
            "Cannot connect to the phishing detection backend. Please try again."
          );

        }
        else {

          showError(
            error.message
          );

        }

      }
    );

  }


  // =========================================================
  // DISPLAY NORMAL RESULT
  // =========================================================

  function displayResults(data) {

    loadingElement.classList.add('hidden');

    resultElement.classList.remove('hidden');


    let badgeColor =
      "#2ecc71";

    let badgeText =
      "SAFE";


    // =========================================================
    // SAFE
    // =========================================================

    if (
      data.status === "SAFE"
    ) {

      statusBadge.className =
        "badge safe";

      statusIcon.innerHTML =
        "✅";

      statusText.textContent =
        "SAFE";

      scoreBarFill.style.backgroundColor =
        "var(--safe-color)";

      badgeColor =
        "#2ecc71";

      badgeText =
        "SAFE";

    }


    // =========================================================
    // SUSPICIOUS
    // =========================================================

    else if (
      data.status === "SUSPICIOUS"
    ) {

      statusBadge.className =
        "badge suspicious";

      statusIcon.innerHTML =
        "⚠️";

      statusText.textContent =
        "SUSPICIOUS";

      scoreBarFill.style.backgroundColor =
        "var(--warn-color)";

      badgeColor =
        "#f39c12";

      badgeText =
        "WARN";

    }


    // =========================================================
    // PHISHING
    // =========================================================

    else if (
      data.status === "PHISHING"
    ) {

      statusBadge.className =
        "badge phishing";

      statusIcon.innerHTML =
        "🚨";

      statusText.textContent =
        "PHISHING";

      scoreBarFill.style.backgroundColor =
        "var(--danger-color)";

      badgeColor =
        "#e74c3c";

      badgeText =
        "DANGER";

    }


    // =========================================================
    // UNKNOWN STATUS
    // =========================================================

    else {

      statusBadge.className =
        "badge suspicious";

      statusIcon.innerHTML =
        "⚠️";

      statusText.textContent =
        data.status ||
        "UNKNOWN";

      scoreBarFill.style.backgroundColor =
        "var(--warn-color)";

      badgeColor =
        "#f39c12";

      badgeText =
        "WARN";

    }


    // Update Chrome badge
    setBadge(
      badgeText,
      badgeColor
    );


    // =========================================================
    // THREAT SCORE
    // =========================================================

    const score =
      Number.isFinite(
        Number(data.threat_score)
      )
        ? Number(data.threat_score)
        : 0;


    animateScore(
      score
    );


    // =========================================================
    // REASONS
    // =========================================================

    displayReasons(
      data.reasons
    );

  }


  // =========================================================
  // DISPLAY BLOCKED RESPONSE
  // =========================================================

  function displayBlocked(reason) {

    loadingElement.classList.add('hidden');

    errorElement.classList.add('hidden');

    resultElement.classList.remove('hidden');


    // =========================================================
    // STATUS
    // =========================================================

    statusBadge.className =
      "badge phishing";


    statusIcon.innerHTML =
      "🛑";


    statusText.textContent =
      "BLOCKED";


    // =========================================================
    // SCORE
    // =========================================================

    threatScoreElement.textContent =
      "—";


    scoreBarFill.style.width =
      "0%";


    scoreBarFill.style.backgroundColor =
      "var(--danger-color)";


    // =========================================================
    // REASONS
    // =========================================================

    reasonsList.innerHTML =
      "";


    const reasonItem =
      document.createElement('li');


    reasonItem.textContent =
      reason;


    reasonItem.style.color =
      "var(--danger-color)";


    reasonItem.style.fontWeight =
      "bold";


    reasonsList.appendChild(
      reasonItem
    );


    const securityItem =
      document.createElement('li');


    securityItem.textContent =
      "Request blocked by backend security validation.";


    reasonsList.appendChild(
      securityItem
    );


    // =========================================================
    // CHROME BADGE
    // =========================================================

    setBadge(
      "BLOCK",
      "#e74c3c"
    );

  }


  // =========================================================
  // DISPLAY REASONS
  // =========================================================

  function displayReasons(reasons) {

    reasonsList.innerHTML =
      "";


    if (
      Array.isArray(reasons) &&
      reasons.length > 0
    ) {

      reasons.forEach(
        function (reason) {

          const li =
            document.createElement('li');


          li.textContent =
            reason;


          // Highlight CRITICAL messages
          if (
            String(reason)
              .toUpperCase()
              .includes("CRITICAL")
          ) {

            li.style.color =
              "var(--danger-color)";

            li.style.fontWeight =
              "bold";

          }


          reasonsList.appendChild(
            li
          );

        }
      );

    }
    else {

      reasonsList.innerHTML =
        "<li>No security threats identified.</li>";

    }

  }


  // =========================================================
  // SCORE ANIMATION
  // =========================================================

  function animateScore(targetScore) {

    targetScore =
      Math.max(
        0,
        Math.min(
          100,
          Number(targetScore) || 0
        )
      );


    let current = 0;


    threatScoreElement.textContent =
      "0";


    scoreBarFill.style.width =
      "0%";


    setTimeout(
      function () {

        scoreBarFill.style.width =
          `${targetScore}%`;

      },
      50
    );


    const duration =
      1000;


    const interval =
      20;


    const steps =
      duration / interval;


    const stepValue =
      targetScore / steps;


    const counter =
      setInterval(
        function () {

          current +=
            stepValue;


          if (
            current >= targetScore
          ) {

            current =
              targetScore;

            clearInterval(
              counter
            );

          }


          threatScoreElement.textContent =
            Math.floor(current);

        },
        interval
      );

  }


  // =========================================================
  // INTERNAL PAGE STATUS
  // =========================================================

  function showInternalPageStatus() {

    loadingElement.classList.add('hidden');

    resultElement.classList.remove('hidden');


    statusText.textContent =
      "SAFE";


    statusBadge.className =
      "badge safe";


    statusIcon.innerHTML =
      "🛡️";


    threatScoreElement.textContent =
      "0";


    scoreBarFill.style.width =
      "0%";


    scoreBarFill.style.backgroundColor =
      "var(--safe-color)";


    reasonsList.innerHTML =
      "<li>Browser internal protected page.</li>";

  }


  // =========================================================
  // CHROME EXTENSION BADGE
  // =========================================================

  function setBadge(text, color) {

    if (
      activeTabId === null ||
      activeTabId === undefined
    ) {

      return;

    }


    chrome.action.setBadgeText(
      {
        text: text,
        tabId: activeTabId
      }
    );


    chrome.action.setBadgeBackgroundColor(
      {
        color: color,
        tabId: activeTabId
      }
    );

  }


  // =========================================================
  // ERROR UI
  // =========================================================

  function showError(message) {

    loadingElement.classList.add('hidden');

    resultElement.classList.add('hidden');

    errorElement.classList.remove('hidden');


    errorMessageElement.textContent =
      message;


    setBadge(
      "ERR",
      "#7f8c8d"
    );

  }

});