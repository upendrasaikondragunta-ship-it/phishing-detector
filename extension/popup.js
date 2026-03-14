document.addEventListener('DOMContentLoaded', function() {
  // UI Elements
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
  
  const demoModeToggle = document.getElementById('demo-mode-toggle');

  let activeUrl = "";
  let activeTabId = null;

  // 1. Initialize
  init();

  function init() {
    // Check if demo mode was previously toggled (save state in localStorage if needed)
    demoModeToggle.checked = localStorage.getItem('demoMode') === 'true';
    
    // Also save it to chrome storage so the background script can read it for auto-scans
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ demoMode: demoModeToggle.checked });
    }
    
    demoModeToggle.addEventListener('change', (e) => {
      localStorage.setItem('demoMode', e.target.checked);
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ demoMode: e.target.checked });
      }
      if(activeUrl) {
          startAnalysis(activeUrl); // re-analyze immediately
      }
    });

    retryBtn.addEventListener('click', () => {
      if(activeUrl) startAnalysis(activeUrl);
    });

    // Get the current active tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (tabs.length === 0) {
        showError("Could not detect active tab.");
        return;
      }

      activeUrl = tabs[0].url;
      activeTabId = tabs[0].id;
      currentUrlElement.textContent = activeUrl;
      
      // Ignore Chrome internal pages
      if (activeUrl.startsWith('chrome://') || activeUrl.startsWith('edge://') || activeUrl.startsWith('about:') || activeUrl.startsWith('file://')) {
        showInternalPageStatus();
        chrome.action.setBadgeText({ text: "SAFE", tabId: activeTabId });
        chrome.action.setBadgeBackgroundColor({ color: "#2ecc71", tabId: activeTabId });
        return;
      }

      startAnalysis(activeUrl);
    });
  }

  function startAnalysis(url) {
    // Reset UI state
    errorElement.classList.add('hidden');
    resultElement.classList.add('hidden');
    loadingElement.classList.remove('hidden');

    const isDemoMode = demoModeToggle.checked;

    // ** DEPLOYMENT UPDATE **
    // Change this URL to your live backend URL (e.g. Render, Railway)
    // Example: const API_URL = 'https://phishing-detector-api.onrender.com/predict';
    const API_URL = 'http://127.0.0.1:5000/predict';

    // Send the URL to the Flask Backend
    fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      // Pass demo mode configuration to the backend
      body: JSON.stringify({ url: url, demo_mode: isDemoMode })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Backend server error. Is Flask running?');
      }
      return response.json();
    })
    .then(data => {
      if (data.error) {
        throw new Error(data.error);
      }
      displayResults(data);
    })
    .catch(error => {
      if (error.message.includes('Failed to fetch')) {
        showError("Cannot connect to backend. Please ensure app.py is running on port 5000.");
      } else {
        showError(error.message);
      }
    });
  }

  function displayResults(data) {
    loadingElement.classList.add('hidden');
    resultElement.classList.remove('hidden');

    let badgeColor = "#2ecc71"; // Safe Green
    let badgeText = "SAFE";

    // 1. Status Badge & Icon
    statusText.textContent = data.status;
    
    if (data.status === "SAFE") {     // 0-30
      statusBadge.className = "badge safe";
      statusIcon.innerHTML = "✅";
      scoreBarFill.style.backgroundColor = "var(--safe-color)";
    } else if (data.status === "SUSPICIOUS") { // 30-60
      statusBadge.className = "badge suspicious";
      statusIcon.innerHTML = "⚠️";
      scoreBarFill.style.backgroundColor = "var(--warn-color)";
      badgeColor = "#f39c12"; // Yellow
      badgeText = "WARN";
    } else {                          // 60-100
      statusBadge.className = "badge phishing";
      statusIcon.innerHTML = "🚨";
      scoreBarFill.style.backgroundColor = "var(--danger-color)";
      badgeColor = "#e74c3c"; // Red
      badgeText = "DANGER";
    }
    
    // Update the tiny icon hovering over the chrome URL bar 
    if (activeTabId) {
        chrome.action.setBadgeText({ text: badgeText, tabId: activeTabId });
        chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: activeTabId });
    }

    // 2. Threat Score Animation
    animateScore(data.threat_score);

    // 3. Reasons
    reasonsList.innerHTML = ''; 
    if (data.reasons && data.reasons.length > 0) {
      data.reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        
        // Highlight critical terms
        if (reason.includes("CRITICAL")) {
            li.style.color = "var(--danger-color)";
            li.style.fontWeight = "bold";
        }
        
        reasonsList.appendChild(li);
      });
    } else {
      reasonsList.innerHTML = '<li>No security threats identified.</li>';
    }
  }

  function animateScore(targetScore) {
    let current = 0;
    threatScoreElement.textContent = "0";
    scoreBarFill.style.width = "0%";
    
    // Set final width immediately for CSS transition
    setTimeout(() => {
        scoreBarFill.style.width = `${targetScore}%`;
    }, 50);

    // Number counter animation
    const duration = 1000;
    const interval = 20;
    const steps = duration / interval;
    const stepValue = targetScore / steps;

    const counter = setInterval(() => {
      current += stepValue;
      if (current >= targetScore) {
        current = targetScore;
        clearInterval(counter);
      }
      threatScoreElement.textContent = Math.floor(current);
    }, interval);
  }

  function showInternalPageStatus() {
    loadingElement.classList.add('hidden');
    resultElement.classList.remove('hidden');
    
    statusText.textContent = "SAFE";
    statusBadge.className = "badge safe";
    statusIcon.innerHTML = "🛡️";
    threatScoreElement.textContent = "0";
    scoreBarFill.style.width = "0%";
    
    reasonsList.innerHTML = "<li>Browser internal protected page.</li>";
  }

  function showError(message) {
    loadingElement.classList.add('hidden');
    errorElement.classList.remove('hidden');
    errorMessageElement.textContent = message;
  }
});
