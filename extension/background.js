// background.js
// V3 - Phase 3 Upgrades: Auto-Scanning and Email Link Context Menus

const API_URL = "http://127.0.0.1:5000/predict";

// Create context menu for right-clicking links (e.g., in Gmail/Outlook)
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyze-phishing-link",
    title: "Analyze Link with AI Phishing Detector",
    contexts: ["link"] // Only show when right-clicking a hyperlink
  });
});

// Handle Context Menu (Right Click) Clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "analyze-phishing-link") {
    const linkUrl = info.linkUrl;
    scanUrlInBackground(linkUrl, true);
  }
});

// Auto-Scanner: Listen for when a user navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only scan once the page has fully loaded the URL
  if (changeInfo.status === 'complete' && tab.url) {
    // Ignore internal chrome pages and local network
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://') || tab.url.startsWith('file://')) {
      chrome.action.setBadgeText({ text: "SAFE", tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#2ecc71", tabId: tabId });
      return;
    }
    
    // Automatically scan the URL silently
    scanUrlInBackground(tab.url, false, tabId);
  }
});

/**
 * Scans a URL silently in the background
 * @param {string} url - The URL to analyze
 * @param {boolean} isExplicit - Did the user explicitly ask to scan this (e.g. via right click?)
 * @param {number} tabId - The ID of the tab (if auto-scanning)
 */
async function scanUrlInBackground(url, isExplicit = false, tabId = null) {
  try {
    // Determine if demo mode is on from storage
    const demoMode = await new Promise((resolve) => {
        chrome.storage.local.get(['demoMode'], function(result) {
            resolve(result.demoMode === true);
        });
    });

    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, demo_mode: demoMode })
    });

    if (!response.ok) throw new Error("Backend server down");
    
    const data = await response.json();
    if (data.error) throw new Error(data.error);

    handleScanResult(url, data, isExplicit, tabId);

  } catch (error) {
    console.error("AI Phishing Detector Error:", error);
    if (isExplicit) {
        showNotification("Error", "Could not reach the AI Backend (Is Flask running on port 5000?)");
    }
  }
}

/**
 * Processes the outcome of the backend scan
 */
function handleScanResult(url, data, isExplicit, tabId) {
    const status = data.status;
    const score = data.threat_score;
    
    // 1. Update the Extension icon Badge text (if tied to a specific tab)
    if (tabId) {
        let badgeColor = "#2ecc71"; // Safe Green
        let badgeText = "SAFE";
        
        if (status === "SUSPICIOUS") {
            badgeColor = "#f39c12"; // Yellow
            badgeText = "WARN";
        } else if (status === "PHISHING") {
            badgeColor = "#e74c3c"; // Red
            badgeText = "DANGER";
        }
        
        chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
    }

    // 2. Push Native Notifications
    
    // If the user right-clicked a link, ALWAYS show them a notification so they know it worked.
    if (isExplicit) {
        let title = "AI Link Analysis: " + status;
        let message = `Threat Score: ${score}/100.\nTarget: ${url}`;
        
        if (status === "PHISHING") {
            message = `🚨 DANGER! DO NOT CLICK THIS LINK! 🚨\n${message}`;
        }
        
        showNotification(`explicit-scan-${Date.now()}`, title, message);
    } 
    // Auto-scan in the background: Show clear notification for every page so the user knows it's working
    else {
       let icon = "✅";
       let actionMessage = "This page appears safe to browse.";
       
       if (status === "PHISHING") {
           icon = "🚨";
           actionMessage = "We recommend you close this tab immediately.";
       } else if (status === "SUSPICIOUS") {
           icon = "⚠️";
           actionMessage = "Proceed with caution.";
       }
       
       const title = `${icon} AI Scan: ${status}`;
       const message = `Threat Score: ${score}/100\n${actionMessage}\n\nURL: ${url}`;
       
       showNotification(`auto-scan-${Date.now()}`, title, message);
    }
}

/**
 * Displays a native Chrome OS Notification sliding in from the corner
 */
function showNotification(id, title, message) {
  chrome.notifications.create(id, {
    type: "basic",
    iconUrl: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAyNCAyNCcgd2lkdGg9JzQ4JyBoZWlnaHQ9JzQ4JyBmaWxsPSdjdXJyZW50Q29sb3InPjxwYXRoIGQ9J00xMiAxTDMgNXY2YzAgNS41NSAzLjg0IDEwLjc0IDkgMTIgNS4xNi0xLjI2IDktNi40NSA5LTEyVjVMMTIgMXptMCAxMC45OWg3Yy0uNTMgNC4xMi0zLjI4IDcuNzktNyA4Ljk0VjEySDVWNi4zbDctMy4xMXY4Ljh6Jy8+PC9zdmc+", // Simple shield icon
    title: title,
    message: message,
    priority: 2
  });
}
