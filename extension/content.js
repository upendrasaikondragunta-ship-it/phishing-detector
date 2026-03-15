// content.js
// Injected into web pages to show a large warning if the site is dangerous

// Listen for messages from background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "show_warning") {
        createWarningBanner(request.data);
    }
});

function createWarningBanner(data) {
    // Check if banner already exists
    if (document.getElementById("phishing-detector-warning-banner")) {
        return;
    }

    const { status, threat_score, reasons } = data;

    // Only show for dangerous or suspicious
    if (status === "SAFE") return;

    // Create the overlay container
    const overlay = document.createElement("div");
    overlay.id = "phishing-detector-warning-banner";
    
    // Choose styling based on status
    const isPhishing = status === "PHISHING";
    const bgColor = isPhishing ? "#e74c3c" : "#f39c12";
    const titleText = isPhishing ? "🚨 DANGER: PHISHING WEBSITE DETECTED 🚨" : "⚠️ WARNING: SUSPICIOUS WEBSITE DEVELOPED ⚠️";
    const subText = isPhishing 
        ? "This website has been flagged as highly dangerous. We strongly recommend you DO NOT enter any personal information or passwords."
        : "This website exhibits suspicious characteristics. Please proceed with caution.";

    // Format reasons as list
    const reasonsHtml = reasons ? reasons.map(r => `<li>${r}</li>`).join('') : "";

    // Set inner HTML for the banner
    overlay.innerHTML = `
        <div class="phishing-banner-content">
            <h1 class="phishing-banner-title">${titleText}</h1>
            <p class="phishing-banner-subtitle">${subText}</p>
            
            <div class="phishing-banner-details">
                <div class="phishing-score-box">
                    <span class="score-label">Threat Score</span>
                    <span class="score-value">${threat_score}<span class="score-max">/100</span></span>
                </div>
                <div class="phishing-reasons-box">
                    <strong>Why was this flagged?</strong>
                    <ul>${reasonsHtml}</ul>
                </div>
            </div>

            <div class="phishing-banner-actions">
                <button id="phishing-btn-leave" class="phishing-btn primary">Leave This Site Immediately</button>
                <button id="phishing-btn-ignore" class="phishing-btn secondary">I understand the risks, continue anyway</button>
            </div>
        </div>
    `;

    // Add styles directly to ensure they load regardless of manifest execution timing
    const style = document.createElement("style");
    style.textContent = `
        #phishing-detector-warning-banner {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: rgba(0, 0, 0, 0.85);
            z-index: 2147483647; /* Maximum possible z-index to stay on top */
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            backdrop-filter: blur(5px);
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        .phishing-banner-content {
            background-color: white;
            border-top: 10px solid ${bgColor};
            border-radius: 8px;
            padding: 40px;
            max-width: 600px;
            width: 90%;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            color: #333;
            text-align: left;
            animation: slideInDown 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }

        .phishing-banner-title {
            color: ${bgColor};
            font-size: 24px;
            font-weight: 800;
            margin: 0 0 15px 0;
            text-transform: uppercase;
            line-height: 1.2;
        }

        .phishing-banner-subtitle {
            font-size: 16px;
            line-height: 1.5;
            margin: 0 0 25px 0;
            color: #555;
        }

        .phishing-banner-details {
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 25px;
            display: flex;
            flex-direction: column;
            gap: 15px;
            border: 1px solid #e9ecef;
        }

        .phishing-score-box {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-bottom: 15px;
            border-bottom: 1px solid #dee2e6;
        }

        .score-label {
            font-weight: bold;
            font-size: 18px;
        }

        .score-value {
            font-size: 32px;
            font-weight: 900;
            color: ${bgColor};
        }

        .score-max {
            font-size: 16px;
            color: #888;
        }

        .phishing-reasons-box ul {
            margin: 10px 0 0 0;
            padding-left: 20px;
            color: #444;
            font-size: 14px;
            line-height: 1.6;
        }

        .phishing-reasons-box li {
            margin-bottom: 5px;
        }

        .phishing-banner-actions {
            display: flex;
            gap: 15px;
            flex-direction: column;
        }

        .phishing-btn {
            padding: 12px 20px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.2s ease;
            text-align: center;
            width: 100%;
        }

        .phishing-btn.primary {
            background-color: ${bgColor};
            color: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .phishing-btn.primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 8px rgba(0,0,0,0.15);
            filter: brightness(1.1);
        }

        .phishing-btn.secondary {
            background-color: transparent;
            color: #6c757d;
            text-decoration: underline;
        }
        
        .phishing-btn.secondary:hover {
            color: #343a40;
        }

        @keyframes slideInDown {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
    `;

    document.head.appendChild(style);
    document.body.appendChild(overlay);

    // Event Listeners for buttons
    document.getElementById("phishing-btn-leave").addEventListener("click", () => {
        // Navigate away to a safe page (e.g. google.com or about:blank)
        window.location.href = "https://www.google.com";
    });

    document.getElementById("phishing-btn-ignore").addEventListener("click", () => {
        // Remove the overlay to continue
        overlay.remove();
        style.remove();
    });
}
