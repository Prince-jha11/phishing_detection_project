console.log("NEW SCRIPT LOADED");

async function analyzeURL() {
    let url = document.getElementById("urlInput").value.trim();

    if (!url) {
        alert("Enter a URL");
        return;
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        url = "http://" + url;
    }

    localStorage.setItem("url", url);
    window.location.href = "report.html";
}

async function fetchRisk(url) {
    try {
        const response = await fetch("http://127.0.0.1:8000/scan-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error("API error");

        return await response.json();

    } catch (error) {
        console.error("Error:", error);
        alert("Backend not running or CORS issue");
    }
}

// 🔥 SMART ANALYSIS FUNCTION
function generateSmartWarning(features) {
    let risky = [];
    let suspicious = [];

    if (features["Domain_registeration_length"] === -1)
        risky.push("Domain registration is short");

    if (features["age_of_domain"] === -1)
        risky.push("Domain is newly created");

    if (features["SFH"] === -1)
        risky.push("Form submission may send data to unsafe destination");

    if (features["URL_of_Anchor"] === 0)
        suspicious.push("Links may be misleading");

    if (features["Redirect"] === 0)
        suspicious.push("Page may redirect unexpectedly");

    let message = "";

    if (risky.length > 0) {
        message += "❌ High Risk Factors:\n- " + risky.join("\n- ") + "\n\n";
    }

    if (suspicious.length > 0) {
        message += "⚠️ Suspicious Signs:\n- " + suspicious.join("\n- ") + "\n\n";
    }

    if (risky.length >= 2) {
        message += "🚨 Likely Phishing: Avoid entering any sensitive information.";
    } else if (risky.length === 1 || suspicious.length >= 2) {
        message += "⚠️ Possibly Unsafe: Be cautious before trusting.";
    } else {
        message += "✅ Likely Legitimate: No strong risk indicators found.";
    }

    return message;
}

window.onload = async function () {
    if (window.location.pathname.includes("report.html")) {

        let url = localStorage.getItem("url");

        if (!url || url.includes("report.html")) {
            alert("Invalid URL. Please analyze again.");
            window.location.href = "index.html";
            return;
        }

        const result = await fetchRisk(url);
        if (!result) return;

        const riskCard = document.getElementById("riskCard");
        const riskLevel = document.getElementById("riskLevel");
        const riskScore = document.getElementById("riskScore");

        const probability = document.getElementById("probability");
        const domainInfo = document.getElementById("domainInfo");
        const sslStatus = document.getElementById("sslStatus");
        const domainAge = document.getElementById("domainAge");
        const historyList = document.getElementById("historyList");

        const level = result.prediction;

        riskLevel.innerText = level;

        if (level === "Phishing") riskCard.classList.add("high");
        else if (level === "Suspicious") riskCard.classList.add("medium");
        else riskCard.classList.add("low");

        riskScore.innerText = `Analyzed URL: ${url}`;

        const prob = (result.probability * 100).toFixed(2);

        if (level === "Legitimate") {
            probability.innerText = result.threat_detected
                ? `${prob}% Legitimate (⚠️ flagged)`
                : `${prob}% Legitimate`;
        } else if (level === "Phishing") {
            probability.innerText = `${prob}% Phishing`;
        } else {
            probability.innerText = "⚠️ Suspicious";
        }

        // 🔥 CLEAN FEATURE DISPLAY (FIXED)
        const features = result.features || {};
        domainInfo.innerHTML = "";

        const highRiskKeys = [
            "Domain_registeration_length",
            "age_of_domain",
            "SFH",
            "URL_of_Anchor",
            "Redirect"
        ];

        let highRisk = [];
        let mediumRisk = [];
        let safe = [];

        for (const key in features) {
            const value = features[key];

            const label = key
                .replace(/_/g, " ")
                .replace(/\b\w/g, c => c.toUpperCase());

            if (value === -1) {
                if (highRiskKeys.includes(key)) {
                    highRisk.push(`❌ ${label}`);
                } else {
                    mediumRisk.push(`⚠️ ${label}`);
                }
            } else if (value === 0) {
                mediumRisk.push(`⚠️ ${label}`);
            } else {
                safe.push(`✅ ${label}`);
            }
        }

        if (highRisk.length > 0) {
            const h = document.createElement("p");
            h.innerHTML = "<strong>🚨 High Risk:</strong><br>" + highRisk.join("<br>");
            domainInfo.appendChild(h);
        }

        if (mediumRisk.length > 0) {
            const m = document.createElement("p");
            m.innerHTML = "<strong>⚠️ Suspicious:</strong><br>" + mediumRisk.join("<br>");
            domainInfo.appendChild(m);
        }

        if (safe.length > 0) {
            const s = document.createElement("p");
            s.innerHTML = "<strong>✅ Safe Signals:</strong><br>" + safe.slice(0,5).join("<br>") + "...";
            domainInfo.appendChild(s);
        }

        // SSL
        sslStatus.innerText =
            features["SSLfinal_State"] === 1
                ? "Valid SSL"
                : "Suspicious / Invalid SSL";

        // DOMAIN AGE
        const ageFeature = features["age_of_domain"];
        const ageDays = features["domain_age_days"];

        if (ageDays !== null && ageDays !== undefined) {
            const years = (ageDays / 365).toFixed(1);

            if (ageFeature === 1) {
                domainAge.innerText = `${ageDays} days (~${years} years) - ✅ Old Domain`;
            } else {
                domainAge.innerText = `${ageDays} days (~${years} years) - ❌ New Domain`;
            }
        } else {
            domainAge.innerText = "Unknown Domain Age ⚠️";
        }

        // THREAT FEED
        historyList.innerHTML = "";

        if (result.threat_detected) {
            const li = document.createElement("li");
            li.innerHTML = `⚠️ Found in threat database: 
                <a href="${result.threat_feed}" target="_blank">View Source</a>`;
            historyList.appendChild(li);
        } else {
            const li = document.createElement("li");
            li.innerText = "✅ No records found";
            historyList.appendChild(li);
        }

        // POPUP
        const smartMessage = generateSmartWarning(features);

        if (level === "Phishing") {
            showPopup("🚨 High Risk Website", smartMessage);
        } else if (level === "Suspicious") {
            showPopup("⚠️ Suspicious Website", smartMessage);
        } else if (level === "Legitimate" && result.threat_detected) {
            showPopup("⚠️ Mixed Signals", smartMessage);
        }
    }
};

function showPopup(title, message) {
    document.getElementById("popupTitle").innerText = title;
    document.getElementById("popupMessage").innerText = message;
    document.getElementById("warningPopup").classList.remove("hidden");
}

function closePopup() {
    document.getElementById("warningPopup").classList.add("hidden");
}

function goBack() {
    window.location.href = "index.html";
}