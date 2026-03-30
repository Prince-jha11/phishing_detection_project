async function analyzeURL() {
    const url = document.getElementById("urlInput").value;

    if (!url) {
        alert("Enter a URL");
        return;
    }

    localStorage.setItem("url", url);
    window.location.href = "report.html";
}

async function fetchRisk(url) {
    try {
        const response = await fetch("http://127.0.0.1:8000/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        return data;

    } catch (error) {
        console.error("Error:", error);
        alert("Backend not running or CORS issue");
    }
}

window.onload = async function () {
    if (window.location.pathname.includes("report.html")) {

        const url = localStorage.getItem("url");

        if (!url) {
            alert("No URL found");
            return;
        }

        const result = await fetchRisk(url);
        if (!result) return;

        const risk = result.risk;

        const riskCard = document.getElementById("riskCard");
        const riskLevel = document.getElementById("riskLevel");
        const riskScore = document.getElementById("riskScore");

        const probability = document.getElementById("probability");
        const domainInfo = document.getElementById("domainInfo");
        const sslStatus = document.getElementById("sslStatus");
        const domainAge = document.getElementById("domainAge");
        const historyList = document.getElementById("historyList");

        let level;

        if (risk > 0.7) {
            level = "High Risk";
            riskCard.classList.add("high");
        } else if (risk > 0.4) {
            level = "Moderate Risk";
            riskCard.classList.add("medium");
        } else {
            level = "Low Risk";
            riskCard.classList.add("low");
        }

        riskLevel.innerText = level;
        riskScore.innerText = `Analyzed URL: ${url}`;
        probability.innerText = `${(risk * 100).toFixed(2)}% chance of phishing`;

        domainInfo.innerText = result.domain || "Unknown";
        sslStatus.innerText = result.ssl || "Unknown";
        domainAge.innerText = result.age || "Unknown";

        historyList.innerHTML = "";

        (result.history || []).forEach(r => {
            const li = document.createElement("li");
            li.innerText = r;
            historyList.appendChild(li);
        });
    }
};

function goBack() {
    window.location.href = "index.html";
}
