function analyzeURL() {
    const url = document.getElementById("urlInput").value;

    if (!url) {
        alert("Enter a URL");
        return;
    }

    localStorage.setItem("url", url);

    window.location.href = "report.html";
}

window.onload = function () {
    if (window.location.pathname.includes("report.html")) {

        const url = localStorage.getItem("url");

        // 🔥 Replace with your ML API later
        const risk = Math.random(); 

        const riskCard = document.getElementById("riskCard");
        const riskLevel = document.getElementById("riskLevel");
        const riskScore = document.getElementById("riskScore");

        const probability = document.getElementById("probability");
        const domainInfo = document.getElementById("domainInfo");
        const sslStatus = document.getElementById("sslStatus");
        const domainAge = document.getElementById("domainAge");
        const historyList = document.getElementById("historyList");

        // Risk Logic
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

        // Dummy Data (replace with backend)
        domainInfo.innerText = "Example Hosting Provider";
        sslStatus.innerText = risk > 0.5 ? "Invalid / Suspicious" : "Valid SSL";
        domainAge.innerText = risk > 0.5 ? "Recently Registered" : "Old Domain";

        // Past Records
        const records = [
            "Flagged in phishing database",
            "Reported by users",
            "Suspicious redirect detected"
        ];

        historyList.innerHTML = "";

        records.forEach(r => {
            const li = document.createElement("li");
            li.innerText = r;
            historyList.appendChild(li);
        });
    }
};

function goBack() {
    window.location.href = "index.html";
}