// Wait for DOM to load
document.addEventListener("DOMContentLoaded", async () => {
    
    const urlDisplay = document.getElementById("url-display");
    const scanBtn = document.getElementById("scan-btn");
    const btnText = document.getElementById("btn-text");
    const btnLoader = document.getElementById("btn-loader");
    
    const resultsCard = document.getElementById("results-card");
    const riskBadge = document.getElementById("risk-badge");
    const predictionValue = document.getElementById("prediction-value");
    const probabilityValue = document.getElementById("probability-value");
    const threatValue = document.getElementById("threat-value");
    const errorBox = document.getElementById("error-message");

    let currentUrl = "";

    // 1 & 2: Get current tab URL
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            currentUrl = tab.url;
            urlDisplay.textContent = new URL(currentUrl).hostname;
            urlDisplay.title = currentUrl;
        } else {
            urlDisplay.textContent = "Unable to read URL";
            scanBtn.disabled = true;
        }
    } catch (err) {
        urlDisplay.textContent = "Error reading URL";
        console.error("Tab reading error", err);
        scanBtn.disabled = true;
    }

    // 3: Send URL to backend when button clicked
    scanBtn.addEventListener("click", async () => {
        if (!currentUrl) return;

        // UI Reset and Loading State
        resultsCard.classList.add("hidden");
        errorBox.classList.add("hidden");
        btnText.classList.add("hidden");
        btnLoader.classList.remove("hidden");
        scanBtn.disabled = true;

        try {
            // 4: API Call
            const response = await fetch("http://localhost:8000/scan-url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: currentUrl })
            });

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            const data = await response.json();
            
            // 5: Display Results in popup
            predictionValue.textContent = data.prediction;
            probabilityValue.textContent = `${(data.probability * 100).toFixed(1)}%`;
            threatValue.textContent = data.threat_feed || "None";
            
            // Apply badge styling
            riskBadge.textContent = data.risk_flag.toUpperCase();
            riskBadge.className = `badge flag-${data.risk_flag}`;
            
            // Show result card
            resultsCard.classList.remove("hidden");
        } catch (error) {
            console.error("API Call failed", error);
            errorBox.textContent = `Analysis failed: Is the local AI server running? (${error.message})`;
            errorBox.classList.remove("hidden");
        } finally {
            // Revert button state
            btnText.classList.remove("hidden");
            btnLoader.classList.add("hidden");
            scanBtn.disabled = false;
        }
    });
});
