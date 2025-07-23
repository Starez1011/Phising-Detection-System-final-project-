const BACKEND_URL = "http://localhost:5050/api";

async function checkUrlForPhishing(url) {
  try {
    const response = await fetch(`${BACKEND_URL}/check_url`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url})
    });
    
    if (!response.ok) {
      console.error('Backend connection failed:', response.status);
      return;
    }
    
    const data = await response.json();
    if (data.label === 1) {
      // Notification removed: phishing detected
      console.log("Phishing detected on this site!", data.user_message || "⚠️ Phishing detected on this site! Please proceed with caution.");
    } else if (data.label === 0) {
      // Only log safe notifications for important sites (banks, etc.)
      const importantDomains = ['bank', 'paypal', 'amazon', 'google', 'facebook', 'twitter'];
      const isImportantSite = importantDomains.some(domain => url.toLowerCase().includes(domain));
      
      if (isImportantSite) {
        // Notification removed: site appears safe
        console.log("This site appears to be safe and legitimate.");
      }
    }
  } catch (error) {
    console.error('Error checking URL for phishing:', error);
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active && tab.url && tab.url.startsWith("http")) {
    checkUrlForPhishing(tab.url);
  }
});

chrome.tabs.onActivated.addListener(activeInfo => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab.url && tab.url.startsWith("http")) {
      checkUrlForPhishing(tab.url);
    }
  });
}); 