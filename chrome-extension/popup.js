// Replace with your backend URL if deployed elsewhere
const BACKEND_URL = "http://localhost:5050/api";

// DOM elements
const spinner = document.getElementById('spinner');
const resultsSection = document.getElementById('results-section');
const urlStatusDiv = document.getElementById('url-status');
const resultDiv = document.getElementById('result');
const autoWarning = document.getElementById('auto-warning');

// Utility functions
function showLoading() {
  spinner.style.display = 'flex';
  resultsSection.style.display = 'none';
  autoWarning.classList.remove('active');
}

function hideLoading() {
  spinner.style.display = 'none';
  resultsSection.style.display = 'block';
}

function setUrlStatus(url, isPhishing) {
  if (!url) {
    urlStatusDiv.innerHTML = '';
    return;
  }
  
  let badge = '';
  if (isPhishing === true) {
    badge = `<span class="status-badge status-phishing">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      Phishing Detected
    </span>`;
  } else if (isPhishing === false) {
    badge = `<span class="status-badge status-safe">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M9 12l2 2 4-4"/>
        <path d="M21 12c-1 0-2-1-2-2s1-2 2-2 2 1 2 2-1 2-2 2z"/>
      </svg>
      Safe
    </span>`;
  }
  
  urlStatusDiv.innerHTML = `
    <div style="font-size: 13px; word-break: break-all; color: #6b7280; margin-bottom: 8px;">
      ${url}
    </div>
    ${badge}
  `;
}

function showResult(message, isPhishing, url) {
  setUrlStatus(url, isPhishing);
  
  if (isPhishing === true) {
    resultDiv.innerHTML = `
      <div class='result-warning'>
        <svg class='warning-icon' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <div>
          <div style="font-weight: 600; margin-bottom: 4px;">Security Alert</div>
          <div style="font-size: 13px;">${message}</div>
        </div>
      </div>
    `;
    autoWarning.classList.add('active');
    
    // Show browser notification
    // if (window.Notification && Notification.permission === "granted") {
    //   new Notification("PhishGuard Pro Alert!", { 
    //     body: message, 
    //     icon: 'icon128.png.png',
    //     badge: 'icon128.png.png',
    //     tag: 'phishing-alert'
    //   });
    // }
  } else if (isPhishing === false) {
    resultDiv.innerHTML = `
      <div class='result-safe'>
        <svg class='warning-icon' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 12l2 2 4-4"/>
          <path d="M21 12c-1 0-2-1-2-2s1-2 2-2 2 1 2 2-1 2-2 2z"/>
        </svg>
        <div>
          <div style="font-weight: 600; margin-bottom: 4px;">All Clear</div>
          <div style="font-size: 13px;">${message}</div>
        </div>
      </div>
    `;
    autoWarning.classList.remove('active');
  } else {
    resultDiv.innerHTML = `
      <div style="text-align: center; color: #6b7280; font-size: 13px; padding: 16px;">
        ${message}
      </div>
    `;
    autoWarning.classList.remove('active');
  }
}

async function checkUrl(url) {
  try {
    showLoading();
    
    const response = await fetch(`${BACKEND_URL}/check_url`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url})
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.label === 1) {
      showResult(data.user_message || "This URL appears to be a phishing attempt. Please proceed with caution.", true, url);
    } else if (data.label === 0) {
      showResult(data.user_message || "This URL appears to be safe and legitimate.", false, url);
    } else {
      showResult(data.user_message || "Unable to analyze this URL. Please try again.", undefined, url);
    }
  } catch (error) {
    console.error('Error checking URL:', error);
    showResult("Connection error. Please check if the backend server is running.", undefined, url);
  } finally {
    hideLoading();
  }
}

async function checkSelection(selectedText) {
  try {
    showLoading();
    
    const response = await fetch(`${BACKEND_URL}/check_message`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({message: selectedText})
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // If either text_result or url_result is phishing, warn
    let isPhishing = false;
    let message = "";
    
    if (data.url_result && data.url_result.label === 1) {
      isPhishing = true;
      message += data.url_result.user_message + "\n";
    }
    if (data.text_result && data.text_result.label === 1) {
      isPhishing = true;
      message += data.text_result.user_message + "\n";
    }
    
    if (!isPhishing) {
      if (data.url_result && data.url_result.label === 0) message += data.url_result.user_message + "\n";
      if (data.text_result && data.text_result.label === 0) message += data.text_result.user_message + "\n";
    }
    
    showResult(message.trim() || data.user_message || "Analysis complete.", isPhishing, null);
  } catch (error) {
    console.error('Error checking selection:', error);
    showResult("Connection error. Please check if the backend server is running.", undefined, null);
  } finally {
    hideLoading();
  }
}

// Event listeners
document.getElementById('check-url').addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const url = tab.url;
    await checkUrl(url);
  } catch (error) {
    console.error('Error getting current tab:', error);
    showResult("Unable to access current page. Please try again.", undefined, null);
  }
});

document.getElementById('check-selection').addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    
    const injectionResults = await chrome.scripting.executeScript({
      target: {tabId: tab.id},
      func: () => window.getSelection().toString()
    });
    
    const selectedText = injectionResults[0].result;
    if (!selectedText || selectedText.trim() === '') {
      showResult("No text selected. Please select some text on the page first.");
      return;
    }
    
    await checkSelection(selectedText);
  } catch (error) {
    console.error('Error getting selection:', error);
    showResult("Unable to get selected text. Please try again.", undefined, null);
  }
});

// Request notification permission on first load
// if (window.Notification && Notification.permission !== "granted") {
//   Notification.requestPermission();
// }

// Initialize popup
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const url = tab.url;
    
    // Show initial state
    setUrlStatus(url);
    resultsSection.style.display = 'none';
    
    // Auto-check the current page
    await checkUrl(url);
  } catch (error) {
    console.error('Error initializing popup:', error);
    showResult("Unable to initialize. Please refresh the extension.", undefined, null);
  }
});

// Add some nice hover effects and animations
document.addEventListener('DOMContentLoaded', () => {
  // Add ripple effect to buttons
  const buttons = document.querySelectorAll('.action-btn');
  buttons.forEach(button => {
    button.addEventListener('click', function(e) {
      const ripple = document.createElement('span');
      const rect = this.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;
      
      ripple.style.width = ripple.style.height = size + 'px';
      ripple.style.left = x + 'px';
      ripple.style.top = y + 'px';
      ripple.classList.add('ripple');
      
      this.appendChild(ripple);
      
      setTimeout(() => {
        ripple.remove();
      }, 600);
    });
  });
}); 