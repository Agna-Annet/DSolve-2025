document.addEventListener('DOMContentLoaded', async () => {
  // Get the current active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    // Show analyzing status for current URL
    document.getElementById('risk-score').textContent = `Analyzing ${tab.url}...`;
    
    // Trigger analysis for current tab
    chrome.runtime.sendMessage({ action: "analyze", url: tab.url, tabId: tab.id }, (response) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError);
        document.getElementById('risk-score').textContent = 'Error: Could not analyze page';
        return;
      }
    });
  }

  // Check for existing results
  const results = await chrome.storage.local.get('analysisResults');
  if (results.analysisResults) {
    updateUI(results.analysisResults);
  }
});

function updateUI(results) {
  const riskScore = document.getElementById('risk-score');
  const riskIndicator = document.getElementById('risk-indicator');
  const issuesList = document.getElementById('issues-list');
  
  // Update risk score
  riskScore.textContent = `Risk Level: ${results.riskScore}%`;
  riskIndicator.style.width = `${results.riskScore}%`;
  
  // Set color based on risk level
  if (results.riskScore < 30) {
    riskIndicator.style.backgroundColor = 'var(--safe-color)';
    riskScore.style.color = 'var(--safe-color)';
  } else if (results.riskScore < 70) {
    riskIndicator.style.backgroundColor = 'var(--warning-color)';
    riskScore.style.color = 'var(--warning-color)';
  } else {
    riskIndicator.style.backgroundColor = 'var(--danger-color)';
    riskScore.style.color = 'var(--danger-color)';
  }
  
  // Clear and update issues list
  issuesList.innerHTML = '';
  
  // Add URL analysis results
  if (results.urlAnalysis.error) {
    addIssue(issuesList, `URL Check Error: ${results.urlAnalysis.error}`);
  } else if (results.urlAnalysis.isMalicious) {
    addIssue(issuesList, `URL detected as malicious by ${results.urlAnalysis.detections} security vendors`);
  }
  
  // Add language issues
  if (results.languageIssues && results.languageIssues.length > 0) {
    results.languageIssues.forEach(issue => {
      addIssue(issuesList, issue);
    });
  }
  
  // Add security check results
  if (results.securityChecks && results.securityChecks.length > 0) {
    results.securityChecks.forEach(check => {
      addIssue(issuesList, check);
    });
  }
  
  // Show "no issues" message if everything is clean
  if (issuesList.children.length === 0) {
    addIssue(issuesList, 'No security issues detected');
  }
}

function addIssue(list, text) {
  const li = document.createElement('li');
  li.textContent = text;
  list.appendChild(li);
}