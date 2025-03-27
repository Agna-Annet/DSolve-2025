// Notify background script that content script is loaded
chrome.runtime.sendMessage({ action: "contentScriptReady" });

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze") {
    analyzePage().then(results => sendResponse(results));
    return true;
  }
});

async function analyzePage() {
  console.log('Analyzing page content...');
  const results = {
    languageIssues: await checkLanguage(),
    securityChecks: performSecurityChecks()
  };
  console.log('Analysis results:', results);
  return results;
}

async function checkLanguage() {
  const textContent = document.body.innerText;
  const issues = [];
  
  // Check for urgent language
  const urgentPhrases = [
    'Act now',
    'Limited time',
    'Urgent',
    'Immediate action required',
    'Don\'t delay',
    'Act immediately',
    'Time sensitive',
    'Expires soon',
    'Account suspended',
    'Security breach',
    'Unauthorized activity'
  ];

  // Check for suspicious phrases
  const suspiciousPhrases = [
    'Verify your account',
    'Confirm your identity',
    'Update your information',
    'Security check required',
    'Account suspended',
    'Unusual activity',
    'Click here to verify',
    'Enter your password',
    'Provide your details',
    'Reset your account'
  ];

  // Check urgent language
  urgentPhrases.forEach(phrase => {
    if (textContent.toLowerCase().includes(phrase.toLowerCase())) {
      issues.push(`Found urgent language: "${phrase}"`);
    }
  });

  // Check suspicious phrases
  suspiciousPhrases.forEach(phrase => {
    if (textContent.toLowerCase().includes(phrase.toLowerCase())) {
      issues.push(`Found suspicious phrase: "${phrase}"`);
    }
  });

  // Check grammar using OpenAI API
  try {
    // Send text to background script for API call
    const response = await chrome.runtime.sendMessage({
      action: "checkGrammar",
      text: textContent.substring(0, 1000) // Limit text length
    });

    if (response && response.hasGrammarIssues) {
      issues.push('Significant grammar and spelling errors detected (common in phishing attempts)');
    }
  } catch (error) {
    console.error('Grammar check error:', error);
  }

  return issues;
}

function performSecurityChecks() {
  const checks = [];
  
  // Check for SSL/HTTPS
  if (window.location.protocol !== 'https:') {
    checks.push('Website not using secure HTTPS connection');
  }
  
  // Check for fake security indicators
  const securityImages = Array.from(document.images).filter(img => 
    img.src.toLowerCase().includes('secure') ||
    img.src.toLowerCase().includes('ssl') ||
    img.src.toLowerCase().includes('lock')
  );
  if (securityImages.length > 0) {
    checks.push('Found potentially fake security indicators');
  }

  // Check for excessive form fields
  const formFields = document.querySelectorAll('input');
  const sensitiveFields = Array.from(formFields).filter(field => 
    field.type === 'password' ||
    field.type === 'credit-card' ||
    field.name.toLowerCase().includes('ssn') ||
    field.name.toLowerCase().includes('card')
  );
  if (sensitiveFields.length > 2) {
    checks.push('Multiple sensitive information fields detected');
  }

  // Check for redirects
  if (document.querySelectorAll('meta[http-equiv="refresh"]').length > 0) {
    checks.push('Page contains automatic redirect');
  }

  // Check for pop-ups
  const popupTriggers = Array.from(document.scripts).filter(script => 
    script.text.includes('window.open') ||
    script.text.includes('popup')
  );
  if (popupTriggers.length > 0) {
    checks.push('Page contains pop-up scripts');
  }

  return checks;
}