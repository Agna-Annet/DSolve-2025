// API configuration
const VIRUSTOTAL_API_KEY = '2e5b5a856ea683df1164c5d8f0061a4f7f8edcb30923626362605cb31af918b0';
const OPENAI_API_KEY = 'YOUR_OPENAI_API_KEY'; // Replace with your OpenAI API key

// Listen for navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId === 0) { // Only analyze main frame
    try {
      const tab = await chrome.tabs.get(details.tabId);
      if (tab.url.startsWith('http')) { // Only analyze HTTP/HTTPS pages
        await analyzeWebsite(tab.url, details.tabId);
      }
    } catch (error) {
      console.error('Error in navigation listener:', error);
    }
  }
});

// Listen for messages from popup and content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze") {
    analyzeWebsite(request.url, request.tabId)
      .then(() => sendResponse({ status: "success" }))
      .catch(error => sendResponse({ status: "error", message: error.message }));
    return true;
  }

  if (request.action === "checkGrammar") {
    checkGrammarWithOpenAI(request.text)
      .then(result => sendResponse(result))
      .catch(error => {
        console.error('Grammar check error:', error);
        sendResponse({ hasGrammarIssues: false });
      });
    return true;
  }
});

async function checkGrammarWithOpenAI(text) {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo",
        messages: [{
          role: "system",
          content: "You are a grammar checker. Analyze the text for significant grammar and spelling errors. Only respond with a number from 0 to 10 indicating the severity of errors (0 = perfect, 10 = severe errors). Consider poor grammar and spelling common in phishing emails."
        }, {
          role: "user",
          content: text
        }],
        temperature: 0.3,
        max_tokens: 5
      })
    });

    if (!response.ok) {
      throw new Error('OpenAI API error');
    }

    const data = await response.json();
    const severityScore = parseInt(data.choices[0].message.content);
    
    return {
      hasGrammarIssues: severityScore > 6 // Only flag significant issues
    };
  } catch (error) {
    console.error('OpenAI API error:', error);
    return { hasGrammarIssues: false };
  }
}

async function analyzeWebsite(url, tabId) {
  console.log('Starting analysis for:', url);
  
  const results = {
    urlAnalysis: { message: 'Analysis in progress' },
    languageIssues: [],
    securityChecks: [],
    riskScore: 0
  };

  try {
    // Store initial state
    await chrome.storage.local.set({ analysisResults: results });

    // Check URL first
    results.urlAnalysis = await checkURL(url);
    console.log('URL analysis complete:', results.urlAnalysis);

    // Get page content analysis
    try {
      const response = await chrome.tabs.sendMessage(tabId, { action: "analyze" });
      if (response) {
        results.languageIssues = response.languageIssues || [];
        results.securityChecks = response.securityChecks || [];
        calculateRiskScore(results);
      }
    } catch (error) {
      console.error('Content script error:', error);
      // Try to inject content script
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tabId },
          files: ['content.js']
        });
        // Wait for script to initialize
        await new Promise(resolve => setTimeout(resolve, 500));
        // Try analysis again
        const retryResponse = await chrome.tabs.sendMessage(tabId, { action: "analyze" });
        if (retryResponse) {
          results.languageIssues = retryResponse.languageIssues || [];
          results.securityChecks = retryResponse.securityChecks || [];
          calculateRiskScore(results);
        }
      } catch (injectionError) {
        console.error('Content script injection error:', injectionError);
        results.urlAnalysis.message = 'Partial analysis only - Could not analyze page content';
        await chrome.storage.local.set({ analysisResults: results });
      }
    }
  } catch (error) {
    console.error('Analysis error:', error);
    results.urlAnalysis = { 
      message: 'Analysis failed', 
      error: error.message 
    };
    await chrome.storage.local.set({ analysisResults: results });
  }
}

async function checkURL(url) {
  console.log('Checking URL:', url);
  
  try {
    // Basic URL checks first
    const urlObj = new URL(url);
    const issues = [];

    // Check for suspicious TLD
    const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) {
      issues.push('Suspicious domain extension');
    }

    // Check for numeric IP
    if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
      issues.push('IP address used instead of domain name');
    }

    // Check for suspicious characters
    if (/[@%]/.test(url)) {
      issues.push('URL contains suspicious characters');
    }

    // Check protocol
    if (urlObj.protocol !== 'https:') {
      issues.push('Not using secure HTTPS connection');
    }

    // If we have local issues, return them
    if (issues.length > 0) {
      return {
        isMalicious: true,
        detections: issues.length,
        total: 4,
        message: issues.join(', ')
      };
    }

    // Try VirusTotal API
    const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(url)}`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    
    return {
      isMalicious: data.positives > 0,
      detections: data.positives || 0,
      total: data.total || 0,
      message: data.positives > 0 ? `Detected as malicious by ${data.positives} scanners` : 'No threats detected'
    };
  } catch (error) {
    console.error('Error checking URL:', error);
    return {
      isMalicious: false,
      detections: 0,
      total: 0,
      message: 'Could not check URL security'
    };
  }
}

function calculateRiskScore(results) {
  let score = 0;
  
  // URL analysis score (40% weight)
  if (results.urlAnalysis.isMalicious) {
    score += 40 * (results.urlAnalysis.detections / results.urlAnalysis.total);
  }
  
  // Language issues score (30% weight)
  score += Math.min(30, results.languageIssues.length * 5);
  
  // Security checks score (30% weight)
  score += Math.min(30, results.securityChecks.length * 5);
  
  results.riskScore = Math.min(100, Math.round(score));
  console.log('Final risk score:', results.riskScore);
  chrome.storage.local.set({ analysisResults: results });
}