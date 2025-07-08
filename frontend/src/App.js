import React, { useState } from 'react';
// Importing icons from lucide-react for a modern look
// Added new icons for external intelligence section: Globe, FileText, Eye
import { Shield, Link, Percent, AlertTriangle, Calendar, Lock, Ruler, GitFork, Hash, Globe, Search, ShieldCheck, Zap, ShieldAlert, FileText, Eye } from 'lucide-react';

const App = () => {
  // Your existing state variables
  const [url, setUrl] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // NEW: State for External Threat Intelligence APIs
  const [urlscanReport, setUrlscanReport] = useState(null);
  const [virustotalReport, setVirustotalReport] = useState(null);
  const [loadingExternal, setLoadingExternal] = useState(false); // Combined loading for external APIs

  // Your existing API Base URL for Flask backend
  const API_BASE_URL = 'http://127.0.0.1:5000';

  // NEW: API Keys (WARNING: NOT SECURE FOR PRODUCTION - these should ideally be on your backend)
  const URLSCAN_API_KEY = '01972b27-df56-72de-93e3-259b008db04c';
  const VIRUSTOTAL_API_KEY = 'fa2edeb4ceb240ee6405593337e2974dbb22b1ae333406955b532a1eeb476d7f';

  const handleUrlChange = (e) => {
    setUrl(e.target.value);
    setAnalysisResult(null);
    setError(null);
    // NEW: Clear external API results and errors on new input
    setUrlscanReport(null);
    setVirustotalReport(null);
  };

  /**
   * NEW: Fetches scan report from urlscan.io.
   * Initiates a scan and then polls for results.
   * @param {string} targetUrl - The URL to scan.
   */
  const fetchUrlscanReport = async (targetUrl) => {
    try {
      // 1. Submit URL for scan
      const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
        method: 'POST',
        headers: {
          'API-Key': URLSCAN_API_KEY,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: targetUrl, visibility: 'public' }), // 'public' or 'private'
      });

      if (!submitResponse.ok) {
        const errorData = await submitResponse.json();
        throw new Error(`urlscan.io submission failed: ${errorData.message || submitResponse.statusText}`);
      }

      const submitData = await submitResponse.json();
      const scanId = submitData.uuid;
      // const resultUrl = submitData.api; // This is the API URL for results

      // For simplicity, we'll wait a fixed time and then fetch.
      // In a real app, you'd implement polling with exponential backoff.
      await new Promise(resolve => setTimeout(resolve, 15000)); // Wait 15 seconds for scan to complete

      // 2. Fetch scan results
      const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${scanId}/`, {
        headers: { 'API-Key': URLSCAN_API_KEY },
      });

      if (!resultResponse.ok) {
        const errorData = await resultResponse.json();
        // Check for specific urlscan.io errors like 'Not Found' or 'API key disabled'
        if (resultResponse.status === 404) {
            throw new Error("Scan result not found or still processing on urlscan.io.");
        } else if (resultResponse.status === 401 || resultResponse.status === 403) {
            throw new Error("urlscan.io: API key is disabled or invalid!");
        }
        throw new Error(`urlscan.io result fetch failed: ${errorData.message || resultResponse.statusText}`);
      }

      const resultData = await resultResponse.json();
      // Summarize the report for display
      const summary = {
        scanUrl: resultData.task.url,
        verdict: resultData.verdicts?.overall?.malicious || 'unknown',
        score: resultData.verdicts?.overall?.score || 0,
        description: resultData.verdicts?.overall?.description || 'No specific verdict description.',
        screenshot: resultData.screenshot || null,
        reportLink: resultData.result || null, // Link to the full report page
      };
      setUrlscanReport(summary);

    } catch (err) {
      console.error("urlscan.io API Error:", err);
      if (err.message.includes("API key is disabled or invalid!")) {
        setUrlscanReport({ error: "API key is disabled!" });
      } else if (err.message.includes("Not Found")) {
        setUrlscanReport({ error: "Scan result not found or still processing." });
      } else {
        setUrlscanReport({ error: `Failed to get urlscan.io report: ${err.message}` });
      }
    }
  };

  /**
   * NEW: Fetches scan report from VirusTotal.
   * Submits a URL and then polls for analysis results.
   * @param {string} targetUrl - The URL to scan.
   */
  const fetchVirustotalReport = async (targetUrl) => {
    try {
      // 1. Submit URL for analysis
      const encodedUrl = encodeURIComponent(targetUrl);
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `url=${encodedUrl}`,
      });

      if (!submitResponse.ok) {
        const errorData = await submitResponse.json();
        if (submitResponse.status === 401 || submitResponse.status === 403) {
            throw new Error("VirusTotal: API key is disabled or invalid!");
        }
        throw new Error(`VirusTotal submission failed: ${errorData.error?.message || submitResponse.statusText}`);
      }

      const submitData = await submitResponse.json();
      const analysisId = submitData.data.id;

      // For simplicity, we'll wait a fixed time and then fetch.
      // In a real app, you'd implement polling with exponential backoff.
      await new Promise(resolve => setTimeout(resolve, 15000)); // Wait 15 seconds for analysis to complete

      // 2. Fetch analysis report
      const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
      });

      if (!reportResponse.ok) {
        const errorData = await reportResponse.json();
        if (reportResponse.status === 404) {
            throw new Error("VirusTotal analysis not found or still processing.");
        } else if (reportResponse.status === 401 || reportResponse.status === 403) {
            throw new Error("VirusTotal: API key is disabled or invalid!");
        }
        throw new Error(`VirusTotal report fetch failed: ${errorData.error?.message || reportResponse.statusText}`);
      }

      const reportData = await reportResponse.json();
      const stats = reportData.data.attributes.stats;
      // const lastAnalysisStats = reportData.data.attributes.last_analysis_stats; // Not used in summary for now

      // Summarize the report for display
      const summary = {
        status: reportData.data.attributes.status,
        harmless: stats.harmless,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected,
        timeout: stats.timeout,
        reportLink: `https://www.virustotal.com/gui/url/${analysisId}/detection`, // Link to the full report page
      };
      setVirustotalReport(summary);

    } catch (err) {
      console.error("VirusTotal API Error:", err);
      if (err.message.includes("API key is disabled or invalid!")) {
        setVirustotalReport({ error: "API key is disabled!" });
      } else if (err.message.includes("analysis not found")) {
        setVirustotalReport({ error: "URL not found in VirusTotal database or still processing." });
      } else {
        setVirustotalReport({ error: `Failed to get VirusTotal report: ${err.message}` });
      }
    }
  };


  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setLoadingExternal(true); // Start loading for external APIs
    setAnalysisResult(null);
    setUrlscanReport(null); // Clear previous external results
    setVirustotalReport(null); // Clear previous external results
    setError(null);

    if (!url) {
      setError("Please enter a URL to check.");
      setLoading(false);
      setLoadingExternal(false);
      return;
    }

    // --- Internal ML Model Prediction ---
    try {
      const response = await fetch(`${API_BASE_URL}/predict`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setAnalysisResult(data);
    } catch (err) {
      console.error("Error fetching internal ML prediction:", err);
      setError(`Failed to get internal ML prediction: ${err.message}. Please ensure the backend is running and responding correctly.`);
    } finally {
      setLoading(false); // ML model prediction loading finishes here
    }

    // --- External Threat Intelligence API Calls (run concurrently) ---
    try {
      // Use Promise.allSettled to allow all promises to finish regardless of individual success/failure
      await Promise.allSettled([
        fetchUrlscanReport(url),
        fetchVirustotalReport(url)
      ]);
    } catch (err) {
      // This catch block will only run if Promise.allSettled itself fails,
      // individual errors are handled within fetchUrlscanReport/fetchVirustotalReport
      console.error("Error during external API calls orchestration:", err);
      // setExternalError("An error occurred coordinating external API calls."); // Individual errors are better
    } finally {
      setLoadingExternal(false); // External API loading finishes here
    }
  };

  const getRiskBarColor = (score) => {
    if (score >= 75) return 'bg-red-500';
    if (score >= 50) return 'bg-orange-500';
    return 'bg-green-500';
  };

  const getClassificationColor = (classification) => {
    switch (classification) {
      case 'PHISHING': return 'text-red-400';
      case 'SUSPICIOUS': return 'text-orange-400';
      case 'BENIGN': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="fixed inset-0 bg-gradient-to-br from-blue-950 via-blue-900 to-indigo-950 text-gray-100 flex flex-col items-center justify-center p-4 sm:p-6 lg:p-8 overflow-auto">
      {/* Header Section */}
      <header className="w-full max-w-5xl text-center mb-8 animate-fade-in">
        <div className="flex items-center justify-center mb-3">
          <Shield className="text-blue-300 mr-2" size={40} />
          <h1 className="text-5xl font-extrabold text-blue-300 tracking-tight drop-shadow-lg">SafeScan.Pro</h1>
        </div>
        <p className="text-base text-gray-300 max-w-2xl mx-auto">
          Advanced phishing URL detection system powered by machine learning. Protect yourself from malicious websites with real-time threat analysis.
        </p>
      </header>

      {/* URL Input Section */}
      <section className="w-full max-w-4xl bg-[#032963] rounded-lg shadow-xl p-5 mb-8 border border-blue-600 transform transition-all duration-300 hover:scale-[1.01] animate-fade-in delay-100">
        <h2 className="text-xl font-semibold text-gray-100 mb-3 flex items-center">
          <Link className="mr-2 text-blue-400" size={20} /> URL Security Scanner
        </h2>
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            className="flex-grow px-4 py-2 rounded-md bg-gradient-to-br text-gray-100 border border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all duration-200 placeholder-gray-400 text-sm shadow-inner"
            placeholder="Enter URL (e.g., https://example.com)"
            value={url}
            onChange={handleUrlChange}
            disabled={loading || loadingExternal} // Disable during all loading
          />
          <button
            type="submit"
            className="flex-shrink-0 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-5 rounded-md shadow-md transition-all duration-300 ease-in-out transform hover:-translate-y-0.5 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-[#2d3748] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center text-sm"
            disabled={loading || loadingExternal} // Disable during all loading
          >
            {(loading || loadingExternal) ? ( // Show combined loading spinner
              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            ) : (
              <>
                <Search className="mr-1" size={16} /> Scan
              </>
            )}
          </button>
        </form>
        {error && (
          <div className="mt-3 p-2 bg-red-800 text-red-100 border border-red-600 rounded-md text-center font-medium text-sm shadow-md">
            <p>Error: {error}</p>
          </div>
        )}
      </section>

      {/* Conditional Rendering: Show static cards OR analysis results */}
      {!analysisResult && !loadingExternal ? ( // Show static cards only if no analysis result AND not loading external
        // Static informational cards (visible when no analysis result is present)
        <section className="w-full max-w-5xl grid grid-cols-1 md:grid-cols-3 gap-6 animate-fade-in delay-200">
          {/* Real-time Analysis Card */}
          <div className="bg-[#032963] rounded-lg shadow-xl p-5 border border-blue-600 flex flex-col items-center text-center transform transition-all duration-300 hover:scale-[1.03]">
            <ShieldCheck className="text-blue-400 mb-3" size={36} />
            <h3 className="text-lg font-semibold text-gray-100 mb-2">Real-time Analysis</h3>
            <p className="text-gray-300 text-xs">Instant URL scanning and advanced feature extraction and ML predictions.</p>
          </div>

          {/* ML-Powered Card */}
          <div className="bg-[#032963] rounded-lg shadow-xl p-5 border border-blue-600 flex flex-col items-center text-center transform transition-all duration-300 hover:scale-[1.03]">
            <Zap className="text-yellow-400 mb-3" size={36} />
            <h3 className="text-lg font-semibold text-gray-100 mb-2">ML-Powered</h3>
            <p className="text-gray-300 text-xs">Random Forest classifier trained on phishing patterns and URL characteristics.</p>
          </div>

          {/* Threat Detection Card */}
          <div className="bg-[#032963] rounded-lg shadow-xl p-5 border border-blue-600 flex flex-col items-center text-center transform transition-all duration-300 hover:scale-[1.03]">
            <ShieldAlert className="text-red-400 mb-3" size={36} />
            <h3 className="text-lg font-semibold text-gray-100 mb-2">Threat Detection</h3>
            <p className="text-gray-300 text-xs">Comprehensive risk assessment with detailed threat analysis.</p>
          </div>
        </section>
      ) : (
        // Analysis Results Section (visible when analysisResult is present)
        <section className="w-full max-w-5xl grid grid-cols-1 md:grid-cols-2 gap-6 animate-fade-in delay-200">
          <div className="bg-[#032963] rounded-lg shadow-xl p-5 border border-blue-600 transform transition-all duration-300 hover:scale-[1.01]">
            <h3 className="text-xl font-semibold text-gray-100 mb-4 flex items-center">
              <Shield className="mr-2 text-blue-400" size={20} /> Security Analysis
            </h3>
            <div className="mb-4">
              <p className="text-gray-400 text-xs mb-1">Analyzed URL</p>
              <p className="text-blue-300 font-medium break-all text-sm">{analysisResult?.analyzed_url || 'N/A'}</p> {/* Added optional chaining */}
            </div>
            <div className="mb-4">
              <p className="text-gray-400 text-xs mb-2">Risk Score</p>
              <div className="flex items-center">
                <div className="w-full bg-gray-700 rounded-full h-2.5">
                  <div 
                    className={`h-full rounded-full transition-all duration-500 ease-out ${getRiskBarColor(analysisResult?.risk_score || 0)}`} 
                    style={{ width: `${analysisResult?.risk_score || 0}%` }}
                  ></div>
                </div>
                <span className="ml-3 text-lg font-bold text-gray-100">{analysisResult?.risk_score || 'N/A'}%</span> {/* Added optional chaining */}
              </div>
              <p className="text-gray-400 text-xs mt-1">Higher scores indicate greater risk</p>
            </div>
            <div className="mb-4">
              <p className="text-gray-400 text-xs mb-1 flex items-center">
                <AlertTriangle className="mr-2 text-yellow-400" size={16} /> Classification
              </p>
              <p className={`text-xl font-bold ${getClassificationColor(analysisResult?.classification || '')}`}> {/* Added optional chaining */}
                {analysisResult?.classification || 'N/A'}
              </p>
              <p className="text-gray-400 text-xs mt-1 flex items-center">
                <Calendar className="mr-1" size={12} /> Analyzed on {analysisResult?.analyzed_date || 'N/A'} {/* Added optional chaining */}
              </p>
            </div>
            <div>
              <p className="text-gray-400 text-xs mb-2">Recommendation</p>
              <p className="text-gray-200 text-sm">{analysisResult?.recommendation || 'N/A'}</p> {/* Added optional chaining */}
            </div>
          </div>
          <div className="bg-[#032963] rounded-lg shadow-xl p-5 border border-blue-600 transform transition-all duration-300 hover:scale-[1.01]">
            <h3 className="text-xl font-semibold text-gray-100 mb-4 flex items-center">
              <Percent className="mr-2 text-blue-400" size={20} /> Feature Analysis
            </h3>
            {analysisResult?.feature_details && ( // Added optional chaining
              <>
                <div className="mb-3 flex items-center">
                  <Lock className="mr-2 text-blue-400" size={18} />
                  <div>
                    <p className="text-gray-300 font-medium text-sm">HTTPS Security</p>
                    <p className="text-gray-400 text-xs">{analysisResult.feature_details['HTTPS Security']}</p>
                  </div>
                  <span className={`ml-auto px-2 py-1 rounded-full text-xs font-semibold ${
                      analysisResult.feature_details['HTTPS Security'] === 'Secured' ? 'bg-green-600' : 'bg-red-600'
                  }`}>
                      {analysisResult.feature_details['HTTPS Security'] === 'Secured' ? 'Secured' : 'Unsecured'}
                  </span>
                </div>
                <div className="mb-3 flex items-center">
                  <Ruler className="mr-2 text-blue-400" size={18} />
                  <div>
                    <p className="text-gray-300 font-medium text-sm">URL Length</p>
                    <p className="text-gray-400 text-xs">{analysisResult.feature_details['URL Length']}</p>
                  </div>
                  <span className={`ml-auto px-2 py-1 rounded-full text-xs font-semibold ${
                      analysisResult.feature_details['URL Length Unsafe'] === 'No' ? 'bg-green-600' : 'bg-orange-600'
                  }`}>
                      {analysisResult.feature_details['URL Length Unsafe'] === 'No' ? 'Low Risk' : 'High Risk'}
                  </span>
                </div>
                <div className="mb-3 flex items-center">
                  <GitFork className="mr-2 text-blue-400" size={18} />
                  <div>
                    <p className="text-gray-300 font-medium text-sm">Subdomains</p>
                    <p className="text-gray-400 text-xs">{analysisResult.feature_details['Subdomains']}</p>
                  </div>
                  <span className={`ml-auto px-2 py-1 rounded-full text-xs font-semibold ${
                      analysisResult.feature_details['Subdomain Unsafe'] === 'No' ? 'bg-green-600' : 'bg-orange-600'
                  }`}>
                      {analysisResult.feature_details['Subdomain Unsafe'] === 'No' ? 'Low Risk' : 'High Risk'}
                  </span>
                </div>
                <div className="mb-3 flex items-center">
                  <Hash className="mr-2 text-blue-400" size={18} />
                  <div>
                    <p className="text-gray-300 font-medium text-sm">Special Characters</p>
                    <p className="text-gray-400 text-xs">{analysisResult.feature_details['Special Characters']}</p>
                  </div>
                  <span className="ml-auto px-2 py-1 rounded-full text-xs font-semibold bg-green-600">
                      Low Risk
                  </span>
                </div>
                <div className="mb-3 flex items-center">
                  <Globe className="mr-2 text-blue-400" size={18} />
                  <div>
                    <p className="text-gray-300 font-medium text-sm">Domain Length</p>
                    <p className="text-gray-400 text-xs">{analysisResult.feature_details['Domain Length']}</p>
                  </div>
                  <span className={`ml-auto px-2 py-1 rounded-full text-xs font-semibold ${
                      parseInt(analysisResult.feature_details['Domain Length'].split(' ')[0]) > 25 ? 'bg-orange-600' : 'bg-green-600'
                  }`}>
                      {parseInt(analysisResult.feature_details['Domain Length'].split(' ')[0]) > 25 ? 'Long' : 'Normal'}
                  </span>
                </div>
              </>
            )}
            <div className="mt-5 pt-5 border-t border-gray-700">
              <h4 className="text-base font-semibold text-gray-200 mb-2">ML Feature Summary</h4>
              <ul className="list-disc list-inside text-gray-400 text-xs space-y-1">
                <li>Random Forest model analyzes key features</li>
                <li>Advanced pattern recognition for phishing detection</li>
                <li>Real-time feature extraction and classification</li>
              </ul>
            </div>
          </div>
        </section>
      )}

      {/* NEW: External Threat Intelligence Section */}
      {/* This section will appear below the main analysis, aligning with the screenshot */}
      {(analysisResult || loadingExternal) && ( // Show this section if internal analysis is done OR external APIs are loading/done
        <section className="w-full max-w-5xl bg-[#032963] rounded-lg shadow-xl p-5 mt-6 border border-blue-600 animate-fade-in delay-300">
          <h3 className="text-xl font-semibold text-gray-100 mb-4 flex items-center">
            <Globe className="mr-2 text-blue-400" size={20} /> External Threat Intelligence
          </h3>
            {/* VirusTotal Report Card */}
            <div className="bg-blue-950 rounded-lg p-4 border border-gray-700 flex flex-col justify-between"> {/* Added flex-col justify-between */}
              <div>
                <h4 className="text-lg font-semibold text-gray-100 mb-2 flex items-center">
                  <FileText className="mr-2 text-green-400" size={16} /> VirusTotal Report
                </h4>
                {loadingExternal && !virustotalReport ? (
                  <div className="text-gray-400 text-sm flex items-center">
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Scanning with VirusTotal...
                  </div>
                ) : virustotalReport?.error ? (
                  <p className="text-red-400 text-sm border border-red-600 p-2 rounded-md">{virustotalReport.error}</p>
                ) : virustotalReport ? (
                  <div className="text-gray-300 text-sm space-y-1">
                    <p>Status: <span className="font-medium capitalize">{virustotalReport.status}</span></p>
                    <p>Malicious: <span className="font-medium text-red-400">{virustotalReport.malicious}</span></p>
                    <p>Suspicious: <span className="font-medium text-orange-400">{virustotalReport.suspicious}</span></p>
                    <p>Undetected: <span className="font-medium text-green-400">{virustotalReport.undetected}</span></p>
                    <p>Harmless: <span className="font-medium text-green-400">{virustotalReport.harmless}</span></p>
                  </div>
                ) : (
                  <p className="text-gray-400 text-sm">No VirusTotal report available.</p>
                )}
              </div>
              {virustotalReport?.reportLink && (
                  <a href={virustotalReport.reportLink} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline text-xs block mt-3 text-right">View Full Report</a>
              )}
            </div>
        </section>
      )}

      <footer className="mt-8 text-center text-gray-500 text-xs">
        <p>© 2024 SafeScan.Pro. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default App;
