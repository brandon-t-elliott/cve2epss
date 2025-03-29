'use client';

import { useEffect, useState } from 'react';
import './style.css';

export default function Home() {
  const [cveId, setCveId] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ epss: string; percentile: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
  }, [darkMode]);

  const handleSubmit = async () => {
    setError('');
    setResult(null);

    const regex = /^CVE-\d{4}-\d{4,10}$/;
    if (!regex.test(cveId)) {
      setError('Invalid CVE format. Example: CVE-1999-0001');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`/api/query?cve=${encodeURIComponent(cveId)}`);
      const data = await res.json();
      if (res.ok) {
        setResult(data);
      } else {
        setError(data.error || 'API Error');
      }
    } catch (err) {
      setError('Request failed.');
    } finally {
      setLoading(false);
    }
  };

  const formatPercent = (value: string) => {
    const num = parseFloat(value);
    if (isNaN(num)) return value;
    return `${(num * 100).toFixed(2)}%`;
  };

  return (
    <main className="container">
      <div className="mode-toggle-wrapper">
        <button className="toggle-button" onClick={() => setDarkMode(prev => !prev)}>
          {darkMode ? 'Light Mode' : 'Dark Mode'}
        </button>
      </div>

      <div className="main-content">
        <div className="card">
          <div className="card-header">
            <h1 className="card-title">CVE to EPSS</h1>
          </div>

          <div className="form-group">
            <input
              type="text"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="Enter CVE ID (e.g., CVE-1999-0001)"
            />
            <button
              className="submit-button"
              onClick={handleSubmit}
              disabled={loading}
              style={{ opacity: loading ? 0.7 : 1 }}
            >
              {loading ? 'Looking up...' : 'EPSS Lookup'}
            </button>
          </div>

          {error && <p className="error">{error}</p>}

          {result && (
            <div className="results">
              <h2>Results</h2>
              <div className="mb-4">
                <p className="metric">
                  EPSS: <span>{formatPercent(result.epss)}</span>
                </p>
                <p className="description">
                  EPSS (Exploit Prediction Scoring System) estimates the likelihood that a vulnerability will be exploited in the wild in the next 30 days.
                </p>
              </div>
              <div>
                <p className="metric">
                  Percentile: <span>{formatPercent(result.percentile)}</span>
                </p>
                <p className="description">
                  How this CVE compares to others (percentage of vulnerabilities that are scored less than or equal to it).
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      <footer style={{ padding: '2rem 0', fontSize: '0.60rem', textAlign: 'center', color: 'var(--muted)' }}>
        <p>
          <a
            href="https://www.linkedin.com/in/brandon-t-elliott/"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--highlight)', textDecoration: 'underline' }}
          >
            Contact
          </a>
        </p>
        <p style={{ marginTop: '0.5rem' }}>
          Disclaimer: This site utilizes the{' '}
          <a
            href="https://www.first.org/epss/api"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--highlight)', textDecoration: 'underline' }}
          >
            EPSS API
          </a>{' '}
          and makes no warranties regarding the availability, accuracy, or completeness of the information provided.
          <br />
          Use at your own risk.
        </p>
      </footer>
    </main>
  );
}
