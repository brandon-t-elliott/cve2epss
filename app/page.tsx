'use client';

import { useEffect, useRef, useState } from 'react';
import './style.css';

export default function Home() {
  const [cveId, setCveId] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ epss: string; percentile: string; date: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  const rateLimitTimestamps = useRef<number[]>([]);

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

    const now = Date.now();
    const last2s = rateLimitTimestamps.current.filter(ts => now - ts < 2000);
    const last1hr = rateLimitTimestamps.current.filter(ts => now - ts < 60 * 60 * 1000);

    if (last2s.length > 0 || last1hr.length >= 100) {
      setError('Too many requests. Please wait before sending more.');
      return;
    }

    rateLimitTimestamps.current.push(now);

    setLoading(true);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      const safeCve = encodeURIComponent(cveId);
      const res = await fetch(`https://api.first.org/data/v1/epss?cve=${safeCve}`, {
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const data = await res.json();

      if (!res.ok || !data.data || data.data.length === 0) {
        setError('No data found for the specified CVE.');
        return;
      }

      const { epss, percentile, date } = data.data[0];

      const floatPattern = /^0\.\d+$/;
      const datePattern = /^\d{4}-\d{2}-\d{2}$/;

      if (!floatPattern.test(epss) || !floatPattern.test(percentile) || !datePattern.test(date)) {
        setError('Invalid data received from the EPSS API.');
        return;
      }

      setResult({ epss, percentile, date });
    } catch (err: any) {
      if (err.name === 'AbortError') {
        setError('EPSS API request timed out.');
      } else {
        setError('An unexpected error occurred.');
      }
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
              <div className="mb-4">
                <p className="metric">
                  Percentile: <span>{formatPercent(result.percentile)}</span>
                </p>
                <p className="description">
                  How this CVE compares to others (percentage of vulnerabilities that are scored less than or equal to it).
                </p>
              </div>
              <div>
                <p className="description" style={{ textAlign: 'center', color: 'var(--highlight)' }}>
                  as of {result.date}
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
