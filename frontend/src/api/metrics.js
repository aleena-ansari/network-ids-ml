import { BASE_URL } from './client.js';

// Reads the saved offline evaluation from the backend (GET /metrics).
// If the backend is down this throws, and the dashboard hides the panel
// instead of showing made-up numbers.
export async function fetchMetrics() {
  const response = await fetch(`${BASE_URL}/metrics`);
  if (!response.ok) throw new Error(`Metrics request failed (${response.status})`);
  const body = await response.json();
  if (!body.summary) throw new Error('Backend /metrics response has no summary');
  return body.summary;
}