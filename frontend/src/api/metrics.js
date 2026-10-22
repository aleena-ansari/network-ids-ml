import sampleMetrics from '../data/metrics.json';

// Replace this local import with `request('/metrics')` when the backend endpoint exists.
export async function fetchMetrics() {
  return sampleMetrics;
}
