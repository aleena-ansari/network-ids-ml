import { request } from './client.js';

export const getAlerts = () => request('/alerts');
export async function getAlert(id) {
  const alert = await request(`/alerts/${encodeURIComponent(id)}`);
  if (!alert) throw new Error(`Alert ${id} was not found.`);
  return alert;
}
export const updateStatus = (id, status) => request(`/alerts/${encodeURIComponent(id)}/status`, {
  method: 'PUT', body: JSON.stringify({ status }),
});
export const predict = (payload) => request('/predict', { method: 'POST', body: JSON.stringify(payload) });
