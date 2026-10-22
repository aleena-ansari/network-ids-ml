export const featureFields = [
  ['duration', 'number'], ['protocol_type', 'text'], ['service', 'text'], ['flag', 'text'],
  ['src_bytes', 'number'], ['dst_bytes', 'number'], ['land', 'number'], ['wrong_fragment', 'number'],
  ['urgent', 'number'], ['hot', 'number'], ['num_failed_logins', 'number'], ['logged_in', 'number'],
  ['num_compromised', 'number'], ['root_shell', 'number'], ['su_attempted', 'number'], ['num_root', 'number'],
  ['num_file_creations', 'number'], ['num_shells', 'number'], ['num_access_files', 'number'], ['num_outbound_cmds', 'number'],
  ['is_host_login', 'number'], ['is_guest_login', 'number'], ['count', 'number'], ['srv_count', 'number'],
  ['serror_rate', 'number'], ['srv_serror_rate', 'number'], ['rerror_rate', 'number'], ['srv_rerror_rate', 'number'],
  ['same_srv_rate', 'number'], ['diff_srv_rate', 'number'], ['srv_diff_host_rate', 'number'], ['dst_host_count', 'number'],
  ['dst_host_srv_count', 'number'], ['dst_host_same_srv_rate', 'number'], ['dst_host_diff_srv_rate', 'number'],
  ['dst_host_same_src_port_rate', 'number'], ['dst_host_srv_diff_host_rate', 'number'], ['dst_host_serror_rate', 'number'],
  ['dst_host_srv_serror_rate', 'number'], ['dst_host_rerror_rate', 'number'], ['dst_host_srv_rerror_rate', 'number'],
];

const common = { protocol_type: 'tcp', service: 'http', flag: 'SF', logged_in: 1, count: 1, srv_count: 1,
  same_srv_rate: 1, dst_host_count: 1, dst_host_srv_count: 1, dst_host_same_srv_rate: 1 };
export const sampleRows = [
  { ...common, duration: 0, src_bytes: 181, dst_bytes: 5450, src_ip: '192.168.1.15', dst_ip: '10.0.0.5' },
  { ...common, protocol_type: 'tcp', service: 'private', flag: 'S0', duration: 0, src_bytes: 0, dst_bytes: 0,
    count: 198, srv_count: 1, serror_rate: 1, srv_serror_rate: 1, same_srv_rate: 0.01, dst_host_count: 255,
    dst_host_srv_count: 1, dst_host_same_srv_rate: 0.01, dst_host_serror_rate: 1, dst_host_srv_serror_rate: 1,
    src_ip: '10.0.0.24', dst_ip: '10.0.0.8' },
];

export function parseCsvRow(line) {
  const values = line.split(',').map((value) => value.trim());
  const row = Object.fromEntries(featureFields.map(([key, type], index) => [key,
    type === 'number' ? Number(values[index] || 0) : (values[index] || '')]));
  return row;
}
