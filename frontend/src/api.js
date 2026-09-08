const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

async function request(path, { method = "GET", body, token, isForm = false } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (!isForm) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    body: isForm ? body : body ? JSON.stringify(body) : undefined,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export const api = {
  register: (name, email, password) => request("/api/auth/register", { method: "POST", body: { name, email, password } }),
  login: (email, password) => request("/api/auth/login", { method: "POST", body: { email, password } }),
  uploadPcap: (file, token) => {
    const formData = new FormData();
    formData.append("pcap", file);
    return request("/api/pcap/upload", { method: "POST", body: formData, token, isForm: true });
  },
  history: (token) => request("/api/pcap/history", { token }),
};

export { API_BASE_URL };
