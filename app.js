// ── app.js — shared auth + API helpers loaded by every page ──
// Supabase is loaded from CDN in each HTML file.
// This file handles session management and provides api() fetch wrapper.

const SUPABASE_URL = "https://yrrytfnfklqlmtsgpcvi.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inlycnl0Zm5ma2xxbG10c2dwY3ZpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU2NDY1ODUsImV4cCI6MjA5MTIyMjU4NX0.wBPIR3x-b6rig0a32kdH6CwpszEKNj6qXZvrKGwKhWU";

// Init Supabase client (used for auth session/realtime only — data goes through server)
const _sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Get current session token
async function getToken() {
  const { data: { session } } = await _sb.auth.getSession();
  return session?.access_token || null;
}

// Auth-aware fetch wrapper — always sends JWT
async function api(path, options = {}) {
  const token = await getToken();
  const res = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

// Guard — redirect to login if not authenticated
async function requireAuth() {
  const token = await getToken();
  if (!token) { window.location.href = "/"; return null; }
  return token;
}

// Sign out
async function signOut() {
  const token = await getToken();
  if (token) {
    await fetch("/api/signout", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    }).catch(() => {});
  }
  await _sb.auth.signOut();
  window.location.href = "/";
}

// Get age from dob string
function calcAge(dob) {
  if (!dob) return null;
  return Math.floor((Date.now() - new Date(dob)) / (365.25 * 86400000));
}

// Format relative time
function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}
