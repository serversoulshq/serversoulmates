const express = require("express");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

// ── Supabase admin client (server-side only, keys never sent to browser) ──
const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // service role key — never expose this
);

// ── Rate limiting (simple in-memory, swap for redis-rate-limit in production) ──
const rateLimitMap = new Map();
function rateLimit(ip, maxReqs = 10, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > windowMs) { entry.count = 0; entry.start = now; }
  entry.count++;
  rateLimitMap.set(ip, entry);
  return entry.count <= maxReqs;
}

// ── Auth middleware — verifies Supabase JWT on every protected route ──
async function auth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  const { data: { user }, error } = await sb.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: "Invalid token" });
  req.user = user;
  next();
}

// ════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════

// Send OTP — server-side domain check
app.post("/api/send-otp", async (req, res) => {
  const ip = req.ip;
  if (!rateLimit(ip, 5, 60000)) return res.status(429).json({ error: "Too many requests. Wait a minute." });

  const { email } = req.body;
  if (!email || typeof email !== "string") return res.status(400).json({ error: "Email required" });
  if (!email.toLowerCase().trim().endsWith("@iiserb.ac.in")) {
    return res.status(403).json({ error: "Only @iiserb.ac.in emails are allowed." });
  }

  const { error } = await sb.auth.admin.generateLink({
    type: "magiclink",
    email: email.toLowerCase().trim(),
  });

  // We use signInWithOtp because generateLink needs SMTP config for magic links
  const { error: otpError } = await sb.auth.signInWithOtp({
    email: email.toLowerCase().trim(),
    options: { shouldCreateUser: true }
  });

  if (otpError) return res.status(500).json({ error: otpError.message });
  res.json({ success: true });
});

// Verify OTP
app.post("/api/verify-otp", async (req, res) => {
  const ip = req.ip;
  if (!rateLimit(ip, 10, 60000)) return res.status(429).json({ error: "Too many requests." });

  const { email, token } = req.body;
  if (!email || !token) return res.status(400).json({ error: "Email and token required" });

  const { data, error } = await sb.auth.verifyOtp({
    email: email.toLowerCase().trim(),
    token,
    type: "email"
  });

  if (error) return res.status(400).json({ error: "Invalid or expired code." });
  res.json({ session: data.session, user: data.user });
});

// Sign out
app.post("/api/signout", auth, async (req, res) => {
  await sb.auth.admin.signOut(req.headers.authorization.replace("Bearer ", ""));
  res.json({ success: true });
});

// ════════════════════════════════════════════
//  PROFILE ROUTES
// ════════════════════════════════════════════

// Get own profile
app.get("/api/profile/me", auth, async (req, res) => {
  const { data, error } = await sb
    .from("profiles")
    .select("*, photos(url, position)")
    .eq("id", req.user.id)
    .single();
  if (error) return res.status(404).json({ error: "Profile not found" });
  res.json(data);
});

// Save / update own profile
app.post("/api/profile/save", auth, async (req, res) => {
  const allowed = ["first_name", "dob", "gender", "looking_for", "year", "major", "home_state", "hostel", "prompt_question", "prompt_answer"];
  const update = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) update[key] = req.body[key];
  }
  update.id = req.user.id;
  update.email = req.user.email;

  const { error } = await sb.from("profiles").upsert(update, { onConflict: "id" });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ════════════════════════════════════════════
//  DISCOVERY ROUTES
// ════════════════════════════════════════════

// Get next batch of profiles to swipe (filtered, not already swiped)
app.get("/api/discover", auth, async (req, res) => {
  // Get current user's preferences
  const { data: me } = await sb
    .from("profiles")
    .select("gender, looking_for")
    .eq("id", req.user.id)
    .single();

  if (!me) return res.status(404).json({ error: "Complete your profile first" });

  // Get IDs already swiped
  const { data: swiped } = await sb
    .from("swipes")
    .select("swiped")
    .eq("swiper", req.user.id);

  const swipedIds = (swiped || []).map(s => s.swiped);
  swipedIds.push(req.user.id); // exclude self

  // Build gender filter
  let genderFilter = null;
  if (me.looking_for === "Men") genderFilter = "Man";
  else if (me.looking_for === "Women") genderFilter = "Woman";

  let query = sb
    .from("profiles")
    .select("id, first_name, dob, gender, year, major, hostel, home_state, prompt_question, prompt_answer, photos(url, position)")
    .not("id", "in", `(${swipedIds.join(",")})`)
    .limit(20);

  if (genderFilter) query = query.eq("gender", genderFilter);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  // Calculate age from dob
  const profiles = (data || []).map(p => ({
    ...p,
    age: p.dob ? Math.floor((Date.now() - new Date(p.dob)) / (365.25 * 86400000)) : null,
    photos: (p.photos || []).sort((a, b) => a.position - b.position)
  }));

  res.json(profiles);
});

// Record a swipe
app.post("/api/swipe", auth, async (req, res) => {
  const ip = req.ip;
  if (!rateLimit(ip, 100, 60000)) return res.status(429).json({ error: "Slow down!" });

  const { swiped_id, is_like } = req.body;
  if (!swiped_id || is_like === undefined) return res.status(400).json({ error: "Missing fields" });
  if (swiped_id === req.user.id) return res.status(400).json({ error: "Cannot swipe yourself" });

  // Insert swipe
  const { error } = await sb.from("swipes").upsert({
    swiper: req.user.id,
    swiped: swiped_id,
    is_like
  }, { onConflict: "swiper,swiped" });

  if (error) return res.status(500).json({ error: error.message });

  // Check for mutual match
  let matched = false;
  if (is_like) {
    const { data: theirSwipe } = await sb
      .from("swipes")
      .select("id")
      .eq("swiper", swiped_id)
      .eq("swiped", req.user.id)
      .eq("is_like", true)
      .single();

    if (theirSwipe) {
      // Create match (store with consistent ordering)
      const [u1, u2] = [req.user.id, swiped_id].sort();
      await sb.from("matches").upsert({ user1: u1, user2: u2 }, { onConflict: "user1,user2" });
      matched = true;
    }
  }

  res.json({ success: true, matched });
});

// ════════════════════════════════════════════
//  MATCHES ROUTES
// ════════════════════════════════════════════

// Get all matches with profile info
app.get("/api/matches", auth, async (req, res) => {
  const uid = req.user.id;

  const { data: matches, error } = await sb
    .from("matches")
    .select("id, user1, user2, created_at")
    .or(`user1.eq.${uid},user2.eq.${uid}`)
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  // Get other user's profile for each match
  const enriched = await Promise.all((matches || []).map(async m => {
    const otherId = m.user1 === uid ? m.user2 : m.user1;
    const { data: profile } = await sb
      .from("profiles")
      .select("id, first_name, dob, hostel, photos(url, position)")
      .eq("id", otherId)
      .single();

    // Get last message
    const { data: lastMsg } = await sb
      .from("messages")
      .select("content, created_at, sender_id")
      .eq("match_id", m.id)
      .order("created_at", { ascending: false })
      .limit(1)
      .single();

    return {
      match_id: m.id,
      matched_at: m.created_at,
      profile: profile ? {
        ...profile,
        age: profile.dob ? Math.floor((Date.now() - new Date(profile.dob)) / (365.25 * 86400000)) : null,
        photo: (profile.photos || []).sort((a, b) => a.position - b.position)[0]?.url || null
      } : null,
      last_message: lastMsg || null
    };
  }));

  res.json(enriched);
});

// ════════════════════════════════════════════
//  MESSAGES ROUTES
// ════════════════════════════════════════════

// Get messages for a match
app.get("/api/messages/:matchId", auth, async (req, res) => {
  const { matchId } = req.params;

  // Verify user is part of this match
  const { data: match } = await sb
    .from("matches")
    .select("user1, user2")
    .eq("id", matchId)
    .single();

  if (!match || (match.user1 !== req.user.id && match.user2 !== req.user.id)) {
    return res.status(403).json({ error: "Not your match" });
  }

  const { data, error } = await sb
    .from("messages")
    .select("id, sender_id, content, created_at")
    .eq("match_id", matchId)
    .order("created_at", { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Send a message
app.post("/api/messages/:matchId", auth, async (req, res) => {
  const ip = req.ip;
  if (!rateLimit(ip, 60, 60000)) return res.status(429).json({ error: "Too many messages" });

  const { matchId } = req.params;
  const { content } = req.body;

  if (!content || content.trim().length === 0) return res.status(400).json({ error: "Empty message" });
  if (content.length > 1000) return res.status(400).json({ error: "Message too long" });

  // Verify membership
  const { data: match } = await sb
    .from("matches")
    .select("user1, user2")
    .eq("id", matchId)
    .single();

  if (!match || (match.user1 !== req.user.id && match.user2 !== req.user.id)) {
    return res.status(403).json({ error: "Not your match" });
  }

  const { data, error } = await sb.from("messages").insert({
    match_id: matchId,
    sender_id: req.user.id,
    content: content.trim()
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════
//  PAGE ROUTES
// ════════════════════════════════════════════

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/matches", (req, res) => res.sendFile(path.join(__dirname, "matches.html")));
app.get("/chat", (req, res) => res.sendFile(path.join(__dirname, "chat.html")));
app.get("/profile", (req, res) => res.sendFile(path.join(__dirname, "profile.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(__dirname, "settings.html")));
app.get("/onboarding", (req, res) => res.sendFile(path.join(__dirname, "onboarding.html")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server Souls running on port " + PORT));
