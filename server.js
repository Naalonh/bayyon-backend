import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import { createClient } from "@supabase/supabase-js";
import nodemailer from "nodemailer";
import { Server } from "socket.io";
import http from "http";
import cors from "cors";
const app = express();
app.use(
  cors({
    origin: "https://bayyon.netlify.app",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

const PORT = process.env.PORT || 3000;

/* =========================
HELPER FUNCTIONS 👈 HERE
========================= */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
/* =========================
   BASIC SETUP
========================= */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
  maxHttpBufferSize: 10 * 1024 * 1024,
});

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("delete_message", async ({ messageId, userId }) => {
    if (!/^[0-9a-fA-F-]{36}$/.test(messageId)) return;

    // 🔐 Only delete own messages
    const { data: msg } = await supabase
      .from("messages")
      .select("user_id")
      .eq("id", messageId)
      .single();

    if (!msg || msg.user_id !== userId) return;

    await supabase.from("messages").delete().eq("id", messageId);

    io.emit("message_deleted", { messageId });
  });

  socket.on("send_reaction", async ({ messageId, userId, emoji }) => {
    if (!/^[0-9a-fA-F-]{36}$/.test(messageId)) return;

    // Save / update reaction
    const { error } = await supabase
      .from("message_reactions")
      .upsert(
        { message_id: messageId, user_id: userId, emoji },
        { onConflict: "message_id,user_id" },
      );

    if (error) {
      console.error("Reaction error:", error);
      return;
    }

    // 🔑 FETCH USER INFO (THIS WAS MISSING)
    const { data: user } = await supabase
      .from("users")
      .select("game_nickname, avatar_url")
      .eq("id", userId)
      .single();

    io.emit("receive_reaction", {
      messageId,
      userId,
      emoji,
      game_nickname: user?.game_nickname || "Unknown",
      avatar: user?.avatar_url || null,
    });
  });

  socket.on("send_message", async (data) => {
    const { userId, text, replyTo } = data;

    const { data: row, error } = await supabase
      .from("messages")
      .insert({
        user_id: userId,
        content: text,
        reply_to: replyTo || null,
      })
      .select()
      .single();

    if (error) {
      console.error("Insert error:", error);
      return;
    }

    const { data: fullMsg, error: joinError } = await supabase
      .from("messages")
      .select(
        `
        id,
        content,
        created_at,
        reply_to,
        users (
        id,
        game_nickname,
        avatar_url
        ),
        reply:reply_to (
        id,
        content,
        users (
        game_nickname
        )
        )
        `,
      )
      .eq("id", row.id)
      .single();

    if (joinError || !fullMsg?.users) {
      console.error("Join error:", joinError);
      return;
    }

    io.emit("receive_message", {
      message_id: fullMsg.id,
      user_id: fullMsg.users.id,
      game_nickname: fullMsg.users.game_nickname, // ✅
      avatar: fullMsg.users.avatar_url,
      text: fullMsg.content,
      reply: fullMsg.reply
        ? {
            id: fullMsg.reply.id,
            username: fullMsg.reply.users.game_nickname,
            text: fullMsg.reply.content,
          }
        : null,
      time: new Date(fullMsg.created_at).getTime(),
    });
  });

  socket.on("remove_reaction", async ({ messageId, userId }) => {
    const { error } = await supabase
      .from("message_reactions")
      .delete()
      .eq("message_id", messageId)
      .eq("user_id", userId);

    if (error) {
      console.error("Remove reaction error:", error);
      return;
    }

    io.emit("reaction_removed", {
      messageId,
      userId,
    });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

app.use(express.static("public"));
app.use(express.json({ limit: "10mb" }));

/* =========================
   SUPABASE
========================= */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

async function requireAdmin(req, res, next) {
  const userId = req.headers["x-user-id"];

  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { data: user } = await supabase
    .from("users")
    .select("role")
    .eq("id", userId)
    .single();

  if (!user || !["admin", "leader", "developer"].includes(user.role)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  next();
}

/* =========================
   ROUTES
========================= */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/register.html"));
});

app.get("/chat/messages", async (req, res) => {
  const { data, error } = await supabase
    .from("messages")
    .select(
      `
      id,
      content,
      created_at,
      users (
        id,
        game_nickname,
        avatar_url
      ),
      reply:reply_to (
        id,
        content,
        users ( game_nickname )
      ),
      message_reactions (
        emoji,
        user_id,
        users (
          game_nickname,
          avatar_url
        )
      )
    `,
    )
    .order("created_at", { ascending: true })
    .limit(50);

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get("/lookup", async (req, res) => {
  const { roleid } = req.query;
  if (!roleid) return res.status(400).json({ error: "Missing roleid" });

  try {
    const apiRes = await fetch(
      `https://pay.neteasegames.com/gameclub/bloodstrike/-1/login-role?roleid=${encodeURIComponent(
        roleid,
      )}&client_type=gameclub`,
    );

    const data = await apiRes.json();

    if (data.code === "0000" && data.data?.rolename) {
      return res.json({ nickname: data.data.rolename });
    }

    res.status(404).json({ error: "Role not found" });
  } catch {
    res.status(500).json({ error: "API error" });
  }
});

app.post("/register", async (req, res) => {
  const { username, email, gender, age, game_id, game_nickname, password } =
    req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    const { error } = await supabase.from("users").insert({
      username: username.trim().toLowerCase(),
      email,
      gender,
      age,
      game_id,
      game_nickname,
      password_hash,
      role: "member",
      is_reviewed: false,
    });

    if (error) throw error;

    res.json({
      success: true,
      message: "Registered successfully. Waiting for admin review.",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/forgot-password", async (req, res) => {
  let { email } = req.body;
  email = email.trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Email required" });

  const otp = generateOTP();
  const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  // 1. Update user with OTP
  const { data, error } = await supabase
    .from("users")
    .update({
      reset_otp: otp,
      reset_otp_expires: expires,
    })
    .eq("email", email)
    .select()
    .single();

  if (error || !data) {
    return res.status(400).json({ error: "Email not found" });
  }

  // 2. Send OTP email
  try {
    await mailer.sendMail({
      from: `"BYN OFFICIAL" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "BYN Clan – Password Reset OTP",
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>BYN Clan Password Reset</h2>
          <p>You requested to reset your password.</p>
          <p><strong>Your OTP code:</strong></p>
          <h1 style="letter-spacing:4px">${otp}</h1>
          <p>This code will expire in <b>10 minutes</b>.</p>
          <hr />
          <p style="font-size:12px;color:#777">
            If you didn’t request this, please ignore this email.
          </p>
        </div>
      `,
    });

    res.json({ success: true, message: "OTP sent to your email" });
  } catch (mailError) {
    console.error("Email error:", mailError);
    res.status(500).json({ error: "Failed to send OTP email" });
  }
});

app.post("/reset-password", async (req, res) => {
  let { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: "Missing data" });
  }

  email = email.trim().toLowerCase();
  otp = String(otp).trim();

  const { data: user, error } = await supabase
    .from("users")
    .select("id")
    .eq("email", email)
    .eq("reset_otp", otp)
    .gt("reset_otp_expires", new Date().toISOString())
    .single();

  if (error || !user) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  // 4️⃣ Hash new password
  const newHash = await bcrypt.hash(newPassword, 10);

  // 5️⃣ Update password + clear OTP
  await supabase
    .from("users")
    .update({
      password_hash: newHash,
      reset_otp: null,
      reset_otp_expires: null,
    })
    .eq("id", user.id);

  res.json({ success: true, message: "Password reset successful" });
});

app.post("/login", async (req, res) => {
  let { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({
      code: "BAD_REQUEST",
      message: "Missing credentials",
    });
  }

  identifier = identifier.trim().toLowerCase();
  const isEmail = identifier.includes("@");

  const { data: user, error } = await supabase
    .from("users")
    .select("id, password_hash, is_reviewed, role")
    .or(isEmail ? `email.eq.${identifier}` : `username.eq.${identifier}`)
    .single();

  if (error || !user) {
    return res.status(400).json({
      code: "USER_NOT_FOUND",
      message: "Invalid credentials",
    });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.status(400).json({
      code: "WRONG_PASSWORD",
      message: "Invalid credentials",
    });
  }

  // ⛔ Block unreviewed users
  if (user.is_reviewed === false) {
    return res.status(403).json({
      code: "NOT_REVIEWED",
      message: "Account pending admin approval",
    });
  }

  res.json({
    success: true,
    userId: user.id,
    role: user.role,
  });
});

app.get("/profile/:id", async (req, res) => {
  const { id } = req.params;

  const { data, error } = await supabase
    .from("users")
    .select(
      `
      id,
      username,
      email,
      gender,
      age,
      game_id,
      game_nickname,
      role,
      real_name,
      bio,
      avatar_url,
      banner_url,
      social_links,
      device,
      created_at
      `,
    )
    .eq("id", id)
    .single();

  if (error) return res.status(404).json({ error: "User not found" });

  res.json(data);
});

app.get("/profile/:id/socials", async (req, res) => {
  const { id } = req.params;

  const { data, error } = await supabase
    .from("user_social_links")
    .select("platform, url")
    .eq("user_id", id);

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post("/profile/socials/save", async (req, res) => {
  const { userId, socials } = req.body;

  if (!userId || !Array.isArray(socials)) {
    return res.status(400).json({ error: "Invalid data" });
  }

  // Remove old socials
  await supabase.from("user_social_links").delete().eq("user_id", userId);

  // Insert new ones
  if (socials.length > 0) {
    const rows = socials.map((s) => ({
      user_id: userId,
      platform: s.platform,
      url: s.url,
    }));

    const { error } = await supabase.from("user_social_links").insert(rows);

    if (error) return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

app.post("/upload-avatar", async (req, res) => {
  try {
    const { userId, imageBase64 } = req.body;

    console.log("UPLOAD AVATAR:", {
      userId,
      size: imageBase64?.length,
    });

    if (!userId || !imageBase64) {
      return res.status(400).json({ error: "Missing image data" });
    }

    const buffer = Buffer.from(imageBase64, "base64");
    const fileName = `${userId}.png`;

    const { data, error } = await supabase.storage
      .from("avatars")
      .upload(fileName, buffer, {
        contentType: "image/png",
        upsert: true,
      });

    console.log("STORAGE RESULT:", { data, error });

    if (error) throw error;

    const { data: urlData } = supabase.storage
      .from("avatars")
      .getPublicUrl(fileName);

    res.json({ avatar_url: urlData.publicUrl });
  } catch (err) {
    console.error("UPLOAD AVATAR ERROR 🔥", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/upload-banner", async (req, res) => {
  const { userId, imageBase64 } = req.body;
  if (!userId || !imageBase64)
    return res.status(400).json({ error: "Missing data" });

  const buffer = Buffer.from(imageBase64, "base64");
  const fileName = `${userId}.png`;

  const { error } = await supabase.storage
    .from("banners")
    .upload(fileName, buffer, {
      contentType: "image/png",
      upsert: true,
    });

  if (error) return res.status(500).json({ error: error.message });

  const { data } = supabase.storage.from("banners").getPublicUrl(fileName);

  await supabase
    .from("users")
    .update({ banner_url: data.publicUrl })
    .eq("id", userId);

  res.json({ banner_url: data.publicUrl });
});

app.post("/profile/device", async (req, res) => {
  const { userId, device } = req.body;

  if (!userId || !device) {
    return res.status(400).json({ error: "Missing data" });
  }

  await supabase.from("users").update({ device }).eq("id", userId);

  res.json({ success: true });
});

app.post("/profile/save", async (req, res) => {
  const {
    userId,
    real_name,
    age,
    bio,
    device,
    gender,
    avatar_url,
    banner_url,
  } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "Missing userId" });
  }

  // 🔐 REMOVE undefined / empty values
  const updateData = Object.fromEntries(
    Object.entries({
      real_name,
      age,
      bio,
      device,
      gender,
      avatar_url,
      banner_url,
    }).filter(([_, v]) => v !== undefined && v !== ""),
  );

  const { error } = await supabase
    .from("users")
    .update(updateData)
    .eq("id", userId);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

app.post("/profile/weapons/save", async (req, res) => {
  const { userId, weapons } = req.body;

  if (!userId || !Array.isArray(weapons)) {
    return res.status(400).json({ error: "Invalid data" });
  }

  // 1. Remove old weapons
  await supabase.from("user_weapons").delete().eq("user_id", userId);

  if (weapons.length === 0) {
    return res.json({ success: true });
  }

  // 2. Get weapon IDs from names
  const { data: weaponRows, error } = await supabase
    .from("weapons")
    .select("id")
    .in("name", weapons);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  // 3. Insert user weapons
  const rows = weaponRows.map((w) => ({
    user_id: userId,
    weapon_id: w.id,
  }));

  await supabase.from("user_weapons").insert(rows);

  res.json({ success: true });
});

app.get("/profile/:id/weapons", async (req, res) => {
  const { id } = req.params;

  const { data, error } = await supabase
    .from("user_weapons")
    .select("weapons(name)")
    .eq("user_id", id);

  if (error) return res.status(500).json({ error: error.message });

  res.json(data.map((w) => w.weapons.name));
});

app.get("/weapons", async (req, res) => {
  const { data, error } = await supabase
    .from("weapons")
    .select("name, weapon_categories(name)")
    .order("name");

  if (error) return res.status(500).json({ error: error.message });

  res.json(
    data.map((w) => ({
      name: w.name,
      category: w.weapon_categories.name,
    })),
  );
});

app.get("/api/members", async (req, res) => {
  const { data, error } = await supabase
    .from("users")
    .select(
      `
      id,
      game_id,
      game_nickname,
      real_name,
      role,
      avatar_url,
      gender,
      is_reviewed
    `,
    )
    .eq("is_reviewed", true)
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json(data);
});

app.get("/api/admin/requests", requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from("users")
    .select("id, game_id, game_nickname, username, created_at")
    .eq("is_reviewed", false)
    .order("created_at", { ascending: true });

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json(data);
});

app.post("/api/admin/requests/accept", requireAdmin, async (req, res) => {
  const { userId } = req.body;

  const { error } = await supabase
    .from("users")
    .update({ is_reviewed: true })
    .eq("id", userId);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

app.post("/api/admin/requests/reject", requireAdmin, async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "Missing userId" });
  }

  const { error } = await supabase.from("users").delete().eq("id", userId);

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

/* =========================
   START SERVER
========================= */
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

