const express = require('express');
const cors    = require('cors');
const { Resend } = require('resend');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Resend setup ─────────────────────────────────────────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY);

// ─── Supabase client ──────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─── Helper: generate 6-digit OTP ─────────────────────────────────────────────
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ─── POST /auth/send-otp ──────────────────────────────────────────────────────
app.post('/auth/send-otp', async (req, res) => {
  const { email, device_id } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ message: 'Invalid email address.' });
  }

  if (!device_id) {
    return res.status(400).json({ message: 'Device ID is required.' });
  }

  // ── 1. Check email exists in registered_voters ────────────────────────────
  const { data: voter, error: voterError } = await supabase
    .from('registered_voters')
    .select('email')
    .ilike('email', email.trim())
    .single();

  if (voterError || !voter) {
    return res.status(403).json({
      message: 'This email is not registered in the NIMC voter database. Please contact NIMC.',
    });
  }

  // ── 2. Check device binding ───────────────────────────────────────────────
  const { data: binding } = await supabase
    .from('device_bindings')
    .select('device_id')
    .ilike('email', email.trim())
    .single();

  if (binding && binding.device_id !== device_id) {
    return res.status(403).json({
      message: 'This account is bound to a different device. Please contact NIMC to reset access.',
    });
  }

  // ── 3. Generate & store OTP ───────────────────────────────────────────────
  const otp       = generateOtp();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  const { error: dbError } = await supabase
    .from('otp_codes')
    .upsert(
      { email, otp, expires_at: expiresAt.toISOString(), verified: false },
      { onConflict: 'email' }
    );

  if (dbError) {
    console.error('Supabase error:', dbError);
    return res.status(500).json({ message: 'Failed to store OTP.' });
  }

  // ── 4. Send OTP email ─────────────────────────────────────────────────────
  const { error: emailError } = await resend.emails.send({
    from: 'NIMC Voting Portal <onboarding@resend.dev>',
    to: email,
    subject: 'Your NIMC Voting OTP',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;">
        <div style="background:#004D2A;padding:24px;text-align:center;">
          <h1 style="color:#C8972B;margin:0;letter-spacing:4px;">NIMC</h1>
          <p style="color:rgba(255,255,255,0.75);margin:4px 0 0;font-size:12px;">
            National Identity Management Commission
          </p>
        </div>
        <div style="background:#F7F8FA;padding:32px;">
          <p style="color:#0D1117;font-size:15px;">Your one-time passcode is:</p>
          <div style="background:#fff;border:2px solid #00703C;border-radius:12px;padding:20px;text-align:center;margin:16px 0;">
            <span style="font-size:36px;font-weight:800;letter-spacing:10px;color:#004D2A;">${otp}</span>
          </div>
          <p style="color:#6B7280;font-size:13px;">
            This code expires in <strong>10 minutes</strong>.<br/>
            Never share this code with anyone.
          </p>
        </div>
        <div style="background:#004D2A;padding:12px;text-align:center;">
          <p style="color:rgba(255,255,255,0.5);font-size:11px;margin:0;">
            © 2026 NIMC — Federal Republic of Nigeria
          </p>
        </div>
      </div>
    `,
  });

  if (emailError) {
    console.error('Resend error:', emailError);
    return res.status(500).json({ message: 'Failed to send OTP email.' });
  }

  return res.json({ message: 'OTP sent successfully.' });
});

// ─── POST /auth/verify-otp ────────────────────────────────────────────────────
app.post('/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required.' });
  }

  const { data, error } = await supabase
    .from('otp_codes')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !data) {
    return res.status(400).json({ message: 'No OTP found for this email.' });
  }

  if (new Date() > new Date(data.expires_at)) {
    return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
  }

  if (data.verified) {
    return res.status(400).json({ message: 'OTP has already been used.' });
  }

  if (data.otp !== otp) {
    return res.status(400).json({ message: 'Incorrect OTP. Please try again.' });
  }

  await supabase
    .from('otp_codes')
    .update({ verified: true })
    .eq('email', email);

  return res.json({ message: 'OTP verified successfully.', email });
});

// ─── POST /auth/verify-nin ────────────────────────────────────────────────────
// Called after OTP is verified — this is where device binding is saved
app.post('/auth/verify-nin', async (req, res) => {
  const { email, nin, device_id } = req.body;

  if (!email || !nin) {
    return res.status(400).json({ message: 'Email and NIN are required.' });
  }

  if (!device_id) {
    return res.status(400).json({ message: 'Device ID is required.' });
  }

  if (!/^\d{11}$/.test(nin)) {
    return res.status(400).json({ message: 'NIN must be exactly 11 digits.' });
  }

  // ── 1. Verify NIN exists and is eligible ──────────────────────────────────
  const { data, error } = await supabase
    .from('registered_voters')
    .select('nin, first_name, last_name, email, is_eligible')
    .eq('nin', nin)
    .single();

  if (error || !data) {
    return res.status(404).json({ message: 'NIN not found in the voter register. Please contact NIMC.' });
  }

  if (!data.is_eligible) {
    return res.status(403).json({ message: 'This NIN has been marked ineligible to vote.' });
  }

  // ── 2. Bind device to this voter (upsert — safe to call multiple times) ───
  const { error: bindError } = await supabase
    .from('device_bindings')
    .upsert(
      {
        email:      email.toLowerCase().trim(),
        nin,
        device_id,
        bound_at:   new Date().toISOString(),
      },
      { onConflict: 'email' }
    );

  if (bindError) {
    console.error('Device bind error:', bindError);
    return res.status(500).json({ message: 'Failed to bind device.' });
  }

  return res.json({
    message: 'NIN verified and device bound successfully.',
    full_name: `${data.first_name} ${data.last_name}`,
  });
});

// ─── POST /auth/reset-device ──────────────────────────────────────────────────
// FOR TESTING ONLY — removes device binding so voter can log in from any device
app.post('/auth/reset-device', async (req, res) => {
  const { email, admin_key } = req.body;

  // Simple admin key guard — set ADMIN_KEY as a Render env variable
  if (admin_key !== process.env.ADMIN_KEY) {
    return res.status(401).json({ message: 'Unauthorized.' });
  }

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  const { error } = await supabase
    .from('device_bindings')
    .delete()
    .ilike('email', email.trim());

  if (error) {
    return res.status(500).json({ message: 'Failed to reset device binding.' });
  }

  return res.json({ message: `Device binding reset for ${email}. They can now log in from any device.` });
});

// ─── GET /election/data ───────────────────────────────────────────────────────
// Returns all positions and their candidates from Supabase
app.get('/election/data', async (req, res) => {
  const { data: positions, error: posErr } = await supabase
    .from('positions')
    .select('id, title, priority')
    .order('priority', { ascending: true });

  if (posErr) return res.status(500).json({ message: 'Failed to load positions.' });

  const { data: candidates, error: canErr } = await supabase
    .from('candidates')
    .select('id, position_id, name, party');

  if (canErr) return res.status(500).json({ message: 'Failed to load candidates.' });

  // Group candidates under their positions
  const result = positions.map(pos => ({
    ...pos,
    candidates: candidates.filter(c => c.position_id === pos.id),
  }));

  return res.json({ positions: result });
});

// ─── POST /election/check-voted ───────────────────────────────────────────────
app.post('/election/check-voted', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required.' });

  const { data } = await supabase
    .from('votes')
    .select('id')
    .eq('email', email)
    .limit(1);

  return res.json({ has_voted: data && data.length > 0 });
});

// ─── POST /election/submit-vote ───────────────────────────────────────────────
app.post('/election/submit-vote', async (req, res) => {
  const { email, votes } = req.body; // votes = { position_id: candidate_id }

  if (!email || !votes || Object.keys(votes).length === 0) {
    return res.status(400).json({ message: 'Email and votes are required.' });
  }

  // Check voter hasn't already voted
  const { data: existing } = await supabase
    .from('votes')
    .select('id')
    .eq('email', email)
    .limit(1);

  if (existing && existing.length > 0) {
    return res.status(403).json({ message: 'You have already submitted your vote.' });
  }

  // Insert one row per position
  const rows = Object.entries(votes).map(([position_id, candidate_id]) => ({
    email,
    position_id,
    candidate_id,
    voted_at: new Date().toISOString(),
  }));

  const { error } = await supabase.from('votes').insert(rows);

  if (error) {
    console.error('Vote insert error:', error);
    return res.status(500).json({ message: 'Failed to record vote.' });
  }

  return res.json({ message: 'Vote submitted successfully.' });
});

// ─── GET /election/results ────────────────────────────────────────────────────
// Powers the leaderboard dashboard — returns vote counts per candidate
app.get('/election/results', async (req, res) => {
  // Positions ordered by priority
  const { data: positions, error: posErr } = await supabase
    .from('positions')
    .select('id, title, priority')
    .order('priority', { ascending: true });

  if (posErr) return res.status(500).json({ message: 'Failed to load positions.' });

  // All candidates
  const { data: candidates, error: canErr } = await supabase
    .from('candidates')
    .select('id, position_id, name, party');

  if (canErr) return res.status(500).json({ message: 'Failed to load candidates.' });

  // Vote counts per candidate
  const { data: votes, error: voteErr } = await supabase
    .from('votes')
    .select('candidate_id');

  if (voteErr) return res.status(500).json({ message: 'Failed to load votes.' });

  // Tally votes
  const tally = {};
  votes.forEach(v => { tally[v.candidate_id] = (tally[v.candidate_id] || 0) + 1; });

  // Total unique voters who voted
  const { data: voterCount } = await supabase
    .from('registered_voters')
    .select('id', { count: 'exact', head: true });

  const { data: votedCount } = await supabase
    .from('votes')
    .select('email')
    .limit(10000);

  const uniqueVoters = new Set(votedCount?.map(v => v.email) || []).size;

  // Build result
  const result = positions.map(pos => ({
    ...pos,
    candidates: candidates
      .filter(c => c.position_id === pos.id)
      .map(c => ({ ...c, votes: tally[c.id] || 0 }))
      .sort((a, b) => b.votes - a.votes),
  }));

  return res.json({
    positions:            result,
    total_votes:          votes.length,
    total_voters:         voterCount?.length || 318,
    total_voters_voted:   uniqueVoters,
  });
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'NIMC API running' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
