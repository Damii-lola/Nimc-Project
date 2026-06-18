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
  const { email } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ message: 'Invalid email address.' });
  }

  const otp       = generateOtp();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  // Upsert OTP into Supabase
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

  // Send email via Resend
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
app.post('/auth/verify-nin', async (req, res) => {
  const { email, nin } = req.body;

  if (!email || !nin) {
    return res.status(400).json({ message: 'Email and NIN are required.' });
  }

  if (!/^\d{11}$/.test(nin)) {
    return res.status(400).json({ message: 'NIN must be exactly 11 digits.' });
  }

  // Look up NIN in the registered_voters table
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

  return res.json({
    message: 'NIN verified successfully.',
    full_name: `${data.first_name} ${data.last_name}`,
    email: data.email,
  });
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'NIMC API running' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
