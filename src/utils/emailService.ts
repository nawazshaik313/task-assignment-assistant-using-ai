import emailjs from 'emailjs-com';

export const sendApprovalEmail = async (toEmail: string, displayName: string) => {
  try {
    await emailjs.send(
      import.meta.env.VITE_EMAILJS_SERVICE_ID,
      import.meta.env.VITE_EMAILJS_TEMPLATE_ID,
      {
        to_name: displayName,
        to_email: toEmail,
        message: `Hello ${displayName}, your account has been approved. You can now log in.`,
      },
      import.meta.env.VITE_EMAILJS_USER_ID
    );
    console.log(`✅ Email sent to ${toEmail}`);
  } catch (err) {
    console.error('❌ Email sending failed:', err);
  }
};
