import emailjs from 'emailjs-com';

export const sendApprovalEmail = async (toEmail: string, displayName: string) => {
try {
await emailjs.send(
'your_service_id', // e.g., service_xyz123
'your_template_id', // e.g., template_abc456
{
to_name: displayName,
to_email: toEmail,
message: Hello ${displayName}, your account has been approved. You can now log in.,
},
'your_public_key' // e.g., RvX3zAbCDeFgHiJKl
);
console.log('✅ Email sent');
} catch (err) {
console.error('❌ Email failed', err);
}
};