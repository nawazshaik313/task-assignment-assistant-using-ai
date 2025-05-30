import emailjs from 'emailjs-com';
import { Role } from '../types';

const SERVICE_ID = import.meta.env.VITE_EMAIL_SERVICE_ID;
const TEMPLATE_ID_WELCOME = import.meta.env.VITE_EMAIL_TEMPLATE_ID_WELCOME;
const TEMPLATE_ID_ACTIVATED = import.meta.env.VITE_EMAIL_TEMPLATE_ID_ACTIVATED;
const TEMPLATE_ID_TASK_PROPOSAL = import.meta.env.VITE_EMAIL_TEMPLATE_ID_TASK_PROPOSAL;
const TEMPLATE_ID_TASK_UPDATE = import.meta.env.VITE_EMAIL_TEMPLATE_ID_TASK_UPDATE;
const TEMPLATE_ID_TASK_APPROVED = import.meta.env.VITE_EMAIL_TEMPLATE_ID_TASK_APPROVED;
const TEMPLATE_ID_RESET = import.meta.env.VITE_EMAIL_TEMPLATE_ID_RESET;
const TEMPLATE_ID_PREREG_USER = import.meta.env.VITE_EMAIL_TEMPLATE_ID_PREREG_USER;
const TEMPLATE_ID_PREREG_ADMIN = import.meta.env.VITE_EMAIL_TEMPLATE_ID_PREREG_ADMIN;
const PUBLIC_KEY = import.meta.env.VITE_EMAIL_PUBLIC_KEY;

export const sendWelcomeRegistrationEmail = async (email: string, displayName: string, role: Role) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_WELCOME,
{ to_email: email, to_name: displayName, role },
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send welcome email:', err);
}
};

export const sendAccountActivatedByAdminEmail = async (userEmail: string, userName: string, adminName: string) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_ACTIVATED,
{ to_email: userEmail, to_name: userName, admin_name: adminName },
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send activation email:', err);
}
};

export const sendTaskProposalEmail = async (
userEmail: string,
userName: string,
taskTitle: string,
adminName: string,
deadline?: string
) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_TASK_PROPOSAL,
{
to_email: userEmail,
to_name: userName,
task_title: taskTitle,
admin_name: adminName,
deadline,
},
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send task proposal email:', err);
}
};

export const sendTaskStatusUpdateToAdminEmail = async (
adminEmail: string,
adminName: string,
userName: string,
taskTitle: string,
userAction: string
) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_TASK_UPDATE,
{
to_email: adminEmail,
to_name: adminName,
user_name: userName,
task_title: taskTitle,
user_action: userAction,
},
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send task update email to admin:', err);
}
};

export const sendTaskCompletionApprovedToUserEmail = async (
userEmail: string,
userName: string,
taskTitle: string,
adminName: string
) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_TASK_APPROVED,
{
to_email: userEmail,
to_name: userName,
task_title: taskTitle,
admin_name: adminName,
},
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send task approval email:', err);
}
};

export const sendPasswordResetRequestEmail = async (userEmail: string, userName: string) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_RESET,
{
to_email: userEmail,
to_name: userName,
reset_link: https://your-app.com/reset-password?user=${encodeURIComponent(userEmail)},
},
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send password reset email:', err);
}
};

export const sendPreRegistrationSubmittedToUserEmail = async (
email: string,
displayName: string,
adminDisplayName: string
) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_PREREG_USER,
{
to_email: email,
to_name: displayName,
admin_name: adminDisplayName,
},
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to send pre-registration confirmation to user:', err);
}
};

export const sendPreRegistrationNotificationToAdminEmail = async (
adminEmail: string,
adminName: string,
pendingUserName: string,
pendingUserUniqueId: string
) => {
try {
await emailjs.send(
SERVICE_ID,
TEMPLATE_ID_PREREG_ADMIN,
{
to_email: adminEmail,
to_name: adminName,
pending_user_name: pendingUserName,
pending_user_id: pendingUserUniqueId,
},
PUBLIC_KEY
);
} catch (err) {
console.error('❌ Failed to notify admin of pre-registration:', err);
}
};