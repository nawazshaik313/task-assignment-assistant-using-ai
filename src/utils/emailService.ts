
const emailjs = require('@emailjs/nodejs');

const EMAILJS_SERVICE_ID = process.env.EMAILJS_SERVICE_ID;
const EMAILJS_PUBLIC_KEY = process.env.EMAILJS_PUBLIC_KEY; // User ID from EmailJS account settings
const EMAILJS_PRIVATE_KEY = process.env.EMAILJS_PRIVATE_KEY;

// Initialize EmailJS SDK
if (EMAILJS_PUBLIC_KEY && EMAILJS_PRIVATE_KEY) {
  emailjs.init({
    publicKey: EMAILJS_PUBLIC_KEY,
    privateKey: EMAILJS_PRIVATE_KEY,
  });
} else {
  console.warn("EmailJS Public or Private Key not found in .env. Email sending will be disabled.");
}

const isEmailServiceConfigured = () => EMAILJS_SERVICE_ID && EMAILJS_PUBLIC_KEY && EMAILJS_PRIVATE_KEY;

const sendEmail = async (templateId, templateParams) => {
  if (!isEmailServiceConfigured()) {
    console.log(`Email Service (EmailJS) not configured. Skipping email send. Template: ${templateId}, Params:`, templateParams);
    return Promise.resolve({ status: 'simulated_success', text: 'EmailJS not configured.' });
  }
  if (!templateId) {
    console.error("EmailJS: Template ID is missing. Cannot send email.");
    return Promise.reject(new Error("EmailJS Template ID is missing."));
  }

  try {
    const response = await emailjs.send(EMAILJS_SERVICE_ID, templateId, templateParams);
    console.log(`EmailJS: Email sent successfully using template ${templateId}! Response:`, response.status, response.text);
    return response;
  } catch (error) {
    console.error(`EmailJS: Failed to send email using template ${templateId}:`, error);
    throw error;
  }
};

// --- Specific Email Sending Functions ---

// Called from userRoutes.js after successful registration
exports.sendWelcomeRegistrationEmail = async (email, displayName, role, companyName = '') => { // Changed organizationName to companyName
  const templateParams = {
    to_email: email,
    to_name: displayName,
    user_role: role,
    company_name: companyName, // For admins creating new site, changed from organization_name
    login_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#LOGIN` // Assumes frontend URL is in env
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_WELCOME, templateParams);
};

// Called from userRoutes.js for password reset
exports.sendPasswordResetEmail = async (email, displayName, resetLink) => {
  const templateParams = {
    to_email: email,
    to_name: displayName,
    reset_link: resetLink,
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_PASSWORD_RESET, templateParams);
};

// Called from pendingUserRoutes.js when an admin activates/approves a user
exports.sendAccountActivatedByAdminEmail = async (userEmail, userName, adminName) => {
  const templateParams = {
    to_email: userEmail,
    to_name: userName,
    admin_name: adminName,
    login_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#LOGIN`
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_ACCOUNT_ACTIVATED, templateParams);
};

// Called from assignmentRoutes.js when a task is proposed
exports.sendTaskProposalEmail = async (userEmail, userName, taskTitle, adminName, deadline) => {
  const templateParams = {
    to_email: userEmail,
    to_name: userName,
    task_title: taskTitle,
    admin_name: adminName,
    task_deadline: deadline ? new Date(deadline).toLocaleDateString() : 'Not set',
    assignments_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#VIEW_ASSIGNMENTS`
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_TASK_PROPOSED, templateParams);
};

// Called from assignmentRoutes.js for task status updates
exports.sendTaskStatusUpdateToAdminEmail = async (adminEmail, adminName, userName, taskTitle, userAction) => {
  const templateParams = {
    to_email: adminEmail,
    admin_name: adminName,
    user_name: userName,
    task_title: taskTitle,
    user_action: userAction, // e.g., "accepted", "declined", "submitted"
    dashboard_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#DASHBOARD`
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_TASK_UPDATE_ADMIN, templateParams);
};

// Called from assignmentRoutes.js when task completion is approved
exports.sendTaskCompletionApprovedToUserEmail = async (userEmail, userName, taskTitle, adminName) => {
  const templateParams = {
    to_email: userEmail,
    to_name: userName,
    task_title: taskTitle,
    admin_name: adminName,
    assignments_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#VIEW_ASSIGNMENTS`
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_TASK_COMPLETED_USER, templateParams);
};

// Called from pendingUserRoutes.js after user submits pre-registration
exports.sendPreRegistrationSubmittedToUserEmail = async (email, displayName, adminDisplayName) => {
  const templateParams = {
    to_email: email,
    to_name: displayName,
    admin_name: adminDisplayName,
    login_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#LOGIN`
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_PREREG_SUBMITTED_USER, templateParams);
};

// Called from pendingUserRoutes.js to notify admin of new pre-registration
exports.sendPreRegistrationNotificationToAdminEmail = async (adminEmail, adminName, pendingUserName, pendingUserUniqueId) => {
  const templateParams = {
    to_email: adminEmail,
    admin_name: adminName,
    pending_user_name: pendingUserName,
    pending_user_unique_id: pendingUserUniqueId,
    user_management_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#USER_MANAGEMENT`
  };
  return sendEmail(process.env.EMAILJS_TEMPLATE_PREREG_NOTIFY_ADMIN, templateParams);
};

// Called from userRoutes.js for general registration that is pending approval
exports.sendRegistrationPendingToUserEmail = async (email, displayName) => {
    const templateParams = {
        to_email: email,
        to_name: displayName,
        login_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#LOGIN`
    };
    return sendEmail(process.env.EMAILJS_TEMPLATE_REG_PENDING_USER, templateParams);
};

// Called from userRoutes.js to notify admin of new general registration needing approval
exports.sendNewPendingRegistrationToAdminEmail = async (adminEmail, adminName, newUserName, newUserEmail, organizationId) => {
    const templateParams = {
        to_email: adminEmail,
        admin_name: adminName,
        new_user_name: newUserName,
        new_user_email: newUserEmail,
        user_management_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}#USER_MANAGEMENT`
        // You might want to include organizationId if admin manages multiple, or if email is for a superadmin
    };
    return sendEmail(process.env.EMAILJS_TEMPLATE_REG_PENDING_ADMIN, templateParams);
};
