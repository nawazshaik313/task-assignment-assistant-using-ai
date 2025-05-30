
// Placeholder for email service
import { Role } from '../types';

/**
 * Simulates sending a welcome and registration confirmation email.
 * @param email The email address of the new user.
 * @param displayName The display name of the new user.
 * @param role The role assigned to the new user.
 */
export const sendWelcomeRegistrationEmail = async (email: string, displayName: string, role: Role): Promise<void> => {
  const subject = "Welcome to Task Assignment Assistant!";
  const body = `
    Hello ${displayName},

    Welcome aboard! Your account for the Task Assignment Assistant has been successfully created with the role: ${role}.
    You can now log in using your credentials.

    Best regards,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${email}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100)); // Simulate async
};

/**
 * Simulates sending an email when an admin activates/approves a user account.
 * @param userEmail The email address of the user whose account was activated.
 * @param userName The display name of the user.
 * @param adminName The display name of the admin who activated the account.
 */
export const sendAccountActivatedByAdminEmail = async (userEmail: string, userName: string, adminName: string): Promise<void> => {
  const subject = "Your Account is Active!";
  const body = `
    Hello ${userName},

    Great news! Your account for the Task Assignment Assistant has been activated by ${adminName}.
    You can now log in to the system.

    Best regards,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${userEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};


/**
 * Simulates sending a task proposal email to a user.
 * @param userEmail The email of the user receiving the task proposal.
 * @param userName The name of the user.
 * @param taskTitle The title of the task.
 * @param adminName The name of the admin proposing the task.
 * @param deadline Optional deadline for the task.
 */
export const sendTaskProposalEmail = async (userEmail: string, userName: string, taskTitle: string, adminName: string, deadline?: string): Promise<void> => {
  const subject = `New Task Proposed: ${taskTitle}`;
  const body = `
    Hello ${userName},

    A new task, "${taskTitle}", has been proposed to you by ${adminName}.
    ${deadline ? `The deadline for this task is ${new Date(deadline).toLocaleDateString()}.` : 'There is no specific deadline set for this task yet.'}
    Please log in to the Task Assignment Assistant to review and accept or decline this task.

    Best regards,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${userEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};

/**
 * Simulates sending an email to an admin about a user's action on a task.
 * @param adminEmail The email of the admin to notify.
 * @param adminName The name of the admin.
 * @param userName The name of the user who acted on the task.
 * @param taskTitle The title of the task.
 * @param userAction A description of the user's action (e.g., "accepted", "declined", "submitted").
 */
export const sendTaskStatusUpdateToAdminEmail = async (adminEmail: string, adminName: string, userName: string, taskTitle: string, userAction: string): Promise<void> => {
  const subject = `Task Update: ${userName} ${userAction} "${taskTitle}"`;
  const body = `
    Hello ${adminName},

    This is to inform you that ${userName} has ${userAction} the task: "${taskTitle}".
    You can view the details in the Task Assignment Assistant.

    Regards,
    Task Assignment System
  `;
  console.log(`Simulating email to: ${adminEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};

/**
 * Simulates sending an email to a user when their task submission is approved by an admin.
 * @param userEmail The email of the user.
 * @param userName The name of the user.
 * @param taskTitle The title of the approved task.
 * @param adminName The name of the admin who approved the task.
 */
export const sendTaskCompletionApprovedToUserEmail = async (userEmail: string, userName: string, taskTitle: string, adminName: string): Promise<void> => {
  const subject = `Task Approved: "${taskTitle}"`;
  const body = `
    Hello ${userName},

    Congratulations! Your submission for the task "${taskTitle}" has been reviewed and approved by ${adminName}.
    Thank you for your hard work!

    Best regards,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${userEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};

/**
 * Simulates sending a password reset request email.
 * @param userEmail The email of the user requesting a password reset.
 * @param userName The name of the user.
 */
export const sendPasswordResetRequestEmail = async (userEmail: string, userName: string): Promise<void> => {
  const subject = "Password Reset Request for Task Assignment Assistant";
  
  // This is where a real link would be generated or templated.
  // The error message implied a structure like this was being created:
  const templateParamsForActualService = {
    to_email: userEmail,
    to_name: userName,
    // The URL must be a string. Corrected by using backticks for template literal.
    reset_link: `https://your-app.com/reset-password?token=SOME_UNIQUE_TOKEN&user=${encodeURIComponent(userEmail)}`,
    // Other params like PUBLIC_KEY would be used if integrating a service like EmailJS directly here.
  };

  // For simulation purposes, we use a placeholder link and log to console.
  const resetLinkPlaceholder = `https://example.com/reset-password?token=SIMULATED_RESET_TOKEN_FOR_${encodeURIComponent(userName)}`;
  const body = `
    Hello ${userName},

    We received a request to reset your password for the Task Assignment Assistant.
    If you made this request, please click the link below to set a new password:
    ${resetLinkPlaceholder} 
    (If this were a real email, the link might look like: ${templateParamsForActualService.reset_link})

    If you did not request a password reset, please ignore this email. This link is valid for a limited time.

    Best regards,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${userEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  // If using a real email service, the call would be here, e.g.:
  // try {
  //   await emailjs.send(SERVICE_ID, TEMPLATE_ID, templateParamsForActualService, PUBLIC_KEY);
  //   console.log('Password reset email sent successfully via EmailJS.');
  // } catch (error) {
  //   console.error('Failed to send password reset email via EmailJS:', error);
  // }
  await new Promise(resolve => setTimeout(resolve, 100)); // Simulate async
};

/**
 * Simulates sending an email to the user after they submit pre-registration.
 * @param email The user's email.
 * @param displayName The user's display name.
 * @param adminDisplayName The display name of the referring admin.
 */
export const sendPreRegistrationSubmittedToUserEmail = async (email: string, displayName: string, adminDisplayName: string): Promise<void> => {
  const subject = "Pre-registration Received - Awaiting Approval";
  const body = `
    Hello ${displayName},

    We have received your pre-registration request for the Task Assignment Assistant, submitted via a link from ${adminDisplayName}.
    Your request is now pending administrator approval. You will be notified via email once your account is active.

    Thank you,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${email}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};

/**
 * Simulates sending an email to the admin when a new user pre-registers.
 * @param adminEmail The admin's email.
 * @param adminName The admin's name.
 * @param pendingUserName The display name of the user who pre-registered.
 * @param pendingUserUniqueId The unique ID chosen by the pending user.
 */
export const sendPreRegistrationNotificationToAdminEmail = async (adminEmail: string, adminName: string, pendingUserName: string, pendingUserUniqueId: string): Promise<void> => {
  const subject = "New User Pre-registration Submitted";
  const body = `
    Hello ${adminName},

    A new user, ${pendingUserName} (Desired System ID: ${pendingUserUniqueId}), has submitted a pre-registration request using your referral link.
    Please log in to the Task Assignment Assistant to review and approve their request in the "User Management" section.

    Regards,
    Task Assignment System
  `;
  console.log(`Simulating email to: ${adminEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};

/**
 * Simulates sending an email to a user after general registration, informing them it's pending approval.
 * @param email The user's email.
 * @param displayName The user's display name.
 */
export const sendRegistrationPendingToUserEmail = async (email: string, displayName: string): Promise<void> => {
  const subject = "Registration Received - Awaiting Approval";
  const body = `
    Hello ${displayName},

    Thank you for registering for the Task Assignment Assistant!
    Your registration is now pending administrator approval. You will be notified via email once your account is active.

    Best regards,
    The Task Assignment Assistant Team
  `;
  console.log(`Simulating email to: ${email}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};

/**
 * Simulates sending an email to an admin about a new general registration that is pending.
 * @param adminEmail The admin's email.
 * @param adminName The admin's name.
 * @param newUserName The display name of the user who registered.
 * @param newUserEmail The email of the user who registered.
 */
export const sendNewPendingRegistrationToAdminEmail = async (adminEmail: string, adminName: string, newUserName: string, newUserEmail: string): Promise<void> => {
  const subject = "New User Registration Pending Approval";
  const body = `
    Hello ${adminName},

    A new user, ${newUserName} (Email: ${newUserEmail}), has registered and is awaiting your approval.
    Please log in to the Task Assignment Assistant to review and approve their request in the "User Management" section.

    Regards,
    Task Assignment System
  `;
  console.log(`Simulating email to: ${adminEmail}\nSubject: ${subject}\nBody: ${body.trim().replace(/\n +/g, '\n')}\n---`);
  await new Promise(resolve => setTimeout(resolve, 100));
};
