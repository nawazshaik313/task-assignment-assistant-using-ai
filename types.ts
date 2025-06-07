
export type Role = 'admin' | 'user';
export type NotificationPreference = 'email' | 'phone' | 'none';

// Clarified status descriptions
export type AssignmentStatus =
  | 'pending_acceptance'      // Admin proposed task to user, user needs to accept/decline.
  | 'accepted_by_user'        // User accepted the task, it is now in progress.
  | 'declined_by_user'        // User declined the task offer.
  | 'submitted_on_time'       // User marked task as completed on or before its deadline.
  | 'submitted_late'          // User marked task as completed after its deadline.
  | 'completed_admin_approved'; // Admin has reviewed the user's submission and approved task completion.

export type UserStatus = 'active' | 'pending_approval';

export interface User {
  id: string; // Internal unique ID for the user record
  email: string; // Primary identifier for login, mandatory.
  uniqueId: string; // System-specific username or secondary ID, chosen during profile setup.
  password: string; // Password for this system.
  role: Role;
  displayName: string;
  position: string;
  userInterests?: string;
  phone?: string; // Optional, can be different from login mechanism
  notificationPreference?: NotificationPreference;
  referringAdminId?: string;
}

export interface PendingUser {
  _id?: string;
  id?: string; // ✅ Add this if missing
  email: string;
  displayName: string;
  password?: string;
  role: string;
  uniqueId: string;
  submissionDate?: string;
}


export interface Program {
  id: string;
  name: string;
  description: string;
}

export interface Task {
  id:string;
  title: string;
  description: string;
  requiredSkills: string;
  programId?: string;
  programName?: string;
  deadline?: string; // ISO date string (e.g., "YYYY-MM-DD")
}

export interface Assignment {
  taskId: string;
  personId: string; // User.id of the assigned person
  taskTitle: string;
  personName: string; // User.displayName of the assigned person
  justification?: string; // AI's reason for suggesting this person
  status: AssignmentStatus;
  deadline?: string; // Specific deadline for this assignment instance
  userSubmissionDate?: string; // ISO datetime string when user submitted
  userDelayReason?: string; // User's reason if submitted late
}

export enum Page {
  InitialAdminSetup = 'INITIAL_ADMIN_SETUP', // Retained for conceptual flow, but behavior changes
  AdminRegistrationEmail = 'ADMIN_REGISTRATION_EMAIL',
  AdminRegistrationProfile = 'ADMIN_REGISTRATION_PROFILE',
  Login = 'LOGIN',
  PreRegistration = 'PRE_REGISTRATION',
  Dashboard = 'DASHBOARD',
  UserProfile = 'USER_PROFILE',
  UserManagement = 'USER_MANAGEMENT',
  ManagePrograms = 'MANAGE_PROGRAMS',
  ManageTasks = 'MANAGE_TASKS',
  AssignWork = 'ASSIGN_WORK',
  ViewAssignments = 'VIEW_ASSIGNMENTS',
  ViewTasks = 'VIEW_TASKS'
}

export interface GeminiSuggestion {
  suggestedPersonName: string | null; // Corresponds to User.displayName
  justification: string;
}

export interface AdminLogEntry {
  id: string;
  adminId: string; // User.id of the admin who made the log
  adminDisplayName: string; // User.displayName of the admin
  timestamp: string;
  logText: string;
  imagePreviewUrl?: string;
}