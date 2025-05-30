import { User, Task, Program, Assignment, AdminLogEntry, PendingUser } from '../types';

// Keys for localStorage
const USERS_KEY = 'task-assign-users';
const PENDING_USERS_KEY = 'task-assign-pending-users';
const TASKS_KEY = 'task-assign-tasks';
const PROGRAMS_KEY = 'task-assign-programs';
const ASSIGNMENTS_KEY = 'task-assign-assignments';
const ADMIN_LOGS_KEY = 'task-assign-adminLogs';
const CURRENT_USER_KEY = 'task-assign-currentUser';

// Helper to simulate async operations
const simulateDelay = (ms: number = 100) => new Promise(resolve => setTimeout(resolve, ms));

// --- Load Functions ---

export const loadUsersFromCloud = async (): Promise<User[]> => {
  await simulateDelay();
  const data = localStorage.getItem(USERS_KEY);
  return data ? JSON.parse(data) : [];
};

export const loadPendingUsersFromCloud = async (): Promise<PendingUser[]> => {
  await simulateDelay();
  const data = localStorage.getItem(PENDING_USERS_KEY);
  return data ? JSON.parse(data) : [];
};

export const loadTasksFromCloud = async (): Promise<Task[]> => {
  await simulateDelay();
  const data = localStorage.getItem(TASKS_KEY);
  return data ? JSON.parse(data) : [];
};

export const loadProgramsFromCloud = async (): Promise<Program[]> => {
  await simulateDelay();
  const data = localStorage.getItem(PROGRAMS_KEY);
  return data ? JSON.parse(data) : [];
};

export const loadAssignmentsFromCloud = async (): Promise<Assignment[]> => {
  await simulateDelay();
  const data = localStorage.getItem(ASSIGNMENTS_KEY);
  return data ? JSON.parse(data) : [];
};

export const loadAdminLogsFromCloud = async (): Promise<AdminLogEntry[]> => {
  await simulateDelay();
  const data = localStorage.getItem(ADMIN_LOGS_KEY);
  return data ? JSON.parse(data) : [];
};

export const loadCurrentUserFromCloud = async (): Promise<User | null> => {
  await simulateDelay();
  const data = localStorage.getItem(CURRENT_USER_KEY);
  return data ? JSON.parse(data) : null;
};

// --- Save Functions ---

export const saveUsersToCloud = async (users: User[]): Promise<void> => {
  await simulateDelay();
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
};

export const savePendingUsersToCloud = async (pendingUsers: PendingUser[]): Promise<void> => {
  await simulateDelay();
  localStorage.setItem(PENDING_USERS_KEY, JSON.stringify(pendingUsers));
};

export const saveTasksToCloud = async (tasks: Task[]): Promise<void> => {
  await simulateDelay();
  localStorage.setItem(TASKS_KEY, JSON.stringify(tasks));
};

export const saveProgramsToCloud = async (programs: Program[]): Promise<void> => {
  await simulateDelay();
  localStorage.setItem(PROGRAMS_KEY, JSON.stringify(programs));
};

export const saveAssignmentsToCloud = async (assignments: Assignment[]): Promise<void> => {
  await simulateDelay();
  localStorage.setItem(ASSIGNMENTS_KEY, JSON.stringify(assignments));
};

export const saveAdminLogsToCloud = async (adminLogs: AdminLogEntry[]): Promise<void> => {
  await simulateDelay();
  localStorage.setItem(ADMIN_LOGS_KEY, JSON.stringify(adminLogs));
};

export const saveCurrentUserToCloud = async (currentUser: User | null): Promise<void> => {
  await simulateDelay();
  if (currentUser) {
    localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(currentUser));
  } else {
    localStorage.removeItem(CURRENT_USER_KEY);
  }
};
