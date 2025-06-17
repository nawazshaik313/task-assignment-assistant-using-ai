
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import * as emailService from './src/utils/emailService'; // Corrected import path
import { validatePassword } from './src/utils/validation';
// import * //as cloudDataService from './services/cloudDataService'; // Deactivated
import LoadingSpinner from './components/LoadingSpinner';
import { UsersIcon, ClipboardListIcon, LightBulbIcon, CheckCircleIcon, TrashIcon, PlusCircleIcon, KeyIcon, BriefcaseIcon, LogoutIcon, UserCircleIcon } from './components/Icons';
import PreRegistrationFormPage from './components/PreRegistrationFormPage';
import UserTour from './components/UserTour';
import Sidebar from './components/Sidebar'; // Import the new Sidebar component

const API_BASE_URL = 'https://task-management-backend-17a5.onrender.com';
const JWT_TOKEN_KEY = 'task-assign-jwt';

// --- START OF NEW AUTH FORM COMPONENTS ---
const AuthFormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { id: string; 'aria-label': string }> = ({ id, ...props }) => (
  <input
    id={id}
    {...props}
    className="w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
  />
);

const AuthFormSelect: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { id: string; 'aria-label': string; children: React.ReactNode }> = ({ id, children, ...props }) => (
  <select
    id={id}
    {...props}
    className="w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight"
  >
    {children}
  </select>
);
// --- END OF NEW AUTH FORM COMPONENTS ---


// Define helper components outside the App component for stability
const FormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label: string; id: string; description?: string; }> = ({ label, id, description, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <input id={id} {...props} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" />
    {description && <p className="mt-1 text-xs text-neutral">{description}</p>}
  </div>
);

const FormTextarea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; id: string; }> = ({ label, id, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <textarea id={id} {...props} rows={3} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" />
  </div>
);

const FormSelect: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { label: string; id: string; children: React.ReactNode; }> = ({ label, id, children, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <select id={id} {...props} className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-neutral focus:outline-none focus:ring-primary focus:border-primary sm:text-sm rounded-md bg-surface text-textlight">
      {children}
    </select>
  </div>
);

// Interface to represent the structure of a pending user object from the backend
interface BackendPendingUser {
  _id?: string; // Potential MongoDB-style ID
  id?: string;  // If backend sometimes sends 'id'
  uniqueId: string;
  displayName: string;
  email: string;
  password?: string; // Password from pending user (might be hashed or plain depending on flow)
  role: Role;
  submissionDate: string;
  referringAdminId?: string;
}

// Interface to represent the structure of a user object from the backend (e.g., after creation)
interface BackendUser {
  _id?: string;
  id?: string; // virtual 'id' from Mongoose
  email: string;
  uniqueId: string;
  // password is NOT expected from backend response for a created/fetched user object for security
  role: Role;
  displayName: string;
  position: string;
  userInterests?: string;
  phone?: string;
  notificationPreference?: NotificationPreference;
  referringAdminId?: string;
  // token?: string; // Token is part of the login response root, not nested in user object
}


const initialPreRegistrationFormState = {
  uniqueId: '',
  displayName: '',
  email: '',
  password: '',
  confirmPassword: '',
  referringAdminId: '',
  referringAdminDisplayName: '',
  isReferralLinkValid: false,
};

const initialAdminRegistrationState = {
  email: '',
  uniqueId: '',
  password: '',
  confirmPassword: '',
  displayName: '',
  position: '',
};

const passwordRequirementsText = "Must be at least 8 characters and include an uppercase letter, a lowercase letter, a number, and a special character (e.g., !@#$%).";

const fetchData = async <T,>(endpoint: string, options: RequestInit = {}, defaultReturnVal: T | null = null): Promise<T | null> => {
  const token = localStorage.getItem(JWT_TOKEN_KEY);
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    ...options.headers, // Allow overriding headers
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (response.status === 204) { // No Content
      return defaultReturnVal !== null ? defaultReturnVal : ({} as T);
    }

    // Check for unauthorized specifically to handle token expiry or invalid token
    if (response.status === 401 || response.status === 403) {
        // Could trigger logout or token refresh logic here
        localStorage.removeItem(JWT_TOKEN_KEY); // Remove potentially invalid token
        // Potentially redirect to login: window.location.hash = Page.Login;
        // For now, just throw an error that can be caught by callers
        const errorText = await response.text();
        let errorData: any = null;
        try { errorData = JSON.parse(errorText); } catch (e) { /* use raw text */ }
        console.error(`Auth Error for ${endpoint}: ${response.status}. Body: ${errorText}`);
        throw new Error(errorData?.message || errorText || `Authentication/Authorization failed with status ${response.status}`);
    }


    const responseText = await response.text();

    if (!response.ok) {
      let errorData: any = null;
      try {
        errorData = JSON.parse(responseText);
      } catch (e) {
        // If parsing fails, use the raw text
      }
      console.error(`API Error for ${endpoint}: ${response.status} ${response.statusText}. Body: ${responseText}`, errorData);
      if (response.status === 404) {
        return defaultReturnVal;
      }
      throw new Error(errorData?.message || errorData?.error || responseText || `Request failed with status ${response.status}`);
    }

    if (!responseText) {
      return defaultReturnVal !== null ? defaultReturnVal : ({} as T);
    }

    const parsedData = JSON.parse(responseText);
    // If backend wraps data in a 'data' or 'user' field, or includes success flags
    // e.g. if (parsedData.success === false && parsedData.message) throw new Error(parsedData.message);
    // return parsedData.data || parsedData.user || parsedData as T;
    return parsedData as T; // Assuming direct data return for now
  } catch (error) {
    console.error(`Network or parsing error for ${endpoint}:`, error);
     if (error instanceof Error && error.message.includes("Failed to fetch")) {
        throw new Error(`Network error: Could not connect to the server at ${API_BASE_URL}. Please check your internet connection and the server status.`);
    }
    throw error;
  }
};


export const App = (): JSX.Element => {
  const [currentPage, _setCurrentPageInternal] = useState<Page>(Page.Login);

  const [users, setUsers] = useState<User[]>([]);
  const [pendingUsers, setPendingUsers] = useState<PendingUser[]>([]);
  const [currentUser, setCurrentUserInternal] = useState<User | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [programs, setPrograms] = useState<Program[]>([]);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [adminLogs, setAdminLogs] = useState<AdminLogEntry[]>([]);
  const [isLoadingAppData, setIsLoadingAppData] = useState<boolean>(true); // Start true


  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [newLoginForm, setNewLoginForm] = useState({ email: '', password: '' });
  const [newRegistrationForm, setNewRegistrationForm] = useState({
    name: '', // Corresponds to displayName
    email: '',
    password: '',
    confirmPassword: '',
    role: 'user' as Role, // Default, might be overridden for first admin
    uniqueId: '', // Added for registration form
    position: '', // Added
  });

  const [adminRegistrationForm, setAdminRegistrationForm] = useState(initialAdminRegistrationState);
  const [preRegistrationForm, setPreRegistrationFormInternal] = useLocalStorage('task-assign-preRegistrationForm',initialPreRegistrationFormState);

  const initialUserFormData = {
      email: '', uniqueId: '', password: '', confirmPassword: '',
      displayName: '', position: '', userInterests: '',
      phone: '', notificationPreference: 'none' as NotificationPreference,
      role: 'user' as Role, // Always default to 'user' for forms initiated by admin
      referringAdminId: ''
  };
  const [userForm, setUserForm] = useState<typeof initialUserFormData>(initialUserFormData);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [approvingPendingUser, setApprovingPendingUser] = useState<PendingUser | null>(null);

  const [programForm, setProgramForm] = useState<{ name: string; description: string }>({ name: '', description: '' });
  const [taskForm, setTaskForm] = useState<{ title: string; description: string; requiredSkills: string; programId?: string; deadline?: string }>({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' });

  const [assignmentForm, setAssignmentForm] = useState<{ specificDeadline?: string }>({ specificDeadline: '' });
  const [userSubmissionDelayReason, setUserSubmissionDelayReason] = useState<string>('');
  const [assignmentToSubmitDelayReason, setAssignmentToSubmitDelayReason] = useState<string | null>(null);


  const [selectedTaskForAssignment, setSelectedTaskForAssignment] = useState<string | null>(null);
  const [assignmentSuggestion, setAssignmentSuggestion] = useState<GeminiSuggestion | null>(null);
  const [isLoadingSuggestion, setIsLoadingSuggestion] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const [generatedLink, setGeneratedLink] = useState<string>('');

  const [adminLogText, setAdminLogText] = useState('');
  const [adminLogImageFile, setAdminLogImageFile] = useState<File | null>(null);
  const [isSubmittingLog, setIsSubmittingLog] = useState(false);

  const [showUserTour, setShowUserTour] = useState<boolean>(false);

  const clearMessages = useCallback(() => { setError(null); setSuccessMessage(null); setInfoMessage(null); }, []);

  const setCurrentUser = (user: User | null) => {
    setCurrentUserInternal(user);
    if (user && user.token) {
      localStorage.setItem(JWT_TOKEN_KEY, user.token);
    } else if (!user) {
      localStorage.removeItem(JWT_TOKEN_KEY);
    }
  };

  // This should be derived from `users` state directly when needed.
  // const adminExists = users.some(u => u.role === 'admin');
  const getAdminExists = () => users.some(u => u.role === 'admin');


  const loadInitialData = useCallback(async (loggedInUser?: User) => {
    setIsLoadingAppData(true);
    try {
      let activeUser = loggedInUser;
      if (!activeUser) {
        const token = localStorage.getItem(JWT_TOKEN_KEY);
        if (token) {
          const userFromServer = await fetchData<User>('/users/current', {}, null);
          if (userFromServer) {
            activeUser = { ...userFromServer, token };
          }
        }
      }

      setCurrentUserInternal(activeUser);
      
      let loadedUsersData: User[] = [];

      if (activeUser) {
        const [
          loadedUsers, loadedPendingUsers, loadedTasks, loadedPrograms, loadedAssignments, loadedAdminLogs,
        ] = await Promise.all([
          fetchData<User[]>('/users', {}, []),
          activeUser.role === 'admin' ? fetchData<PendingUser[]>('/pending-users', {}, []) : Promise.resolve([]),
          fetchData<Task[]>('/tasks', {}, []),
          fetchData<Program[]>('/programs', {}, []),
          fetchData<Assignment[]>('/assignments', {}, []),
          activeUser.role === 'admin' ? fetchData<AdminLogEntry[]>('/admin-logs', {}, []) : Promise.resolve([]),
        ]);

        loadedUsersData = loadedUsers || [];
        setUsers(loadedUsersData);
        setPendingUsers(loadedPendingUsers || []);
        setTasks(loadedTasks || []);
        setPrograms(loadedPrograms || []);
        setAssignments(loadedAssignments || []);
        setAdminLogs(loadedAdminLogs || []);
        
      } else {
        // Attempt to fetch users even if not logged in to check for admin existence for registration form
        // This is a simplified approach. A dedicated backend endpoint might be better.
        const allUsersResponse = await fetchData<User[]>('/users/all-for-status-check', {}, []); // Hypothetical endpoint
        loadedUsersData = allUsersResponse || [];
        setUsers(loadedUsersData);

        setPendingUsers([]);
        setTasks([]);
        setPrograms([]);
        setAssignments([]);
        setAdminLogs([]);
      }
      
      const currentAdminExists = loadedUsersData.some(u => u.role === 'admin');
      if (!currentAdminExists) {
          setNewRegistrationForm(prev => ({ ...prev, role: 'admin' })); 
      } else {
            setNewRegistrationForm(prev => ({ ...prev, role: 'user' }));
      }


      console.log("Initial data processed based on user session.");
    } catch (err: any) {
      console.error("Critical error during initial data load:", err);
      setError("Failed to load application data. Error: " + err.message);
      if (err.message.includes("Authentication/Authorization failed")) {
        setCurrentUser(null);
        navigateTo(Page.Login);
      }
      setUsers([]); setPendingUsers([]); setTasks([]); setPrograms([]); setAssignments([]); setAdminLogs([]);
    } finally {
      setIsLoadingAppData(false);
    }
  }, []); // Removed navigateTo from dependencies as it causes issues here.

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);


  // Wrapper for setPreRegistrationForm to persist to localStorage
  const setPreRegistrationForm = (value: React.SetStateAction<typeof initialPreRegistrationFormState>) => {
    setPreRegistrationFormInternal(value);
  };

  const navigateTo = useCallback((page: Page, params?: Record<string, string>) => { let hash = `#${page}`; if (params && Object.keys(params).length > 0) { hash += `?${new URLSearchParams(params).toString()}`; } if (window.location.hash !== hash) { window.location.hash = hash; } else { _setCurrentPageInternal(page); /* Ensure internal state updates if hash is same */ } }, []);

  useEffect(() => {
    if (isLoadingAppData && !currentUser) return;

    const processHash = () => {
      clearMessages();
      const hash = window.location.hash.substring(1);
      const [pagePath, paramsString] = hash.split('?');
      const params = new URLSearchParams(paramsString || '');
      const targetPageFromHashPath = pagePath.toUpperCase() as Page | string;

      if (targetPageFromHashPath === Page.PreRegistration) {
        const refAdminIdFromHash = params.get('refAdminId');
        // Fetch users to verify admin only if users array is empty or stale. 
        // Small optimization: If users array is populated, use it directly.
        const adminUser = users.find(u => u.id === refAdminIdFromHash && u.role === 'admin');

        setPreRegistrationForm(prev => ({
          ...initialPreRegistrationFormState,
          referringAdminId: refAdminIdFromHash || '',
          referringAdminDisplayName: adminUser ? adminUser.displayName : (refAdminIdFromHash ? `Admin ID: ${refAdminIdFromHash}`: 'an administrator'),
          isReferralLinkValid: !!refAdminIdFromHash && !!adminUser // Link valid only if refAdminId exists AND is an admin
        }));
        if (!refAdminIdFromHash || !adminUser) {
          setError("Pre-registration link is invalid, missing administrator reference, or the referring admin is no longer valid.");
        }
        _setCurrentPageInternal(Page.PreRegistration);
        return;
      }

      if (!currentUser) {
        _setCurrentPageInternal(Page.Login);
        if (targetPageFromHashPath && targetPageFromHashPath !== Page.Login.toUpperCase() && window.location.hash !== `#${Page.Login}`) {
           navigateTo(Page.Login);
        }
        return;
      }

      // User is logged in
      const defaultPageDetermination = currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
      let newPage = (Object.values(Page).includes(targetPageFromHashPath as Page) ? targetPageFromHashPath : defaultPageDetermination) as Page;

      if ([Page.Login, Page.PreRegistration, Page.AdminRegistrationEmail, Page.AdminRegistrationProfile, Page.InitialAdminSetup].includes(newPage as Page)) {
        newPage = defaultPageDetermination;
      }

      const currentTopLevelPagePath = window.location.hash.substring(1).split('?')[0].toUpperCase();
      const targetParams = paramsString ? Object.fromEntries(params) : undefined;

      if (newPage !== currentTopLevelPagePath && Object.values(Page).includes(newPage)) {
           navigateTo(newPage, targetParams);
      }
      _setCurrentPageInternal(newPage);

      if (currentUser && currentUser.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${currentUser.id}`)) {
         setTimeout(() => {
            const finalCurrentPage = window.location.hash.substring(1).split('?')[0].toUpperCase() as Page | string;
            if (finalCurrentPage !== Page.Login.toUpperCase() && finalCurrentPage !== Page.PreRegistration.toUpperCase() && Object.values(Page).includes(finalCurrentPage as Page)) {
                setShowUserTour(true);
            }
        }, 500);
      }
    };

    processHash();
    window.addEventListener('hashchange', processHash);

    return () => {
      window.removeEventListener('hashchange', processHash);
    };
  }, [currentUser, navigateTo, clearMessages, users, isLoadingAppData, _setCurrentPageInternal]);


  useEffect(() => {
    if (currentPage === Page.UserProfile && currentUser) {
      setUserForm({
        email: currentUser.email,
        uniqueId: currentUser.uniqueId,
        displayName: currentUser.displayName,
        position: currentUser.position,
        userInterests: currentUser.userInterests || '',
        phone: currentUser.phone || '',
        notificationPreference: currentUser.notificationPreference || 'none',
        role: currentUser.role, // This will be 'admin' or 'user'
        password: '',
        confirmPassword: '',
        referringAdminId: currentUser.referringAdminId || ''
      });
    }
  }, [currentPage, currentUser]);

  const getAdminToNotify = useCallback((referringAdminId?: string): User | undefined => {
    if (referringAdminId) {
      const refAdmin = users.find(u => u.id === referringAdminId && u.role === 'admin');
      if (refAdmin) return refAdmin;
    }
    return users.find(u => u.role === 'admin');
  }, [users]);

const handleNewRegistration = async (e: React.FormEvent) => {
  e.preventDefault();
  clearMessages();

  const { name, email, password, confirmPassword, uniqueId, position } = newRegistrationForm;
  const adminExists = getAdminExists();

  if (!name.trim() || !email.trim() || !password.trim() || !confirmPassword.trim() || !uniqueId.trim()) {
    setError("Full Name, Email, Password, Confirm Password, and System ID are required.");
    return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    setError("Please enter a valid email address.");
    return;
  }
  if (password !== confirmPassword) {
    setError("Passwords do not match.");
    return;
  }
  const passwordValidationResult = validatePassword(password);
  if (!passwordValidationResult.isValid) {
    setError(passwordValidationResult.errors.join(" "));
    return;
  }

  const isFirstPossibleAdmin = !adminExists; // Simplified check
  const roleToRegister = isFirstPossibleAdmin ? 'admin' : 'user';

  if (roleToRegister === 'admin' && adminExists) {
    setError("Cannot register as admin. An administrator account already exists.");
    return;
  }

  const registrationData = {
    displayName: name,
    email,
    password,
    role: roleToRegister,
    uniqueId,
    position: position || (roleToRegister === 'admin' ? 'Administrator' : 'User Position'),
  };

  const endpoint = roleToRegister === 'admin' ? '/users/register' : '/pending-users';

  try {
    const response = await fetchData<{ success: boolean; user: BackendUser | BackendPendingUser; message?: string }>(endpoint, {
      method: 'POST',
      body: JSON.stringify(registrationData),
    });

    if (response && response.success && response.user) {
      if (roleToRegister === 'admin') {
        const createdAdmin = response.user as BackendUser;
        setUsers(prev => [...prev, createdAdmin as User]); // Add to local users state
        setSuccessMessage("Admin account registered successfully! You can now log in.");
        emailService.sendWelcomeRegistrationEmail(createdAdmin.email, createdAdmin.displayName, createdAdmin.role);
      } else {
        const createdPendingUser = response.user as BackendPendingUser;
        setPendingUsers(prev => [...prev, createdPendingUser as PendingUser]);
        setSuccessMessage("Registration submitted! Your account is pending administrator approval.");
        emailService.sendRegistrationPendingToUserEmail(createdPendingUser.email, createdPendingUser.displayName);
        const adminToNotify = getAdminToNotify();
        if (adminToNotify) {
          emailService.sendNewPendingRegistrationToAdminEmail(
            adminToNotify.email, adminToNotify.displayName,
            createdPendingUser.displayName, createdPendingUser.email
          );
        }
      }
      setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user', uniqueId: '', position: '' });
      setAuthView('login');
    } else {
      setError(response?.message || "Registration failed. Please check details and try again.");
    }
  } catch (err: any) {
    setError(err.message || "Registration failed. Please try again later.");
  }
};

const handlePreRegistrationSubmit = async (e: React.FormEvent) => {
  e.preventDefault();
  clearMessages();

  const { uniqueId, displayName, email, password, confirmPassword, referringAdminId } = preRegistrationForm;

  if (!uniqueId.trim() || !displayName.trim() || !email.trim() || !password.trim() || !confirmPassword.trim()) {
    setError("All fields (System ID, Display Name, Email, Password, Confirm Password) are required.");
    return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    setError("Please enter a valid email address.");
    return;
  }
  if (password !== confirmPassword) {
    setError("Passwords do not match.");
    return;
  }
  const passwordValidationResult = validatePassword(password);
  if (!passwordValidationResult.isValid) {
    setError(passwordValidationResult.errors.join(" "));
    return;
  }

  const newPendingUserData = {
    uniqueId, displayName, email, password,
    role: 'user' as Role, // Pre-registration always creates a 'user'
    referringAdminId: referringAdminId || undefined,
  };

  try {
    const response = await fetchData<{ success: boolean; user: BackendPendingUser; message?: string }>('/pending-users', {
      method: 'POST',
      body: JSON.stringify(newPendingUserData),
    });

    if (response && response.success && response.user) {
      const createdPendingUser = response.user as BackendPendingUser;
      setPendingUsers(prev => [...prev, createdPendingUser as PendingUser]);
      setSuccessMessage("Pre-registration submitted successfully! Your account is pending administrator approval.");
      setPreRegistrationForm(prev => ({ ...initialPreRegistrationFormState, referringAdminId: prev.referringAdminId, referringAdminDisplayName: prev.referringAdminDisplayName, isReferralLinkValid: prev.isReferralLinkValid }));

      const adminToNotify = getAdminToNotify(createdPendingUser.referringAdminId);
      emailService.sendPreRegistrationSubmittedToUserEmail(createdPendingUser.email, createdPendingUser.displayName, adminToNotify?.displayName || 'the administrator');
      if (adminToNotify) {
        emailService.sendPreRegistrationNotificationToAdminEmail(adminToNotify.email, adminToNotify.displayName, createdPendingUser.displayName, createdPendingUser.uniqueId);
      }
    } else {
      setError(response?.message || "Failed to submit pre-registration.");
    }
  } catch (err: any) {
    setError(err.message || "Failed to submit pre-registration. Please try again later.");
  }
};

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    const { email, password } = newLoginForm;

    if (!email.trim() || !password.trim()) {
      setError("Email and password are required.");
      return;
    }
     if (!/\S+@\S+\.\S+/.test(email)) {
      setError("Please enter a valid email address.");
      return;
    }

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; token: string; message?: string }>('/users/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (response && response.success && response.user && response.token) {
        const loggedInUserWithToken: User = {
          ...response.user,
          id: response.user.id || response.user._id!, // Ensure id is correctly assigned
          token: response.token
        };
        setCurrentUser(loggedInUserWithToken);

        setSuccessMessage(`Welcome back, ${loggedInUserWithToken.displayName}!`);
        setNewLoginForm({ email: '', password: '' });

        await loadInitialData(loggedInUserWithToken);

        const targetPage = loggedInUserWithToken.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
        navigateTo(targetPage);

        if (loggedInUserWithToken.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${loggedInUserWithToken.id}`)) {
          setShowUserTour(true);
        }
      } else {
        setError(response?.message || "Invalid email or password, or login failed on server.");
      }
    } catch (err: any) {
      setError(err.message || "Login failed. Please check your credentials or server status.");
    }
  };

  const handleLogout = async () => {
    clearMessages();
    try {
      await fetchData('/users/logout', { method: 'POST' });
    } catch (err: any) {
      console.warn("Logout API call failed (user will be logged out client-side anyway):", err.message);
    }
    setCurrentUser(null);
    setUsers([]);
    setPendingUsers([]);
    setTasks([]);
    setPrograms([]);
    setAssignments([]);
    setAdminLogs([]);
    setSuccessMessage("You have been logged out successfully.");
    _setCurrentPageInternal(Page.Login);
    navigateTo(Page.Login);
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!currentUser) return;

    const { uniqueId, displayName, position, userInterests, phone, notificationPreference, password, confirmPassword } = userForm;

    if (!uniqueId.trim() || !displayName.trim() || !position.trim()) {
        setError("System ID, Display Name, and Position are required.");
        return;
    }

    const updatePayload: Partial<User> & { password?: string } = {
      uniqueId, displayName, position, userInterests, phone, notificationPreference,
    };

    if (password) {
        if (password !== confirmPassword) {
            setError("New passwords do not match."); return;
        }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) {
            setError(passwordValidationResult.errors.join(" ")); return;
        }
        updatePayload.password = password;
    }

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>(`/users/${currentUser.id}`, {
        method: 'PUT',
        body: JSON.stringify(updatePayload),
      });

      if (response && response.success && response.user) {
        const updatedUserFromServer: User = {
            ...response.user,
            id: response.user.id || response.user._id!,
            token: localStorage.getItem(JWT_TOKEN_KEY) || undefined
        };
        setUsers(users.map(u => u.id === currentUser.id ? updatedUserFromServer : u));
        setCurrentUserInternal(updatedUserFromServer);
        setSuccessMessage("Profile updated successfully!");
        setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' }));
        await addAdminLogEntry(`User profile updated for ${updatedUserFromServer.displayName} (ID: ${updatedUserFromServer.uniqueId}).`);
      } else {
        setError(response?.message || "Failed to update profile.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to update profile.");
    }
  };

  const handleAdminUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!editingUserId || !currentUser || currentUser.role !== 'admin') return;

    const { email, uniqueId, displayName, position, userInterests, phone, notificationPreference, password, confirmPassword } = userForm;

    if (!email.trim() || !uniqueId.trim() || !displayName.trim() || !position.trim()) {
        setError("Email, System ID, Display Name, and Position are required."); return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
        setError("Please enter a valid email address for the user."); return;
    }

    const userBeingEdited = users.find(u => u.id === editingUserId);
    if (!userBeingEdited) { setError("User being edited not found."); return; }
    if (userBeingEdited.role === 'admin') { setError("Administrator account cannot be edited here. Use My Profile."); return; }


    const updatePayload: Partial<User> & { password?: string } = {
      email, uniqueId, displayName, position, userInterests, phone, notificationPreference,
      role: 'user', // Forcibly set role to 'user' as admin cannot promote/change role to admin here
    };

    if (password) {
        if (password !== confirmPassword) { setError("New passwords do not match."); return; }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) { setError(passwordValidationResult.errors.join(" ")); return; }
        updatePayload.password = password;
    }

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>(`/users/${editingUserId}`, {
        method: 'PUT',
        body: JSON.stringify(updatePayload),
      });

      if (response && response.success && response.user) {
        const baseUpdatedUser: User = { ...response.user, id: response.user.id || response.user._id!};
        setUsers(users.map(u => u.id === editingUserId ? baseUpdatedUser : u));
        setSuccessMessage(`User ${baseUpdatedUser.displayName} updated successfully!`);
        setEditingUserId(null); setUserForm(initialUserFormData);
        await addAdminLogEntry(`Admin updated user profile for ${baseUpdatedUser.displayName}.`);
        navigateTo(Page.UserManagement);
      } else {
        setError(response?.message || "Failed to update user.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to update user.");
    }
  };


  const handleCreateUserByAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();

    if (!currentUser || !currentUser.id || currentUser.role !== 'admin') {
        setError("Action not allowed or current user data is missing.");
        return;
    }

    const { email, uniqueId, displayName, position, userInterests, phone, notificationPreference, password, confirmPassword } = userForm;

    if (!email.trim() || !uniqueId.trim() || !displayName.trim() || !position.trim() || !password.trim() || !confirmPassword.trim()) {
        setError("Email, System ID, Display Name, Position, Password, and Confirm Password are required."); return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) { setError("Please enter a valid email address."); return; }
    if (password !== confirmPassword) { setError("Passwords do not match."); return; }
    const passVal = validatePassword(password);
    if (!passVal.isValid) { setError(passVal.errors.join(" ")); return; }

    const newUserData = {
      email, uniqueId, password, 
      role: 'user' as Role, // Always create as 'user'
      displayName, position, userInterests, phone, notificationPreference,
      referringAdminId: currentUser.id
    };

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>('/users/register', { // Using /users/register, backend must handle 'admin' role override if needed for first user
        method: 'POST',
        body: JSON.stringify(newUserData),
      });

      if (response && response.success && response.user) {
        const createdUser: User = {...response.user, id: response.user.id || response.user._id!};
        setUsers(prev => [...prev, createdUser]);
        setSuccessMessage(`User ${createdUser.displayName} created successfully!`);
        setUserForm(initialUserFormData);
        emailService.sendWelcomeRegistrationEmail(createdUser.email, createdUser.displayName, createdUser.role);
        await addAdminLogEntry(`Admin created new user: ${createdUser.displayName}, Role: User.`);
        navigateTo(Page.UserManagement);
      } else {
        setError(response?.message || "Failed to create user.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to create user.");
    }
  };

  const handleApprovePendingUser = async () => {
    if (!approvingPendingUser || !currentUser || currentUser.role !== 'admin') {
      setError("Approval failed: Invalid operation or permissions."); return;
    }
    clearMessages();

    const approvalData = {
        position: userForm.position || 'Default Position',
        userInterests: userForm.userInterests || '',
        phone: userForm.phone || '',
        notificationPreference: userForm.notificationPreference || 'email',
        role: 'user' as Role, // Always approve as 'user'
    };
    
    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>(`/pending-users/approve/${approvingPendingUser.id}`, {
        method: 'POST',
        body: JSON.stringify(approvalData),
      });

      if (response && response.success && response.user) {
        const createdUser: User = {...response.user, id: response.user.id || response.user._id!};
        setUsers(prev => [...prev, createdUser]);
        setPendingUsers(prev => prev.filter(pu => pu.id !== approvingPendingUser.id));

        setApprovingPendingUser(null); setUserForm(initialUserFormData);
        setSuccessMessage(`User ${createdUser.displayName} approved and account activated!`);

        emailService.sendAccountActivatedByAdminEmail(createdUser.email, createdUser.displayName, currentUser.displayName);
        await addAdminLogEntry(`Admin approved pending user: ${createdUser.displayName} as User.`);
      } else {
        setError(response?.message || "Failed to approve user.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to approve user.");
    }
  };

  const handleRejectPendingUser = async (pendingUserId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    clearMessages();
    try {
      const userToReject = pendingUsers.find(pu => pu.id === pendingUserId);
      const response = await fetchData<{success: boolean, message?:string}>(`/pending-users/${pendingUserId}`, { method: 'DELETE' });

      if(response && response.success){
        setPendingUsers(prev => prev.filter(pu => pu.id !== pendingUserId));
        setSuccessMessage(`Pending registration for ${userToReject?.displayName || 'user'} rejected.`);
        await addAdminLogEntry(`Admin rejected pending registration for ${userToReject?.displayName}.`);
      } else {
        setError(response?.message || "Failed to reject pending user.");
      }
    } catch (err:any) {
        setError(err.message || "Failed to reject pending user registration.");
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    if (currentUser.id === userId) { setError("Admins cannot delete their own accounts."); return; }
    
    const userToDelete = users.find(u => u.id === userId);
    if (userToDelete && userToDelete.role === 'admin') {
        setError("Cannot delete an administrator account using this function.");
        return;
    }

    clearMessages();
    try {
      const response = await fetchData<{success: boolean, message?:string}>(`/users/${userId}`, { method: 'DELETE' });
      if(response && response.success) {
        setUsers(prev => prev.filter(u => u.id !== userId));
        const updatedAssignments = await fetchData<Assignment[]>('/assignments', {}, []);
        setAssignments(updatedAssignments || []);
        setSuccessMessage(`User ${userToDelete?.displayName || 'user'} deleted.`);
        await addAdminLogEntry(`Admin deleted user: ${userToDelete?.displayName}.`);
      } else {
         setError(response?.message || "Failed to delete user.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to delete user.");
    }
  };

  const handleGeneratePreRegistrationLink = () => {
    if (!currentUser || currentUser.role !== 'admin') {
      setError("Only admins can generate pre-registration links."); return;
    }
    const link = `${window.location.origin}${window.location.pathname}#${Page.PreRegistration}?refAdminId=${currentUser.id}`;
    setGeneratedLink(link);
    setSuccessMessage("Pre-registration link generated. Share it with the intended user.");
    addAdminLogEntry(`Admin ${currentUser.displayName} generated a pre-registration link.`);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setInfoMessage("Link copied to clipboard!");
    }).catch(err => {
      console.error('Failed to copy link: ', err);
      setError("Failed to copy link. Please copy it manually.");
    });
  };

  const handleCreateProgram = async (e: React.FormEvent) => {
    e.preventDefault(); clearMessages();
    if (!programForm.name.trim() || !programForm.description.trim()) { setError("Program name and description are required."); return; }
    const newProgramData: Omit<Program, 'id'> = { ...programForm };
    try {
      const createdProgram = await fetchData<Program>('/programs', { method: 'POST', body: JSON.stringify(newProgramData) });
      if (createdProgram && createdProgram.id) {
        setPrograms(prev => [...prev, createdProgram]);
        setSuccessMessage("Program created successfully!");
        setProgramForm({ name: '', description: '' });
        if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} created program: ${createdProgram.name}.`);
      } else { setError("Failed to create program."); }
    } catch (err:any) { setError(err.message || "Failed to create program."); }
  };

  const handleDeleteProgram = async (programId: string) => {
    clearMessages();
    try {
      const programToDelete = programs.find(p => p.id === programId);
      await fetchData(`/programs/${programId}`, { method: 'DELETE' });
      setPrograms(prev => prev.filter(p => p.id !== programId));
      const updatedTasks = await fetchData<Task[]>('/tasks', {}, []); setTasks(updatedTasks || []);
      setSuccessMessage(`Program "${programToDelete?.name}" deleted.`);
      if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} deleted program: ${programToDelete?.name}.`);
    } catch (err:any) { setError(err.message || "Failed to delete program."); }
  };


  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault(); clearMessages();
    if (!taskForm.title.trim() || !taskForm.description.trim() || !taskForm.requiredSkills.trim()) { setError("Task title, description, and required skills are required."); return; }
    const associatedProgram = programs.find(p => p.id === taskForm.programId);
    const newTaskData: Partial<Task> = { ...taskForm, deadline: taskForm.deadline ? new Date(taskForm.deadline).toISOString().split('T')[0] : undefined, programName: associatedProgram?.name };
    try {
      const createdTask = await fetchData<Task>('/tasks', { method: 'POST', body: JSON.stringify(newTaskData) });
      if (createdTask && createdTask.id) {
        setTasks(prev => [...prev, createdTask]);
        setSuccessMessage("Task created successfully!");
        setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' });
        if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} created task: ${createdTask.title}.`);
      } else { setError("Failed to create task."); }
    } catch (err:any) { setError(err.message || "Failed to create task."); }
  };

  const handleDeleteTask = async (taskId: string) => {
    clearMessages();
    try {
      const taskToDelete = tasks.find(t => t.id === taskId);
      await fetchData(`/tasks/${taskId}`, { method: 'DELETE' });
      setTasks(prev => prev.filter(t => t.id !== taskId));
      const updatedAssignments = await fetchData<Assignment[]>('/assignments', {}, []); setAssignments(updatedAssignments || []);
      setSuccessMessage(`Task "${taskToDelete?.title}" deleted.`);
      if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} deleted task: ${taskToDelete?.title}.`);
    } catch (err:any) { setError(err.message || "Failed to delete task."); }
  };

  const handleGetAssignmentSuggestion = async () => {
    if (!selectedTaskForAssignment) { setError("Please select a task first."); return; }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    if (!task) { setError("Selected task not found."); return; }
    const usersEligible = users.filter(u => u.role === 'user' && !assignments.some(a => a.taskId === task.id && a.personId === u.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user')));
    setIsLoadingSuggestion(true); setError(null); setAssignmentSuggestion(null);
    try {
      const suggestion = await getAssignmentSuggestion(task, usersEligible, programs, assignments);
      setAssignmentSuggestion(suggestion);
      if(suggestion?.suggestedPersonName){ setInfoMessage(`AI Suggestion: ${suggestion.suggestedPersonName}. Justification: ${suggestion.justification}`); }
      else if (suggestion?.justification) { setInfoMessage(`AI: ${suggestion.justification}`); }
      else { setInfoMessage("AI could not provide a suggestion."); }
      if(currentUser) await addAdminLogEntry(`Admin requested AI suggestion for task: ${task.title}.`);
    } catch (err: any) { setError(`AI suggestion failed: ${err.message || "Unknown error"}`); }
    finally { setIsLoadingSuggestion(false); }
  };

  const handleAssignTask = async (e: React.FormEvent, suggestedPersonDisplayName?: string | null) => {
    e.preventDefault(); clearMessages();
    const personIdToAssign = (e.target as HTMLFormElement).assignPerson.value;
    const specificDeadline = (e.target as HTMLFormElement).specificDeadline?.value;
    if (!selectedTaskForAssignment || !personIdToAssign) { setError("Task and person must be selected."); return; }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    const person = users.find(u => u.id === personIdToAssign);
    if (!task || !person) { setError("Selected task or person not found."); return; }
    if (assignments.some(a => a.taskId === task.id && a.personId === person.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))) { setError(`${person.displayName} is already assigned this task or pending acceptance.`); return; }
    const justification = suggestedPersonDisplayName === person.displayName && assignmentSuggestion?.justification ? assignmentSuggestion.justification : 'Manually assigned by admin.';
    const newAssignmentData: Partial<Assignment> = { taskId: task.id, personId: person.id, taskTitle: task.title, personName: person.displayName, justification, status: 'pending_acceptance', deadline: specificDeadline || task.deadline, };
    try {
      const createdAssignment = await fetchData<Assignment>('/assignments', { method: 'POST', body: JSON.stringify(newAssignmentData) });
      if (createdAssignment && createdAssignment.taskId) {
        setAssignments(prev => [...prev, createdAssignment]);
        setSuccessMessage(`Task "${task.title}" assigned to ${person.displayName}.`);
        setSelectedTaskForAssignment(null); setAssignmentSuggestion(null); setAssignmentForm({ specificDeadline: '' });
        if (person.notificationPreference === 'email' && person.email) { emailService.sendTaskProposalEmail(person.email, person.displayName, task.title, currentUser?.displayName || "Admin", createdAssignment.deadline); }
        if(currentUser) await addAdminLogEntry(`Admin assigned task "${task.title}" to ${person.displayName}.`);
      } else { setError("Failed to assign task."); }
    } catch (err:any) { setError(err.message || "Failed to assign task."); }
  };

  const updateAssignmentStatus = async (taskId: string, personId: string, newStatus: AssignmentStatus, additionalData: Record<string, any> = {}) => {
    if (!currentUser && newStatus !== 'pending_acceptance') return null;
    clearMessages();
    const payload = { taskId, personId, status: newStatus, ...additionalData };
    try {
      const updatedAssignment = await fetchData<Assignment>(`/assignments`, { method: 'PATCH', body: JSON.stringify(payload) });
      if (updatedAssignment && updatedAssignment.taskId) {
        setAssignments(prev => prev.map(a => (a.taskId === taskId && a.personId === personId) ? updatedAssignment : a));
        return updatedAssignment;
      } else { setError(`Failed to update task status. Server did not confirm.`); return null; }
    } catch (err:any) { setError(err.message || `Failed to update task status.`); throw err; }
  };


  const handleUserAcceptTask = async (taskId: string) => {
    if (!currentUser) return;
    try {
        const updatedAssignment = await updateAssignmentStatus(taskId, currentUser.id, 'accepted_by_user');
        if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" accepted.`);
            const admin = getAdminToNotify(users.find(u=>u.id === currentUser.referringAdminId)?.id);
            if (admin?.notificationPreference === 'email' && admin.email) { emailService.sendTaskStatusUpdateToAdminEmail(admin.email, admin.displayName, currentUser.displayName, updatedAssignment.taskTitle, "accepted"); }
        }
    } catch (e) { /* error set by updateAssignmentStatus */ }
  };

  const handleUserDeclineTask = async (taskId: string) => {
    if (!currentUser) return;
     try {
        const updatedAssignment = await updateAssignmentStatus(taskId, currentUser.id, 'declined_by_user');
         if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" declined.`);
            const admin = getAdminToNotify(users.find(u=>u.id === currentUser.referringAdminId)?.id);
            if (admin?.notificationPreference === 'email' && admin.email) { emailService.sendTaskStatusUpdateToAdminEmail(admin.email, admin.displayName, currentUser.displayName, updatedAssignment.taskTitle, "declined"); }
        }
    } catch (e) { /* error set */ }
  };

  const handleUserSubmitTask = async (taskId: string, delayReason?: string) => {
    if (!currentUser) return;
    const assignment = assignments.find(a => a.taskId === taskId && a.personId === currentUser.id && a.status === 'accepted_by_user');
    if (!assignment) { setError("Task not found or not accepted."); return; }
    const submissionDate = new Date();
    let newStatus: AssignmentStatus = 'submitted_on_time';
    if (assignment.deadline && submissionDate > new Date(assignment.deadline)) {
      newStatus = 'submitted_late';
      if (!delayReason && assignmentToSubmitDelayReason === `${assignment.taskId}-${assignment.personId}`) { setError("Reason required for late submission."); return; }
    }
    const additionalData: any = { userSubmissionDate: submissionDate.toISOString() };
    if (newStatus === 'submitted_late') additionalData.userDelayReason = delayReason || userSubmissionDelayReason;
    try {
        const updated = await updateAssignmentStatus(taskId, currentUser.id, newStatus, additionalData);
        if (updated) {
            setSuccessMessage(`Task "${updated.taskTitle}" submitted.`);
            setUserSubmissionDelayReason(''); setAssignmentToSubmitDelayReason(null);
            const admin = getAdminToNotify(users.find(u=>u.id === currentUser.referringAdminId)?.id);
            if (admin?.notificationPreference === 'email' && admin.email) { emailService.sendTaskStatusUpdateToAdminEmail(admin.email, admin.displayName, currentUser.displayName, updated.taskTitle, `submitted (${newStatus.replace(/_/g, ' ')})`); }
        }
    } catch (e) { /* error set */ }
  };

  const handleAdminApproveTaskCompletion = async (taskId: string, personId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
     try {
        const updated = await updateAssignmentStatus(taskId, personId, 'completed_admin_approved');
        if (updated) {
            const user = users.find(u => u.id === personId);
            setSuccessMessage(`Completion of task "${updated.taskTitle}" by ${user?.displayName || 'user'} approved.`);
            if (user?.notificationPreference === 'email' && user.email) { emailService.sendTaskCompletionApprovedToUserEmail(user.email, user.displayName, updated.taskTitle, currentUser.displayName); }
            await addAdminLogEntry(`Admin approved task completion for "${updated.taskTitle}" by ${user?.displayName}.`);
        }
    } catch (e) { /* error set */ }
  };

  const addAdminLogEntry = async (logText: string, imagePreviewUrl?: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    const newLogData: Omit<AdminLogEntry, 'id'> = { adminId: currentUser.id, adminDisplayName: currentUser.displayName, timestamp: new Date().toISOString(), logText, imagePreviewUrl };
    try {
        const createdLog = await fetchData<AdminLogEntry>('/admin-logs', { method: 'POST', body: JSON.stringify(newLogData) });
        if (createdLog?.id) setAdminLogs(prev => [createdLog, ...prev]);
        else console.error("Failed to save admin log to backend.");
    } catch (error: any) { console.error("Failed to save admin log:", error); }
  };

  const handleAdminLogSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminLogText.trim() && !adminLogImageFile) { setError("Log text or an image is required."); return; }
    setIsSubmittingLog(true); clearMessages();
    let imagePreviewUrl: string | undefined = undefined;
    if (adminLogImageFile) {
        try {
            imagePreviewUrl = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = () => resolve(reader.result as string);
                reader.onerror = reject;
                reader.readAsDataURL(adminLogImageFile);
            });
        } catch (error) { setError("Failed to process image file."); setIsSubmittingLog(false); return; }
    }
    try {
        await addAdminLogEntry(adminLogText || `Image log by ${currentUser?.displayName}`, imagePreviewUrl);
        setSuccessMessage("Admin log entry added.");
        setAdminLogText(''); setAdminLogImageFile(null);
        const fileInput = document.getElementById('adminLogImage') as HTMLInputElement; if (fileInput) fileInput.value = '';
    } catch (err: any) { setError("Failed to submit admin log: " + err.message); }
    finally { setIsSubmittingLog(false); }
  };


  const handleForgotPassword = async () => {
    clearMessages();
    const emailToReset = newLoginForm.email;
    if (!emailToReset || !/\S+@\S+\.\S+/.test(emailToReset)) { setError("Please enter a valid email address."); return; }
    try {
        await fetchData('/users/forgot-password', { method: 'POST', body: JSON.stringify({ email: emailToReset }) });
        setInfoMessage(`If an account exists for ${emailToReset}, a password reset link has been sent.`);
    } catch (err: any) {
        console.error("Forgot password API call failed:", err);
        setInfoMessage(`If an account exists for ${emailToReset}, instructions will be sent. (Error: ${err.message})`);
    }
  };

  const handleCompleteUserTour = (completed: boolean) => {
    setShowUserTour(false);
    if (currentUser) {
        localStorage.setItem(`hasCompletedUserTour_${currentUser.id}`, 'true');
        if (completed) setSuccessMessage("Great! You've completed the tour.");
        else setInfoMessage("Tour skipped.");
    }
  };


  if (isLoadingAppData && !localStorage.getItem(JWT_TOKEN_KEY)) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-bground p-4">
        <LoadingSpinner />
        <p className="mt-4 text-textlight">Loading application...</p>
        {error && <div className="mt-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg max-w-md w-full" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p></div>}
      </div>
    );
  }

  const UIMessages: React.FC = () => (
    <>
      {error && <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg w-full" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
      {successMessage && <div className="mb-4 p-3 bg-green-100 border-green-400 text-green-700 rounded-md shadow-lg w-full" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
      {infoMessage && <div className="mb-4 p-3 bg-blue-100 border-blue-400 text-blue-700 rounded-md shadow-lg w-full" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
    </>
  );

  if (isLoadingAppData && !currentUser) {
     return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-bground p-4">
        <LoadingSpinner />
        <p className="mt-4 text-textlight">Authenticating...</p>
      </div>
    );
  }


  if (!currentUser || currentPage === Page.Login || currentPage === Page.PreRegistration) {
    if (currentPage === Page.PreRegistration) {
      return (
        <PreRegistrationFormPage
          formState={preRegistrationForm}
          setFormState={setPreRegistrationForm}
          onSubmit={handlePreRegistrationSubmit}
          error={error}
          successMessage={successMessage}
          infoMessage={infoMessage}
          clearMessages={clearMessages}
          navigateToLogin={() => navigateTo(Page.Login)}
        />
      );
    }

    const adminExists = getAdminExists();
    const isFirstPossibleAdmin = !adminExists;


    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4 main-app-scope">
        {isLoadingAppData && <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-50 flex items-center justify-center z-50"><LoadingSpinner /><p className="text-white ml-2">Loading...</p></div>}
        <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-md">
          <UIMessages />
          <h2 className="text-3xl font-bold text-textlight mb-6 text-center">
            Task Assignment Assistant
          </h2>

          {authView === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-5">
              <h3 className="text-xl font-semibold text-textlight mb-4">Login</h3>
              <div>
                <label htmlFor="loginEmail" className="block text-sm font-medium text-textlight">Email Address</label>
                <AuthFormInput type="email" id="loginEmail" aria-label="Email for login" placeholder="you@example.com" value={newLoginForm.email} onChange={(e) => setNewLoginForm({ ...newLoginForm, email: e.target.value })} required autoComplete="email" />
              </div>
              <div>
                <label htmlFor="loginPassword" className="block text-sm font-medium text-textlight">Password</label>
                <AuthFormInput type="password" id="loginPassword" aria-label="Password for login" placeholder="Enter your password" value={newLoginForm.password} onChange={(e) => setNewLoginForm({ ...newLoginForm, password: e.target.value })} required autoComplete="current-password" />
              </div>
              <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm" disabled={isLoadingAppData}>
                {isLoadingAppData ? <LoadingSpinner /> : 'Sign In'}
              </button>
              <div className="text-sm text-center"> <button type="button" onClick={handleForgotPassword} className="font-medium text-authLink hover:underline"> Forgot password? </button> </div>
            </form>
          ) : (
            <form onSubmit={handleNewRegistration} className="space-y-5">
              <h3 className="text-xl font-semibold text-textlight mb-4">Register New Account</h3>
              <div> <label htmlFor="regName" className="block text-sm font-medium text-textlight">Full Name</label> <AuthFormInput type="text" id="regName" aria-label="Full name for registration" placeholder="Your Full Name" value={newRegistrationForm.name} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, name: e.target.value })} required autoComplete="name" /> </div>
              <div> <label htmlFor="regEmail" className="block text-sm font-medium text-textlight">Email Address</label> <AuthFormInput type="email" id="regEmail" aria-label="Email for registration" placeholder="you@example.com" value={newRegistrationForm.email} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, email: e.target.value })} required autoComplete="email" /> </div>
              <div> <label htmlFor="regUniqueId" className="block text-sm font-medium text-textlight">System ID / Username</label> <AuthFormInput type="text" id="regUniqueId" aria-label="System ID for registration" placeholder="Create a unique ID" value={newRegistrationForm.uniqueId} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, uniqueId: e.target.value })} required /> </div>
              <div> <label htmlFor="regPassword" className="block text-sm font-medium text-textlight">Password</label> <AuthFormInput type="password" id="regPassword" aria-label="Password for registration" placeholder="Create a password" value={newRegistrationForm.password} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, password: e.target.value })} required autoComplete="new-password" aria-describedby="passwordHelpReg"/> <p id="passwordHelpReg" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p> </div>
              <div> <label htmlFor="regConfirmPassword" className="block text-sm font-medium text-textlight">Confirm Password</label> <AuthFormInput type="password" id="regConfirmPassword" aria-label="Confirm password for registration" placeholder="Confirm your password" value={newRegistrationForm.confirmPassword} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, confirmPassword: e.target.value })} required autoComplete="new-password" /> </div>

              <div>
                  <label htmlFor="regRoleInfo" className="block text-sm font-medium text-textlight">Role</label>
                  <input type="text" id="regRoleInfo" value={isFirstPossibleAdmin ? "Admin (Auto-assigned)" : "User (Pending Approval)"}  readOnly className="mt-1 block w-full px-3 py-2 bg-gray-100 border border-gray-300 rounded-md shadow-sm text-gray-700"/>
                  <small className="text-xs text-gray-500">
                    {isFirstPossibleAdmin ? "First user will be registered as Admin." : "General registration is for 'User' role and requires admin approval. Only one Admin account is allowed."}
                  </small>
              </div>

              <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm" disabled={isLoadingAppData}>
                {isLoadingAppData ? <LoadingSpinner/> : 'Register'}
              </button>
            </form>
          )}
          <p className="text-center text-sm text-textlight mt-6">
            {authView === 'login' ? "Don't have an account?" : "Already have an account?"}{' '}
            <button type="button" onClick={() => { clearMessages(); setAuthView(authView === 'login' ? 'register' : 'login'); }} className="font-medium text-authLink hover:underline">
              {authView === 'login' ? 'Register here' : 'Sign in here'}
            </button>
          </p>
           { !isLoadingAppData && isFirstPossibleAdmin && authView === 'login' && (
            <div className="mt-6 p-4 bg-yellow-50 border border-yellow-300 rounded-md">
              <p className="text-sm text-yellow-700">
                <strong className="font-bold">First-time Setup:</strong> No admin accounts detected. The first user to register will become an administrator.
                Please <button type="button" onClick={() => { clearMessages(); setAuthView('register'); }} className="font-medium text-authLink hover:underline">register as Admin</button>.
              </p>
            </div>
          )}
        </div>
        <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by SHAIK MOAHAMMED NAWAZ.</p>
        </footer>
      </div>
    );
  }


  return (
    <div className="flex h-screen bg-bground main-app-scope">
       {isLoadingAppData && <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-70 flex items-center justify-center z-[100]"><LoadingSpinner /><p className="text-white ml-3 text-lg">Loading data...</p></div>}
       {showUserTour && currentUser && <UserTour user={currentUser} onClose={handleCompleteUserTour} />}
      
      <Sidebar 
        currentUser={currentUser}
        currentPage={currentPage}
        navigateTo={navigateTo}
        handleLogout={handleLogout}
      />

      <main className="flex-1 p-6 overflow-y-auto">
        <UIMessages />

        {currentPage === Page.Dashboard && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">Admin Dashboard</h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Users</h3> <p className="text-3xl font-bold text-textlight">{users.length}</p> <p className="text-sm text-neutral">Total active users</p> </div>
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Pending Approvals</h3> <p className="text-3xl font-bold text-textlight">{pendingUsers.length}</p> <p className="text-sm text-neutral">Users awaiting approval</p> </div>
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Tasks</h3> <p className="text-3xl font-bold text-textlight">{tasks.length}</p> <p className="text-sm text-neutral">Total defined tasks</p> </div>
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Programs</h3> <p className="text-3xl font-bold text-textlight">{programs.length}</p> <p className="text-sm text-neutral">Total programs</p> </div>
                 <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Active Assignments</h3> <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'accepted_by_user' || a.status === 'pending_acceptance').length}</p> <p className="text-sm text-neutral">Tasks currently assigned</p> </div>
                 <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Completed Tasks</h3> <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'completed_admin_approved').length}</p> <p className="text-sm text-neutral">Successfully finished tasks</p> </div>
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-primary mb-4">Admin Log Entry</h3>
              <form onSubmit={handleAdminLogSubmit} className="space-y-4">
                <FormTextarea label="Log Message" id="adminLogText" value={adminLogText} onChange={(e) => setAdminLogText(e.target.value)} placeholder="Enter log details..." />
                <div> <label htmlFor="adminLogImage" className="block text-sm font-medium text-textlight">Attach Image (Optional)</label> <input type="file" id="adminLogImage" aria-label="Attach image to admin log" accept="image/*" onChange={(e) => setAdminLogImageFile(e.target.files ? e.target.files[0] : null)} className="mt-1 block w-full text-sm text-neutral file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-primary file:text-white hover:file:bg-blue-600"/> </div>
                <button type="submit" className="btn-primary" disabled={isSubmittingLog}> {isSubmittingLog ? <LoadingSpinner/> : 'Add Log Entry'} </button>
              </form>
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-primary mb-4">Recent Admin Logs</h3>
                {adminLogs.length === 0 ? <p className="text-neutral">No admin logs.</p> : (
                    <ul className="space-y-3 max-h-96 overflow-y-auto">
                    {adminLogs.slice(0, 10).map(log => ( <li key={log.id} className="p-3 bg-bground rounded-md shadow-sm"> <p className="text-sm text-textlight"><strong className="font-medium">{log.adminDisplayName}</strong>: {log.logText}</p> <p className="text-xs text-neutral mt-1">{new Date(log.timestamp).toLocaleString()}</p> {log.imagePreviewUrl && <div className="mt-2"><img src={log.imagePreviewUrl} alt="Log attachment" className="max-h-40 max-w-xs rounded border border-neutral"/></div>} </li> ))}
                    </ul>
                )}
            </div>
          </div>
        )}

        {currentPage === Page.UserProfile && (
          <div className="max-w-2xl mx-auto bg-surface p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Profile</h2>
            <form onSubmit={handleUpdateProfile} className="space-y-4">
              <FormInput label="Email (Cannot be changed)" id="profileEmail" type="email" value={userForm.email} readOnly disabled description="Login email cannot be changed." />
              <FormInput label="System ID / Username" id="profileUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required description="Your unique system identifier." />
              <FormInput label="Display Name" id="profileDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
              <FormInput label="Position / Role Title" id="profilePosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
              <FormTextarea label="My Skills & Interests" id="profileUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} placeholder="e.g., Python, data analysis" />
              <FormInput label="Phone (Optional)" id="profilePhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
              <FormSelect label="Notification Preference" id="profileNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}> <option value="email">Email</option> <option value="phone" disabled>Phone (Not Implemented)</option> <option value="none">None</option> </FormSelect>
               <div className="pt-4 border-t border-gray-200">
                <h3 className="text-lg font-medium text-textlight mb-2">Change Password (Optional)</h3>
                <FormInput label="New Password" id="profileNewPassword" type="password" value={userForm.password} onChange={e => setUserForm({...userForm, password: e.target.value})} description={passwordRequirementsText} autoComplete="new-password" />
                <FormInput label="Confirm New Password" id="profileConfirmPassword" type="password" value={userForm.confirmPassword} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} autoComplete="new-password" />
              </div>
              <button type="submit" className="btn-primary">Update Profile</button>
            </form>
          </div>
        )}

        {currentPage === Page.UserManagement && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-1">User Management</h2>
            <p className="text-sm text-neutral mb-6">Manage accounts, approve registrations, view details.</p>

            {editingUserId || approvingPendingUser || new URLSearchParams(window.location.hash.split('?')[1]).get('action') === 'createUser' ? (
              <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-accent mb-4"> {editingUserId ? 'Edit User' : (approvingPendingUser ? `Approve: ${approvingPendingUser.displayName}` : 'Create New User')} </h3>
                <form onSubmit={editingUserId ? handleAdminUpdateUser : (approvingPendingUser ? handleApprovePendingUser : handleCreateUserByAdmin)} className="space-y-4">
                  <FormInput label="Email" id="userMgmtEmail" type="email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required />
                  <FormInput label="System ID / Username" id="userMgmtUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required />
                  <FormInput label="Display Name" id="userMgmtDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
                  <FormInput label="Position / Role Title" id="userMgmtPosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                  <FormTextarea label="Skills & Interests" id="userMgmtUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                  <FormInput label="Phone (Optional)" id="userMgmtPhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                  <FormSelect label="Notification Preference" id="userMgmtNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}> <option value="email">Email</option> <option value="phone" disabled>Phone (Not Implemented)</option> <option value="none">None</option> </FormSelect>
                  
                  <div>
                    <label htmlFor="userMgmtRoleDisplay" className="block text-sm font-medium text-textlight">Role</label>
                    <input 
                      type="text" 
                      id="userMgmtRoleDisplay" 
                      value="User" 
                      readOnly 
                      disabled 
                      className="mt-1 block w-full px-3 py-2 bg-gray-100 border-gray-300 rounded-md shadow-sm text-gray-700"
                    />
                     {(editingUserId && users.find(u => u.id === editingUserId)?.role === 'admin') && 
                        <p className="mt-1 text-xs text-neutral">Admin role cannot be changed here. Use My Profile for own details.</p>
                     }
                     {(!editingUserId && !approvingPendingUser) &&
                        <p className="mt-1 text-xs text-neutral">New users are created with the 'User' role.</p>
                     }
                     {approvingPendingUser &&
                        <p className="mt-1 text-xs text-neutral">Pending users are approved with the 'User' role.</p>
                     }
                  </div>

                  {!approvingPendingUser && (
                    <div className="pt-4 border-t border-gray-200">
                        <h3 className="text-lg font-medium text-textlight mb-2">{editingUserId ? 'Reset Password (Optional)' : 'Set Password'}</h3>
                        <FormInput label="Password" id="userMgmtPassword" type="password" value={userForm.password} onChange={e => setUserForm({...userForm, password: e.target.value})} required={!editingUserId} description={passwordRequirementsText} autoComplete="new-password"/>
                        <FormInput label="Confirm Password" id="userMgmtConfirmPassword" type="password" value={userForm.confirmPassword} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} required={!editingUserId} autoComplete="new-password" />
                    </div>
                  )}
                  <div className="flex space-x-3"> <button type="submit" className="btn-success"> {editingUserId ? 'Save Changes' : (approvingPendingUser ? 'Approve & Create' : 'Create User')} </button> <button type="button" className="btn-neutral" onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); clearMessages(); navigateTo(Page.UserManagement); }}>Cancel</button> </div>
                </form>
              </div>
            ) : ( <button onClick={() => { setUserForm({...initialUserFormData, role: 'user'}); clearMessages(); navigateTo(Page.UserManagement, {action: 'createUser'}); }} className="btn-primary mb-4 flex items-center"><PlusCircleIcon className="w-5 h-5 mr-2"/>Add New User</button> )}

             <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-3">Pre-registration Link</h3>
              <button onClick={handleGeneratePreRegistrationLink} className="btn-secondary flex items-center"><KeyIcon className="w-5 h-5 mr-2"/>Generate Link</button>
              {generatedLink && ( <div className="mt-3 p-3 bg-bground rounded"> <p className="text-sm text-textlight break-all">{generatedLink}</p> <button onClick={() => copyToClipboard(generatedLink)} className="text-xs btn-neutral mt-2">Copy</button> </div> )}
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Pending Approvals ({pendingUsers.length})</h3>
              {pendingUsers.length === 0 ? <p className="text-neutral">No users awaiting approval.</p> : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-bground"> <tr> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Name</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Email / System ID</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Intended Role / Date</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Actions</th> </tr> </thead>
                    <tbody className="bg-surface divide-y divide-gray-200">
                      {pendingUsers.map(pu => {
                        const canApprove = !pu.referringAdminId || (pu.referringAdminId && currentUser && currentUser.id === pu.referringAdminId);
                        return (
                          <tr key={pu.id}>
                            <td className="px-4 py-3 text-sm text-textlight">{pu.displayName}</td>
                            <td className="px-4 py-3 text-sm text-textlight">{pu.email} ({pu.uniqueId})</td>
                            <td className="px-4 py-3 text-sm text-textlight">{pu.role} <br/><span className="text-xs text-neutral">{new Date(pu.submissionDate).toLocaleDateString()}</span></td>
                            <td className="px-4 py-3 text-sm space-x-2">
                              <button
                                onClick={() => { setApprovingPendingUser(pu); setUserForm({ email: pu.email, uniqueId: pu.uniqueId, displayName: pu.displayName, position: '', userInterests: '', phone: '', notificationPreference: 'email', role: 'user', password: '', confirmPassword: '', referringAdminId: pu.referringAdminId || currentUser?.id || '' }); setEditingUserId(null); navigateTo(Page.UserManagement, {action: 'approveUser', userId: pu.id}); clearMessages(); }}
                                className={`btn-success text-xs px-2 py-1 ${!canApprove ? 'opacity-50 cursor-not-allowed' : ''}`}
                                disabled={!canApprove}
                                title={!canApprove ? "Approval restricted to the referring admin or for general registrations." : "Approve this user"}
                              >
                                Approve
                              </button>
                              <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger text-xs px-2 py-1">Reject</button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Active Users ({users.length})</h3>
              {users.length === 0 ? <p className="text-neutral">No active users.</p> : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-bground"> <tr> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Name</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Email / System ID</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Role / Position</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Actions</th> </tr> </thead>
                    <tbody className="bg-surface divide-y divide-gray-200">
                      {users.map(user => ( <tr key={user.id}> <td className="px-4 py-3 text-sm font-medium text-textlight">{user.displayName}</td> <td className="px-4 py-3 text-sm text-textlight">{user.email}<br/><span className="text-xs text-neutral">{user.uniqueId}</span></td> <td className="px-4 py-3 text-sm text-textlight capitalize">{user.role}<br/><span className="text-xs text-neutral">{user.position}</span></td> <td className="px-4 py-3 text-sm space-x-2"> 
                        {currentUser.id !== user.id && user.role !== 'admin' && (
                            <button onClick={() => { setEditingUserId(user.id); setUserForm({ email: user.email, uniqueId: user.uniqueId, displayName: user.displayName, position: user.position, userInterests: user.userInterests || '', phone: user.phone || '', notificationPreference: user.notificationPreference || 'none', role: 'user', password: '', confirmPassword: '', referringAdminId: user.referringAdminId || '' }); setApprovingPendingUser(null); navigateTo(Page.UserManagement, {action: 'editUser', userId: user.id}); clearMessages(); }} className="btn-info text-xs px-2 py-1"> Edit </button> 
                        )}
                        {currentUser.id !== user.id && user.role !== 'admin' && ( 
                          <button onClick={() => handleDeleteUser(user.id)} className="btn-danger text-xs px-2 py-1">Delete</button> 
                        )} 
                        {currentUser.id === user.id && (
                           <button onClick={() => navigateTo(Page.UserProfile)} className="btn-neutral text-xs px-2 py-1">My Profile</button>
                        )}
                      </td> </tr> ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {currentPage === Page.ManagePrograms && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Manage Programs</h2>
            <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Create Program</h3> <form onSubmit={handleCreateProgram} className="space-y-4"> <FormInput label="Program Name" id="programName" value={programForm.name} onChange={e => setProgramForm({...programForm, name: e.target.value})} required /> <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({...programForm, description: e.target.value})} required /> <button type="submit" className="btn-primary">Create</button> </form> </div>
            <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Existing Programs ({programs.length})</h3> {programs.length === 0 ? <p className="text-neutral">No programs.</p> : ( <ul className="space-y-3"> {programs.map(p => ( <li key={p.id} className="p-4 bg-bground rounded-md shadow flex justify-between items-start"> <div> <h4 className="font-semibold text-textlight">{p.name}</h4> <p className="text-sm text-neutral">{p.description}</p> </div> <button onClick={() => handleDeleteProgram(p.id)} className="btn-danger text-xs p-1 ml-2 self-start"><TrashIcon className="w-4 h-4"/></button> </li> ))} </ul> )} </div>
          </div>
        )}

        {currentPage === Page.ManageTasks && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Manage Tasks</h2>
             <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Create Task</h3> <form onSubmit={handleCreateTask} className="space-y-4"> <FormInput label="Task Title" id="taskTitle" value={taskForm.title} onChange={e => setTaskForm({...taskForm, title: e.target.value})} required /> <FormTextarea label="Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({...taskForm, description: e.target.value})} required /> <FormTextarea label="Required Skills (comma-separated)" id="taskRequiredSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({...taskForm, requiredSkills: e.target.value})} required placeholder="e.g., JS, Writing"/> <FormSelect label="Related Program (Optional)" id="taskProgramId" value={taskForm.programId} onChange={e => setTaskForm({...taskForm, programId: e.target.value})}> <option value="">None</option> {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)} </FormSelect> <FormInput label="Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline} onChange={e => setTaskForm({...taskForm, deadline: e.target.value})} /> <button type="submit" className="btn-primary">Create Task</button> </form> </div>
            <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Existing Tasks ({tasks.length})</h3> {tasks.length === 0 ? <p className="text-neutral">No tasks.</p> : ( <ul className="space-y-3"> {tasks.map(task => ( <li key={task.id} className="p-4 bg-bground rounded-md shadow"> <div className="flex justify-between items-start"> <div> <h4 className="font-semibold text-textlight">{task.title}</h4> <p className="text-sm text-neutral mt-1">{task.description}</p> <p className="text-xs text-neutral mt-1"><strong>Skills:</strong> {task.requiredSkills}</p> {task.programName && <p className="text-xs text-neutral mt-1"><strong>Program:</strong> {task.programName}</p>} {task.deadline && <p className="text-xs text-neutral mt-1"><strong>Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>} </div> <button onClick={() => handleDeleteTask(task.id)} className="btn-danger text-xs p-1 ml-2 self-start"><TrashIcon className="w-4 h-4"/></button> </div> <div className="mt-2 pt-2 border-t border-gray-300"> <p className="text-xs font-medium text-neutral">Assigned:</p> <ul className="text-xs list-disc list-inside pl-2"> {assignments.filter(a=>a.taskId===task.id).map(a=>(<li key={`${a.taskId}-${a.personId}`} className="text-neutral">{a.personName} - <span className={`font-semibold ${a.status==='completed_admin_approved'?'text-success':a.status==='declined_by_user'?'text-danger':a.status==='pending_acceptance'?'text-warning':'text-info'}`}>{a.status.replace(/_/g,' ')}</span></li>))} {assignments.filter(a=>a.taskId===task.id).length===0 && <li className="text-neutral">None.</li>}</ul></div></li>))}</ul>)}</div>
          </div>
        )}

        {currentPage === Page.AssignWork && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Assign Work</h2>
            <div className="bg-surface p-6 rounded-lg shadow-md">
              <FormSelect label="Select Task" id="selectTaskForAssignment" value={selectedTaskForAssignment || ''} onChange={e => { setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); clearMessages(); }}> <option value="">-- Select Task --</option> {tasks.map(t => (<option key={t.id} value={t.id}>{t.title}</option>))} </FormSelect>
              {selectedTaskForAssignment && ( <div className="mt-4 p-3 bg-bground rounded"> <h4 className="font-medium text-textlight">Selected Task:</h4> <p className="text-sm text-neutral">{tasks.find(t=>t.id === selectedTaskForAssignment)?.description}</p> <p className="text-xs text-neutral">Skills: {tasks.find(t=>t.id === selectedTaskForAssignment)?.requiredSkills}</p> {tasks.find(t=>t.id === selectedTaskForAssignment)?.deadline && <p className="text-xs">Deadline: {new Date(tasks.find(t=>t.id === selectedTaskForAssignment)!.deadline!).toLocaleDateString()}</p>} </div> )}
              <button onClick={handleGetAssignmentSuggestion} className="btn-accent mt-4 flex items-center" disabled={!selectedTaskForAssignment || isLoadingSuggestion}> {isLoadingSuggestion ? <LoadingSpinner /> : <><LightBulbIcon className="w-5 h-5 mr-2"/>AI Suggestion</>} </button>
              {assignmentSuggestion && ( <div className={`mt-4 p-3 rounded shadow-sm ${assignmentSuggestion.suggestedPersonName ? 'bg-green-50' : 'bg-yellow-50'}`}> <p className="text-sm font-medium">{assignmentSuggestion.suggestedPersonName ? `Suggests: ${assignmentSuggestion.suggestedPersonName}` : "AI:"}</p> <p className="text-xs text-neutral">{assignmentSuggestion.justification}</p> </div> )}
              <form onSubmit={(e) => handleAssignTask(e, assignmentSuggestion?.suggestedPersonName)} className="mt-6 space-y-4">
                <FormSelect label="Assign to" id="assignPerson" name="assignPerson" required defaultValue={assignmentSuggestion?.suggestedPersonName ? users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName)?.id : ""}> <option value="">-- Select Person --</option> {users.filter(u => u.role === 'user' && !assignments.some(a => a.taskId === selectedTaskForAssignment && a.personId === u.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))).map(user => ( <option key={user.id} value={user.id}>{user.displayName} ({user.position})</option>))} </FormSelect>
                <FormInput label="Specific Deadline (Optional)" id="specificDeadline" name="specificDeadline" type="date" value={assignmentForm.specificDeadline} onChange={e => setAssignmentForm({...assignmentForm, specificDeadline: e.target.value})} />
                <button type="submit" className="btn-primary" disabled={!selectedTaskForAssignment}>Assign Task</button>
              </form>
            </div>
          </div>
        )}

        {currentPage === Page.ViewAssignments && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Assignments</h2>
            {assignments.filter(a => currentUser.role === 'admin' || a.personId === currentUser.id).length === 0 ? ( <p className="text-neutral bg-surface p-4 rounded-md shadow"> {currentUser.role === 'admin' ? "No assignments in system." : "No tasks assigned."} </p> ) : (
              <ul className="space-y-4">
                {assignments.filter(a => currentUser.role === 'admin' || a.personId === currentUser.id).sort((x,y) => (x.deadline && y.deadline) ? new Date(x.deadline).getTime() - new Date(y.deadline).getTime() : 0).map(assignment => {
                    const task = tasks.find(t => t.id === assignment.taskId);
                    const isLate = assignment.deadline && new Date() > new Date(assignment.deadline) && (assignment.status === 'pending_acceptance' || assignment.status === 'accepted_by_user');
                    const isSubmittedLate = assignment.status === 'submitted_late';
                    return ( <li key={`${assignment.taskId}-${assignment.personId}`} className="bg-surface p-4 rounded-lg shadow-md"> <h3 className={`text-lg font-semibold ${isLate && !isSubmittedLate ? 'text-danger' : 'text-textlight'}`}>{assignment.taskTitle}</h3> {currentUser.role === 'admin' && <p className="text-sm text-neutral">To: <strong>{assignment.personName}</strong></p>} <p className="text-xs text-neutral mt-1">Status: <span className={`font-medium ${assignment.status==='completed_admin_approved'?'text-success':assignment.status==='declined_by_user'?'text-danger':assignment.status.startsWith('submitted')?'text-info':assignment.status==='pending_acceptance'?'text-warning':'text-blue-500' }`}>{assignment.status.replace(/_/g,' ')}</span> {isLate && !isSubmittedLate && <span className="text-danger text-xs font-bold ml-2">(OVERDUE)</span>} {isSubmittedLate && <span className="text-warning text-xs font-bold ml-2">(LATE)</span>} </p> {task && <p className="text-sm text-neutral mt-1">{task.description}</p>} {task?.requiredSkills && <p className="text-xs">Skills: {task.requiredSkills}</p>} {assignment.deadline && <p className="text-xs">Deadline: {new Date(assignment.deadline).toLocaleDateString()}</p>} {assignment.justification && assignment.justification !== 'Manually assigned by admin.' && <p className="text-xs italic">AI: {assignment.justification}</p>} {assignment.userSubmissionDate && <p className="text-xs">Submitted: {new Date(assignment.userSubmissionDate).toLocaleString()}</p>} {assignment.userDelayReason && <p className="text-xs">Delay reason: {assignment.userDelayReason}</p>}
                        <div className="mt-3 pt-3 border-t border-gray-200 space-x-2 flex flex-wrap gap-y-2">
                          {assignment.status === 'pending_acceptance' && assignment.personId === currentUser.id && ( <> <button onClick={() => handleUserAcceptTask(assignment.taskId)} className="btn-success text-sm">Accept</button> <button onClick={() => handleUserDeclineTask(assignment.taskId)} className="btn-danger text-sm">Decline</button> </> )}
                          {assignment.status === 'accepted_by_user' && assignment.personId === currentUser.id && ( <> {isLate && assignmentToSubmitDelayReason !== `${assignment.taskId}-${assignment.personId}` && ( <button onClick={() => setAssignmentToSubmitDelayReason(`${assignment.taskId}-${assignment.personId}`)} className="btn-warning text-sm">Submit Late</button> )} {assignmentToSubmitDelayReason === `${assignment.taskId}-${assignment.personId}` && isLate && ( <div className="w-full space-y-2 my-2 p-2 border border-warning bg-yellow-50"> <FormTextarea label="Reason for Late Submission:" id={`delayReason-${assignment.taskId}`} value={userSubmissionDelayReason} onChange={e => setUserSubmissionDelayReason(e.target.value)} /> <button onClick={() => handleUserSubmitTask(assignment.taskId, userSubmissionDelayReason)} className="btn-primary text-sm">Confirm</button> <button onClick={() => { setAssignmentToSubmitDelayReason(null); setUserSubmissionDelayReason(''); }} className="btn-neutral text-sm ml-2">Cancel</button> </div> )} {!isLate && ( <button onClick={() => handleUserSubmitTask(assignment.taskId)} className="btn-primary text-sm">Mark Completed</button> )} </> )}
                          {currentUser.role === 'admin' && (assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') && ( <button onClick={() => handleAdminApproveTaskCompletion(assignment.taskId, assignment.personId)} className="btn-success text-sm">Approve Completion</button> )}
                        </div> </li> );
                  })} </ul> )}
          </div>
        )}

        {currentPage === Page.ViewTasks && (
            <div className="space-y-6"> <h2 className="text-2xl font-semibold text-primary mb-6">Available Tasks</h2> {tasks.length === 0 ? ( <p className="text-neutral bg-surface p-4 rounded-md shadow">No tasks defined.</p> ) : (
                <ul className="space-y-4">
                    {tasks.map(task => {
                        const taskAssignments = assignments.filter(a => a.taskId === task.id);
                        const isFullyAssigned = taskAssignments.some(a => a.status === 'accepted_by_user' || a.status === 'completed_admin_approved' || a.status.startsWith('submitted'));
                        const isPending = taskAssignments.some(a => a.status === 'pending_acceptance');
                        let availability = "Available"; let color = "text-success";
                        if (isFullyAssigned) { availability = "Assigned/In Progress"; color = "text-neutral"; }
                        else if (isPending) { availability = "Pending Acceptance"; color = "text-warning"; }
                        return ( <li key={task.id} className="bg-surface p-4 rounded-lg shadow-md"> <h3 className="text-lg font-semibold">{task.title}</h3> <p className="text-sm mt-1">{task.description}</p> <p className="text-xs mt-1">Skills: {task.requiredSkills}</p> {task.programName && <p className="text-xs">Program: {task.programName}</p>} {task.deadline && <p className="text-xs">Deadline: {new Date(task.deadline).toLocaleDateString()}</p>} <p className={`text-xs font-medium mt-2 ${color}`}>Status: {availability}</p>
                        {currentUser.role === 'admin' && taskAssignments.length > 0 && ( <div className="mt-2 pt-2 border-t"> <p className="text-xs font-medium">Assignees:</p> <ul className="text-xs list-disc list-inside pl-2"> {taskAssignments.map(a => (<li key={`${a.taskId}-${a.personId}`}>{a.personName} - {a.status.replace(/_/g,' ')}</li>))} </ul> </div> )}
                        </li> );
                    })} </ul> )}
            </div>
        )}
      </main>
    </div>
  );
};
