
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import * as emailService from './src/utils/emailService'; // Corrected import path
import { validatePassword } from './src/utils/validation'; // Corrected import path
import LoadingSpinner from './components/LoadingSpinner';
import { UsersIcon, ClipboardListIcon, LightBulbIcon, CheckCircleIcon, TrashIcon, PlusCircleIcon, KeyIcon, BriefcaseIcon, LogoutIcon, UserCircleIcon } from './components/Icons';
import { PreRegistrationFormPage } from './components/PreRegistrationFormPage';
import UserTour from './components/UserTour';
import TopNavbar from './components/TopNavbar'; // Import the new TopNavbar component

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
  organizationId?: string;
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
  organizationId: string; // Now required
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
      return defaultReturnVal;
    }

    if (response.status === 401 || response.status === 403) {
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
      return defaultReturnVal;
    }

    const parsedData = JSON.parse(responseText);
    return parsedData as T;
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
  const [isLoadingAppData, setIsLoadingAppData] = useState<boolean>(true); 
  const [isVerifyingLink, setIsVerifyingLink] = useState<boolean>(false);


  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [newLoginForm, setNewLoginForm] = useState({ email: '', password: '' });
  const [newRegistrationForm, setNewRegistrationForm] = useState({
    name: '', 
    email: '',
    password: '',
    confirmPassword: '',
    role: 'user' as Role, 
    uniqueId: '', 
    position: '',
    organizationName: '', // For admin UI when creating new "site"
  });

  const [adminRegistrationForm, setAdminRegistrationForm] = useState(initialAdminRegistrationState);
  const [preRegistrationForm, setPreRegistrationFormInternal] = useLocalStorage('task-assign-preRegistrationForm',initialPreRegistrationFormState);

  const initialUserFormData: User & { confirmPassword?: string} = {
      id: '', email: '', uniqueId: '', password: '', confirmPassword: '',
      displayName: '', position: '', userInterests: '',
      phone: '', notificationPreference: 'none' as NotificationPreference,
      role: 'user' as Role, 
      referringAdminId: '',
      organizationId: '' // Will be set from currentUser or context
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

  const setCurrentUser = useCallback((user: User | null) => {
    setCurrentUserInternal(user);
    if (user && user.token) {
      localStorage.setItem(JWT_TOKEN_KEY, user.token);
    } else if (!user) {
      localStorage.removeItem(JWT_TOKEN_KEY);
    }
  }, []);

  const loadInitialData = useCallback(async (loggedInUserTokenData?: User) => { // Token data includes orgId
    setIsLoadingAppData(true);
    setError(null); // Clear previous errors on new load attempt
    try {
      let activeUserWithFullProfile: User | null = null;
      
      if (loggedInUserTokenData && loggedInUserTokenData.token) {
          setCurrentUser(loggedInUserTokenData); 
          const userFromServer = await fetchData<BackendUser>('/users/current', {}, null);
          if (userFromServer) {
            activeUserWithFullProfile = { ...userFromServer, id: userFromServer.id || userFromServer._id!, token: loggedInUserTokenData.token };
            setCurrentUserInternal(activeUserWithFullProfile);
          } else { 
            localStorage.removeItem(JWT_TOKEN_KEY);
            setCurrentUserInternal(null);
          }
      } else {
        const token = localStorage.getItem(JWT_TOKEN_KEY);
        if (token) {
           const userFromServer = await fetchData<BackendUser>('/users/current', {}, null);
           if (userFromServer) {
             activeUserWithFullProfile = { ...userFromServer, id: userFromServer.id || userFromServer._id!, token };
             setCurrentUserInternal(activeUserWithFullProfile);
           } else { 
             localStorage.removeItem(JWT_TOKEN_KEY);
             setCurrentUserInternal(null);
           }
        }
      }
      
      if (activeUserWithFullProfile) {
        const [
          loadedUsers, loadedPendingUsers, loadedTasks, loadedPrograms, loadedAssignments, loadedAdminLogs,
        ] = await Promise.all([
          // Only fetch all users if the current user is an admin. Otherwise, just use the current user.
          activeUserWithFullProfile.role === 'admin' ? fetchData<User[]>('/users', {}, []) : Promise.resolve([activeUserWithFullProfile]),
          activeUserWithFullProfile.role === 'admin' ? fetchData<PendingUser[]>('/pending-users', {}, []) : Promise.resolve([]),
          fetchData<Task[]>('/tasks', {}, []),
          fetchData<Program[]>('/programs', {}, []),
          fetchData<Assignment[]>('/assignments', {}, []),
          activeUserWithFullProfile.role === 'admin' ? fetchData<AdminLogEntry[]>('/admin-logs', {}, []) : Promise.resolve([]),
        ]);

        setUsers(loadedUsers || []);
        setPendingUsers(loadedPendingUsers || []);
        setTasks(loadedTasks || []);
        setPrograms(loadedPrograms || []);
        setAssignments(loadedAssignments || []);
        setAdminLogs(loadedAdminLogs || []);
      } else {
        setUsers([]); setPendingUsers([]); setTasks([]); setPrograms([]); setAssignments([]); setAdminLogs([]);
      }
      console.log("Initial data processed based on user session.");
    } catch (err: any) {
      console.error("Critical error during initial data load:", err);
      setError("Failed to load application data. Error: " + err.message);
      if (err.message.includes("Authentication/Authorization failed") || 
          err.message.includes("Token is missing organization information") ||
          err.message.includes("Access token missing") ||
          err.message.includes("Invalid or expired token")) {
        setCurrentUser(null); // This will also remove JWT_TOKEN_KEY
        // Navigation to Login will be handled by the hashChange effect
      }
    } finally {
      setIsLoadingAppData(false);
    }
  }, [setCurrentUser]); 

  useEffect(() => {
    if (!currentUser) {
        const token = localStorage.getItem(JWT_TOKEN_KEY);
        if (token) {
            try {
                const base64Url = token.split('.')[1];
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
                const decodedTokenUser = JSON.parse(jsonPayload) as User; 
                if (decodedTokenUser && decodedTokenUser.id && decodedTokenUser.organizationId) {
                     loadInitialData({ ...decodedTokenUser, token });
                } else {
                    localStorage.removeItem(JWT_TOKEN_KEY); 
                    loadInitialData(); 
                }
            } catch (e) {
                console.error("Failed to parse token from localStorage", e);
                localStorage.removeItem(JWT_TOKEN_KEY);
                loadInitialData(); 
            }
        } else {
            loadInitialData(); 
        }
    }
  }, [loadInitialData, currentUser]);


  const setPreRegistrationForm = (value: React.SetStateAction<typeof initialPreRegistrationFormState>) => {
    setPreRegistrationFormInternal(value);
  };

  const navigateTo = useCallback((page: Page, params?: Record<string, string>) => { let hash = `#${page}`; if (params && Object.keys(params).length > 0) { hash += `?${new URLSearchParams(params).toString()}`; } if (window.location.hash !== hash) { window.location.hash = hash; } else { _setCurrentPageInternal(page); } }, []);

  useEffect(() => {
    if (isLoadingAppData && !currentUser && localStorage.getItem(JWT_TOKEN_KEY)) {
        return; 
    }
    
    const processHash = () => {
      clearMessages();
      const hash = window.location.hash.substring(1);
      const [pagePath, paramsString] = hash.split('?');
      const params = new URLSearchParams(paramsString || '');
      const targetPageFromHashPath = pagePath.toUpperCase() as Page | string;

      if (targetPageFromHashPath === Page.PreRegistration) {
        const refAdminIdFromHash = params.get('refAdminId');
        
        if (!refAdminIdFromHash) {
            setPreRegistrationForm(prev => ({
                ...initialPreRegistrationFormState,
                isReferralLinkValid: false
            }));
            _setCurrentPageInternal(Page.PreRegistration);
            return;
        }

        _setCurrentPageInternal(Page.PreRegistration);
        setIsVerifyingLink(true);

        fetchData<{displayName: string}>(`/users/public-info/${refAdminIdFromHash}`, {}, null)
          .then(adminInfo => {
            if (adminInfo && adminInfo.displayName) {
                setPreRegistrationForm({
                  ...initialPreRegistrationFormState,
                  referringAdminId: refAdminIdFromHash,
                  referringAdminDisplayName: adminInfo.displayName,
                  isReferralLinkValid: true
                });
            } else {
                setPreRegistrationForm(prev => ({ ...prev, isReferralLinkValid: false }));
            }
          })
          .catch(err => {
            console.warn(`Could not fetch admin display name for pre-registration: ${err.message}`);
            setPreRegistrationForm(prev => ({ ...prev, isReferralLinkValid: false }));
          })
          .finally(() => {
            setIsVerifyingLink(false);
          });

        return;
      }

      if (!currentUser) {
        _setCurrentPageInternal(Page.Login);
        if (targetPageFromHashPath && targetPageFromHashPath !== Page.Login.toUpperCase() && window.location.hash !== `#${Page.Login}`) {
           navigateTo(Page.Login);
        }
        return;
      }

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

      if (currentUser) {
        const isNotAuthPage = (page: Page | string) => page !== Page.Login.toUpperCase() && page !== Page.PreRegistration.toUpperCase() && Object.values(Page).includes(page as Page);
        
        if (currentUser.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${currentUser.id}`)) {
          setTimeout(() => {
            const finalCurrentPage = window.location.hash.substring(1).split('?')[0].toUpperCase();
            if (isNotAuthPage(finalCurrentPage)) setShowUserTour(true);
          }, 500);
        }
      }
    };

    processHash();
    window.addEventListener('hashchange', processHash);

    return () => {
      window.removeEventListener('hashchange', processHash);
    };
  }, [currentUser, navigateTo, clearMessages, isLoadingAppData, _setCurrentPageInternal]);


  useEffect(() => {
    if (currentPage === Page.UserProfile && currentUser) {
      setUserForm({
        id: currentUser.id,
        email: currentUser.email,
        uniqueId: currentUser.uniqueId,
        displayName: currentUser.displayName,
        position: currentUser.position,
        userInterests: currentUser.userInterests || '',
        phone: currentUser.phone || '',
        notificationPreference: currentUser.notificationPreference || 'none',
        role: currentUser.role,
        password: '',
        confirmPassword: '',
        referringAdminId: currentUser.referringAdminId || '',
        organizationId: currentUser.organizationId
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

  const { name, email, password, confirmPassword, uniqueId, position, role, organizationName } = newRegistrationForm;

  if (!name.trim() || !email.trim() || !password.trim() || !confirmPassword.trim() || !uniqueId.trim()) {
    setError("Full Name, Email, Password, Confirm Password, and System ID are required.");
    return;
  }
  if (role === 'admin' && !organizationName.trim()) {
      setError("Organization Name is required when registering as an Administrator for a new site.");
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

  const registrationData: any = {
    displayName: name,
    email,
    password,
    role: role,
    uniqueId,
    position: position || (role === 'admin' ? 'Administrator' : 'User Position'),
    organizationName: role === 'admin' ? organizationName : undefined, 
  };

  const endpoint = '/users/register'; 

  try {
    const response = await fetchData<{ success: boolean; user: BackendUser | BackendPendingUser; message?: string }>(endpoint, {
      method: 'POST',
      body: JSON.stringify(registrationData),
    });

    if (response && response.success && response.user) {
      const createdEntity = response.user;
      
      if ('role' in createdEntity && createdEntity.role === 'admin') { // Assuming BackendUser for admin
         setSuccessMessage(`Administrator account for organization '${organizationName}' registered successfully! You can now log in.`);
      } else { // Could be BackendPendingUser or BackendUser if auto-approved user
         setSuccessMessage(`User account for ${createdEntity.displayName} registered. If admin approval is needed, you'll be notified.`);
      }

      emailService.sendWelcomeRegistrationEmail(createdEntity.email, createdEntity.displayName, createdEntity.role);
      setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user', uniqueId: '', position: '', organizationName: '' });
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
    role: 'user' as Role, // Pre-registrations are for 'user' role.
    referringAdminId: referringAdminId || undefined
    // organizationId will be determined by backend based on referringAdminId
  };

  try {
    const response = await fetchData<{ success: boolean; user: BackendPendingUser; message?: string }>('/pending-users', {
      method: 'POST',
      body: JSON.stringify(newPendingUserData),
    });

    if (response && response.success && response.user) {
      setSuccessMessage("Pre-registration submitted successfully! Your account is pending administrator approval.");
      setPreRegistrationForm(prev => ({ ...initialPreRegistrationFormState, referringAdminId: prev.referringAdminId, referringAdminDisplayName: prev.referringAdminDisplayName, isReferralLinkValid: prev.isReferralLinkValid }));

      emailService.sendPreRegistrationSubmittedToUserEmail(response.user.email, response.user.displayName, preRegistrationForm.referringAdminDisplayName);
      // Backend should notify the specific referring admin
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
      const response = await fetchData<{ success: boolean; user: User; token: string; message?: string }>('/users/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (response && response.success && response.user && response.token && response.user.organizationId) {
        const loggedInUserWithTokenAndOrg: User = {
          ...response.user, 
          token: response.token
        };
        
        setSuccessMessage(`Welcome back, ${loggedInUserWithTokenAndOrg.displayName}!`);
        setNewLoginForm({ email: '', password: '' });

        // loadInitialData will call setCurrentUser and handle localStorage for token
        await loadInitialData(loggedInUserWithTokenAndOrg); 

        // Determine target page after data load completes and currentUser is fully set by loadInitialData.
        // navigateTo might be called too early here if loadInitialData's effects on currentUser aren't immediate for this scope.
        // The hashChange useEffect is better suited to handle navigation post-login based on updated currentUser.
        const targetPage = loggedInUserWithTokenAndOrg.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
        navigateTo(targetPage); // This might need to be after loadInitialData fully resolves and updates state.

        if (loggedInUserWithTokenAndOrg.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${loggedInUserWithTokenAndOrg.id}`)) {
          setShowUserTour(true);
        }
      } else {
        setError(response?.message || "Invalid email or password, or login failed on server (org ID might be missing).");
      }
    } catch (err: any) {
      setError(err.message || "Login failed. Please check your credentials or server status.");
    }
  };

  const handleLogout = async () => {
    clearMessages();
    const token = localStorage.getItem(JWT_TOKEN_KEY);
    if (token) {
        try {
          await fetchData('/users/logout', { method: 'POST' }); 
        } catch (err: any) {
          console.warn("Logout API call failed (user will be logged out client-side anyway):", err.message);
        }
    }
    setCurrentUser(null); 
    setUsers([]);
    setPendingUsers([]);
    setTasks([]);
    setPrograms([]);
    setAssignments([]);
    setAdminLogs([]);
    _setCurrentPageInternal(Page.Login); 
    navigateTo(Page.Login); 
    setSuccessMessage("You have been logged out successfully.");
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
            organizationId: currentUser.organizationId, 
            token: localStorage.getItem(JWT_TOKEN_KEY) || undefined
        };
        setUsers(users.map(u => u.id === currentUser.id ? updatedUserFromServer : u));
        setCurrentUserInternal(updatedUserFromServer); 
        setSuccessMessage("Profile updated successfully!");
        setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' }));
        if (currentUser.role === 'admin') {
            await addAdminLogEntry(`User profile updated for ${updatedUserFromServer.displayName} (ID: ${updatedUserFromServer.uniqueId}).`);
        }
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
    if (!editingUserId || !currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) return;

    const { email, uniqueId, displayName, position, userInterests, phone, notificationPreference, password, confirmPassword, role } = userForm;

    if (!email.trim() || !uniqueId.trim() || !displayName.trim() || !position.trim()) {
        setError("Email, System ID, Display Name, and Position are required."); return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
        setError("Please enter a valid email address for the user."); return;
    }

    const updatePayload: Partial<User> & { password?: string } = {
      email, uniqueId, displayName, position, userInterests, phone, notificationPreference, role,
      organizationId: currentUser.organizationId 
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
        const baseUpdatedUser: User = { ...response.user, id: response.user.id || response.user._id!, organizationId: currentUser.organizationId };
        setUsers(users.map(u => u.id === editingUserId ? baseUpdatedUser : u));
        setSuccessMessage(`User ${baseUpdatedUser.displayName} updated successfully!`);
        setEditingUserId(null); setUserForm(initialUserFormData);
        await addAdminLogEntry(`Admin updated user profile for ${baseUpdatedUser.displayName} (Role: ${baseUpdatedUser.role}).`);
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

    if (!currentUser || !currentUser.id || currentUser.role !== 'admin' || !currentUser.organizationId) {
        setError("Action not allowed or current user data is missing organization context.");
        return;
    }

    const { email, uniqueId, displayName, position, userInterests, phone, notificationPreference, password, confirmPassword, role } = userForm;

    if (!email.trim() || !uniqueId.trim() || !displayName.trim() || !position.trim() || !password.trim() || !confirmPassword.trim()) {
        setError("Email, System ID, Display Name, Position, Password, and Confirm Password are required."); return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) { setError("Please enter a valid email address."); return; }
    if (password !== confirmPassword) { setError("Passwords do not match."); return; }
    const passVal = validatePassword(password);
    if (!passVal.isValid) { setError(passVal.errors.join(" ")); return; }

    const newUserData = {
      email, uniqueId, password, 
      role: role, 
      displayName, position, userInterests, phone, notificationPreference,
      referringAdminId: currentUser.id, 
      organizationId: currentUser.organizationId 
    };

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>('/users/register', { 
        method: 'POST',
        body: JSON.stringify(newUserData), 
      });

      if (response && response.success && response.user) {
        const createdUser: User = {...response.user, id: response.user.id || response.user._id!, organizationId: currentUser.organizationId};
        setUsers(prev => [...prev, createdUser]);
        setSuccessMessage(`User ${createdUser.displayName} (Role: ${createdUser.role}) created successfully!`);
        setUserForm(initialUserFormData);
        emailService.sendWelcomeRegistrationEmail(createdUser.email, createdUser.displayName, createdUser.role);
        await addAdminLogEntry(`Admin created new user: ${createdUser.displayName}, Role: ${createdUser.role}.`);
        navigateTo(Page.UserManagement);
      } else {
        setError(response?.message || "Failed to create user.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to create user.");
    }
  };

  const handleApprovePendingUser = async () => {
    if (!approvingPendingUser || !currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) {
      setError("Approval failed: Invalid operation, permissions, or missing organization context."); return;
    }
    if (approvingPendingUser.organizationId && approvingPendingUser.organizationId !== currentUser.organizationId) {
        setError("Cannot approve user from a different organization."); return;
    }
    clearMessages();

    const roleToApprove = userForm.role || approvingPendingUser.role || 'user';

    const approvalData = {
        position: userForm.position || 'Default Position',
        userInterests: userForm.userInterests || '',
        phone: userForm.phone || '',
        notificationPreference: userForm.notificationPreference || 'email',
        role: roleToApprove,
    };
    
    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>(`/pending-users/approve/${approvingPendingUser.id}`, {
        method: 'POST',
        body: JSON.stringify(approvalData),
      });

      if (response && response.success && response.user) {
        const createdUser: User = {...response.user, id: response.user.id || response.user._id!, organizationId: currentUser.organizationId};
        setUsers(prev => [...prev, createdUser]);
        setPendingUsers(prev => prev.filter(pu => pu.id !== approvingPendingUser.id));

        setApprovingPendingUser(null); setUserForm(initialUserFormData);
        setSuccessMessage(`User ${createdUser.displayName} approved (Role: ${createdUser.role}) and account activated!`);

        emailService.sendAccountActivatedByAdminEmail(createdUser.email, createdUser.displayName, currentUser.displayName);
        await addAdminLogEntry(`Admin approved pending user: ${createdUser.displayName} as ${createdUser.role}.`);
      } else {
        setError(response?.message || "Failed to approve user.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to approve user.");
    }
  };

  const handleRejectPendingUser = async (pendingUserId: string) => {
    if (!currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) return;
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
    if (!currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) return;
    if (currentUser.id === userId) { setError("Admins cannot delete their own accounts."); return; }
    
    const userToDelete = users.find(u => u.id === userId);
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
    if (!currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) {
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
    if (!currentUser || !currentUser.organizationId) { setError("Organization context missing."); return; }
    if (!programForm.name.trim() || !programForm.description.trim()) { setError("Program name and description are required."); return; }
    const newProgramData: Omit<Program, 'id' | 'organizationId'> = { ...programForm };
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
    if (!currentUser || !currentUser.organizationId) { setError("Organization context missing."); return; }
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
    if (!currentUser || !currentUser.organizationId) { setError("Organization context missing."); return; }
    if (!taskForm.title.trim() || !taskForm.description.trim() || !taskForm.requiredSkills.trim()) { setError("Task title, description, and required skills are required."); return; }
    const associatedProgram = programs.find(p => p.id === taskForm.programId); 
    const newTaskData: Partial<Omit<Task, 'id' | 'organizationId'>> = { ...taskForm, deadline: taskForm.deadline ? new Date(taskForm.deadline).toISOString().split('T')[0] : undefined, programName: associatedProgram?.name };
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
     if (!currentUser || !currentUser.organizationId) { setError("Organization context missing."); return; }
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
    if (!currentUser || !currentUser.organizationId) { setError("Organization context missing."); return; }
    const personIdToAssign = (e.target as HTMLFormElement).assignPerson.value;
    const specificDeadline = (e.target as HTMLFormElement).specificDeadline?.value;

    if (!selectedTaskForAssignment) { setError("No task selected for assignment."); return; }
    if (!personIdToAssign) { setError("No person selected for assignment."); return; }

    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    const person = users.find(u => u.id === personIdToAssign);
    if (!task || !person) { setError("Task or person not found."); return; }

    const justification = person.displayName === suggestedPersonDisplayName ? assignmentSuggestion?.justification : "Assigned manually by administrator.";

    const newAssignmentData: Partial<Omit<Assignment, 'id' | 'taskTitle' | 'personName'>> = {
      taskId: selectedTaskForAssignment,
      personId: personIdToAssign,
      justification,
      status: 'pending_acceptance',
      deadline: specificDeadline || task.deadline,
    };

    try {
      const createdAssignment = await fetchData<Assignment>('/assignments', {
        method: 'POST',
        body: JSON.stringify(newAssignmentData),
      });

      if (createdAssignment && createdAssignment.id) {
        setAssignments(prev => [...prev, createdAssignment]);
        setSuccessMessage(`Task "${task.title}" assigned to ${person.displayName}.`);
        if(person.notificationPreference === 'email' && person.email) {
            emailService.sendTaskProposalEmail(person.email, person.displayName, task.title, currentUser.displayName, newAssignmentData.deadline);
        }
        await addAdminLogEntry(`Admin assigned task "${task.title}" to ${person.displayName}.`);
        setSelectedTaskForAssignment(null);
        setAssignmentSuggestion(null);
        setAssignmentForm({ specificDeadline: '' });
      } else {
        setError("Failed to create assignment.");
      }
    } catch (err: any) {
      setError(err.message || "Server error while assigning task.");
    }
  };


const handleUpdateAssignmentStatus = async (assignment: Assignment, newStatus: AssignmentStatus, delayReason?: string) => {
    clearMessages();
    if (!currentUser) return;
    try {
        const updatePayload: any = {
            taskId: typeof assignment.taskId === 'object' ? (assignment.taskId as Task).id : assignment.taskId,
            personId: assignment.personId,
            status: newStatus,
        };
        
        if (newStatus === 'submitted_on_time' || newStatus === 'submitted_late') {
            updatePayload.userSubmissionDate = new Date().toISOString();
        }
        if (newStatus === 'submitted_late' && delayReason) {
            updatePayload.userDelayReason = delayReason;
        }

        const updatedAssignment = await fetchData<Assignment>('/assignments', {
            method: 'PATCH',
            body: JSON.stringify(updatePayload),
        });

        if (updatedAssignment) {
            setAssignments(assignments.map(a => a.id === updatedAssignment.id ? updatedAssignment : a));
            setSuccessMessage(`Assignment "${assignment.taskTitle}" status updated to: ${formatAssignmentStatus(newStatus)}.`);

            if (currentUser.role === 'admin' && newStatus === 'completed_admin_approved') {
                const assignedUser = users.find(u => u.id === assignment.personId);
                if (assignedUser && assignedUser.notificationPreference === 'email' && assignedUser.email) {
                    emailService.sendTaskCompletionApprovedToUserEmail(assignedUser.email, assignedUser.displayName, assignment.taskTitle, currentUser.displayName);
                }
                await addAdminLogEntry(`Admin approved completion for task "${assignment.taskTitle}" by ${assignment.personName}.`);
            } else if (currentUser.role === 'user') {
                const adminToNotify = getAdminToNotify();
                if (adminToNotify && adminToNotify.notificationPreference === 'email' && adminToNotify.email) {
                    const action = newStatus.includes('accept') ? 'accepted' : newStatus.includes('decline') ? 'declined' : 'submitted';
                    emailService.sendTaskStatusUpdateToAdminEmail(adminToNotify.email, adminToNotify.displayName, currentUser.displayName, assignment.taskTitle, action);
                }
                 await addAdminLogEntry(`User ${currentUser.displayName} ${newStatus.replace(/_/g, ' ')} task: ${assignment.taskTitle}.`);
            }
        } else {
            setError("Failed to update assignment status.");
        }
    } catch (err:any) {
        setError(err.message || "Error updating assignment status.");
    } finally {
        setAssignmentToSubmitDelayReason(null);
        setUserSubmissionDelayReason('');
    }
};

  const addAdminLogEntry = async (logText: string, imageFile?: File | null) => {
    if (!currentUser || currentUser.role !== 'admin') return;

    let imagePreviewUrl: string | undefined = undefined;
    // Note: Image upload to a service (like S3, Cloudinary) would happen here.
    // For this app, we're assuming the backend might just store a placeholder or log text.
    // If you implement file uploads, the backend would return a URL to save.
    if(imageFile) {
        // Placeholder for image upload logic
        console.warn("Image upload simulation: In a real app, this file would be uploaded to a cloud storage service.");
        // We'll use a local object URL for immediate preview, but this isn't persistent.
        // A real implementation needs backend upload handling.
        imagePreviewUrl = URL.createObjectURL(imageFile); // For local preview only.
    }
    
    setIsSubmittingLog(true);
    try {
      const newLog = await fetchData<AdminLogEntry>('/admin-logs', {
        method: 'POST',
        body: JSON.stringify({ logText, imagePreviewUrl }), // In real app, send actual URL from storage
      });

      if (newLog) {
        setAdminLogs([newLog, ...adminLogs]);
        setAdminLogText('');
        setAdminLogImageFile(null);
      }
    } catch (err: any) {
      setError(`Failed to add admin log: ${err.message}`);
    } finally {
        setIsSubmittingLog(false);
    }
  };

  const handleTourClose = (completed: boolean) => {
    setShowUserTour(false);
    if (currentUser) {
      localStorage.setItem(`hasCompletedUserTour_${currentUser.id}`, 'true');
      if (completed) {
        setSuccessMessage("You've completed the tour! You can now explore the application.");
      }
    }
  };

  const formatAssignmentStatus = (status: AssignmentStatus): string => {
    return status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const getStatusColorClass = (status: AssignmentStatus): string => {
    switch (status) {
      case 'pending_acceptance': return 'text-amber-600 bg-amber-100';
      case 'accepted_by_user': return 'text-blue-600 bg-blue-100';
      case 'declined_by_user': return 'text-red-600 bg-red-100';
      case 'submitted_on_time':
      case 'submitted_late': return 'text-purple-600 bg-purple-100';
      case 'completed_admin_approved': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const renderAssignmentItem = (assignment: Assignment, task: Task, userForRender: User) => {
    const isLateSubmission = assignment.status === 'submitted_on_time' && assignment.deadline && assignment.userSubmissionDate && new Date(assignment.userSubmissionDate) > new Date(assignment.deadline);
    if (isLateSubmission && assignment.status === 'submitted_on_time') { // Correct the status if it was miscategorized
        assignment.status = 'submitted_late';
    }
    
    return (
        <li key={assignment.id} className="p-4 sm:p-6 hover:bg-gray-50 transition-colors">
            <div className="flex items-start justify-between flex-wrap gap-4">
                <div className="flex-grow">
                    <h3 className="text-lg font-semibold text-primary">{assignment.taskTitle}</h3>
                    {currentUser?.role === 'admin' && (
                        <p className="text-sm text-neutral">To: <span className="font-medium text-textlight">{userForRender.displayName}</span></p>
                    )}
                    <p className="text-sm mt-1">
                        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColorClass(assignment.status)}`}>
                            {formatAssignmentStatus(assignment.status)}
                        </span>
                    </p>
                    {assignment.deadline && <p className="text-sm text-neutral mt-2">Deadline: <span className="font-medium text-textlight">{new Date(assignment.deadline).toLocaleDateString()}</span></p>}
                    
                    <details className="mt-3 text-sm">
                        <summary className="cursor-pointer text-texthighlight hover:underline">View Details</summary>
                        <div className="mt-2 pl-4 border-l-2 border-bground space-y-2">
                           <p><strong className="font-medium text-textlight">Description:</strong> {task.description}</p>
                           <p><strong className="font-medium text-textlight">Required Skills:</strong> {task.requiredSkills}</p>
                           {assignment.justification && <p><strong className="font-medium text-textlight">AI Justification:</strong> <span className="italic">{assignment.justification}</span></p>}
                           {assignment.status === 'submitted_late' && assignment.userDelayReason && <p><strong className="font-medium text-danger">Delay Reason:</strong> {assignment.userDelayReason}</p>}
                        </div>
                    </details>
                </div>

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 flex-shrink-0">
                    {currentUser?.id === assignment.personId && assignment.status === 'pending_acceptance' && (
                        <>
                            <button onClick={() => handleUpdateAssignmentStatus(assignment, 'accepted_by_user')} className="btn-success text-xs px-3 py-1.5">Accept Task</button>
                            <button onClick={() => handleUpdateAssignmentStatus(assignment, 'declined_by_user')} className="btn-danger text-xs px-3 py-1.5">Decline Task</button>
                        </>
                    )}
                    {currentUser?.id === assignment.personId && assignment.status === 'accepted_by_user' && (
                        <>
                         {assignment.deadline && new Date() > new Date(assignment.deadline) ? (
                            <button onClick={() => setAssignmentToSubmitDelayReason(assignment.id)} className="btn-warning text-xs px-3 py-1.5">Submit (Late)</button>
                         ) : (
                            <button onClick={() => handleUpdateAssignmentStatus(assignment, 'submitted_on_time')} className="btn-primary text-xs px-3 py-1.5">Mark as Completed / Submit</button>
                         )}
                        </>
                    )}
                     {currentUser?.role === 'admin' && (assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') && (
                        <button onClick={() => handleUpdateAssignmentStatus(assignment, 'completed_admin_approved')} className="btn-success text-xs px-3 py-1.5">Approve Completion</button>
                    )}
                </div>
            </div>
             {assignmentToSubmitDelayReason === assignment.id && (
                <div className="mt-4 p-4 bg-amber-50 border border-amber-200 rounded-md">
                    <FormTextarea
                        id={`delay-reason-${assignment.id}`}
                        label="Reason for Late Submission (Required)"
                        value={userSubmissionDelayReason}
                        onChange={(e) => setUserSubmissionDelayReason(e.target.value)}
                        placeholder="Please briefly explain the reason for the delay."
                    />
                    <div className="mt-2 flex gap-2">
                        <button onClick={() => handleUpdateAssignmentStatus(assignment, 'submitted_late', userSubmissionDelayReason)} className="btn-warning text-xs px-3 py-1.5" disabled={!userSubmissionDelayReason.trim()}>Confirm Submission</button>
                        <button onClick={() => setAssignmentToSubmitDelayReason(null)} className="btn-neutral text-xs px-3 py-1.5">Cancel</button>
                    </div>
                </div>
            )}
        </li>
    );
};


  // --- Main Render Logic ---

  if (isLoadingAppData && !currentUser) { // Show loading screen on initial app load, especially if checking for a token
    return (
      <div className="min-h-screen flex items-center justify-center bg-bground">
        <LoadingSpinner />
      </div>
    );
  }


  if (!currentUser) {
    const commonAuthProps = {
      error, successMessage, infoMessage, clearMessages
    };

    switch (currentPage) {
        case Page.PreRegistration:
            return <PreRegistrationFormPage 
                        formState={preRegistrationForm}
                        setFormState={setPreRegistrationForm}
                        onSubmit={handlePreRegistrationSubmit}
                        navigateToLogin={() => navigateTo(Page.Login)}
                        isVerifyingLink={isVerifyingLink}
                        {...commonAuthProps}
                   />
        default: // Default to Login page
         return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
            <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-md">
                 {error && <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg w-full" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
                 {successMessage && <div className="mb-4 p-3 bg-green-100 border-green-400 text-green-700 rounded-md shadow-lg w-full" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
                 {infoMessage && <div className="mb-4 p-3 bg-blue-100 border-blue-400 text-blue-700 rounded-md shadow-lg w-full" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}

                 <h2 className="text-center text-3xl font-bold text-textlight mb-2">{authView === 'login' ? 'Welcome Back!' : 'Create Your Account'}</h2>
                 <p className="text-center text-sm text-neutral mb-6">{authView === 'login' ? 'Sign in to access your dashboard.' : 'Register to get started.'}</p>
                 {authView === 'login' ? (
                     <form onSubmit={handleLogin} className="space-y-5">
                          <AuthFormInput id="loginEmail" name="email" type="email" value={newLoginForm.email} onChange={(e) => setNewLoginForm({...newLoginForm, email: e.target.value})} required autoComplete="email" placeholder="you@example.com" aria-label="Email Address" />
                          <AuthFormInput id="loginPassword" name="password" type="password" value={newLoginForm.password} onChange={(e) => setNewLoginForm({...newLoginForm, password: e.target.value})} required autoComplete="current-password" placeholder="Password" aria-label="Password" />
                          <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm">Sign In</button>
                          <p className="text-center text-sm text-textlight">
                            Don't have an account?{' '}
                            <button type="button" onClick={() => { setAuthView('register'); clearMessages(); }} className="font-medium text-authLink hover:underline">Register here</button>
                          </p>
                     </form>
                 ) : (
                    <form onSubmit={handleNewRegistration} className="space-y-4">
                        <AuthFormInput id="regName" name="name" type="text" value={newRegistrationForm.name} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, name: e.target.value})} required placeholder="Your Full Name" aria-label="Full Name" />
                        <AuthFormInput id="regEmail" name="email" type="email" value={newRegistrationForm.email} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, email: e.target.value})} required autoComplete="email" placeholder="Your Email Address" aria-label="Email Address" />
                        <AuthFormInput id="regUniqueId" name="uniqueId" type="text" value={newRegistrationForm.uniqueId} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, uniqueId: e.target.value})} required placeholder="Desired System ID (e.g. jdoe23)" aria-label="System ID" />
                        <AuthFormInput id="regPassword" name="password" type="password" value={newRegistrationForm.password} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, password: e.target.value})} required autoComplete="new-password" placeholder="Create Password" aria-label="Password" aria-describedby="passwordHelp" />
                        <p id="passwordHelp" className="mt-1 text-xs text-neutral -pt-2">{passwordRequirementsText}</p>
                        <AuthFormInput id="regConfirmPassword" name="confirmPassword" type="password" value={newRegistrationForm.confirmPassword} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, confirmPassword: e.target.value})} required autoComplete="new-password" placeholder="Confirm Password" aria-label="Confirm Password" />
                        
                        <div className="border-t border-gray-200 pt-4">
                            <AuthFormSelect id="regRole" name="role" value={newRegistrationForm.role} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, role: e.target.value as Role})} aria-label="Select Role">
                                <option value="user">Register as a standard User</option>
                                <option value="admin">Register as an Admin (creates a new site)</option>
                            </AuthFormSelect>
                        </div>

                        {newRegistrationForm.role === 'admin' && (
                          <AuthFormInput id="regOrgName" name="organizationName" type="text" value={newRegistrationForm.organizationName} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, organizationName: e.target.value})} required placeholder="Your Organization's Name" aria-label="Organization Name" />
                        )}

                        <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm">Register</button>
                        <p className="text-center text-sm text-textlight">
                            Already have an account?{' '}
                             <button type="button" onClick={() => { setAuthView('login'); clearMessages(); }} className="font-medium text-authLink hover:underline">Sign in</button>
                        </p>
                    </form>
                 )}
             </div>
              <footer className="text-center py-6 text-sm text-neutral mt-auto">
                <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by AI.</p>
              </footer>
            </div>
        );
    }
  }

  // --- Logged-in App View ---
  let pageContent;
  switch (currentPage) {
    case Page.Dashboard:
       const stats = {
            users: users.filter(u => u.role === 'user').length,
            pendingApprovals: pendingUsers.length,
            tasks: tasks.length,
            programs: programs.length,
            activeAssignments: assignments.filter(a => a.status === 'accepted_by_user').length,
            completedTasks: assignments.filter(a => a.status === 'completed_admin_approved').length,
        };
      pageContent = (
        <div className="p-4 sm:p-6 lg:p-8">
            <h2 className="text-2xl font-bold text-textlight mb-6">Admin Dashboard</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {Object.entries({
                    "Users": {value: stats.users, desc: "Total active users in your organization"},
                    "Pending Approvals": {value: stats.pendingApprovals, desc: "Users awaiting approval in your organization"},
                    "Tasks": {value: stats.tasks, desc: "Total defined tasks in your organization"},
                    "Programs": {value: stats.programs, desc: "Total programs in your organization"},
                    "Active Assignments": {value: stats.activeAssignments, desc: "Tasks currently assigned in your organization"},
                    "Completed Tasks": {value: stats.completedTasks, desc: "Successfully finished tasks in your organization"},
                }).map(([key, {value, desc}]) => (
                    <div key={key} className="bg-surface rounded-lg shadow-md p-5">
                        <h3 className="text-sm font-medium text-neutral">{key}</h3>
                        <p className="mt-1 text-3xl font-semibold text-textlight">{value}</p>
                        <p className="text-xs text-neutral mt-1">{desc}</p>
                    </div>
                ))}
            </div>

             <div className="mt-8 bg-surface rounded-lg shadow-md p-5">
                <h3 className="text-lg font-semibold text-textlight mb-4">Admin Log Entry</h3>
                <div className="space-y-4">
                  <FormTextarea
                    id="admin-log"
                    label="Log Message"
                    value={adminLogText}
                    onChange={(e) => setAdminLogText(e.target.value)}
                    placeholder="Enter log details..."
                  />
                  <div>
                    <label htmlFor="admin-log-image" className="block text-sm font-medium text-textlight">Attach Image (Optional)</label>
                    <input
                      id="admin-log-image"
                      type="file"
                      accept="image/*"
                      onChange={(e) => setAdminLogImageFile(e.target.files ? e.target.files[0] : null)}
                      className="mt-1 block w-full text-sm text-neutral file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-bground file:text-primary hover:file:bg-blue-100"
                    />
                  </div>
                  <button onClick={() => addAdminLogEntry(adminLogText, adminLogImageFile)} className="btn-primary" disabled={isSubmittingLog || (!adminLogText.trim() && !adminLogImageFile)}>
                    {isSubmittingLog ? "Submitting..." : "Add Log Entry"}
                  </button>
                </div>
            </div>

            <div className="mt-8 bg-surface rounded-lg shadow-md">
                 <h3 className="text-lg font-semibold text-textlight mb-4 p-5 border-b border-bground">Recent Admin Logs (Your Organization)</h3>
                <ul className="divide-y divide-bground">
                    {adminLogs.length > 0 ? adminLogs.slice(0, 10).map(log => (
                        <li key={log.id} className="p-5">
                            <p className="text-sm text-textlight">{log.logText}</p>
                            <p className="text-xs text-neutral mt-1">
                                By <span className="font-medium">{log.adminDisplayName}</span> on {new Date(log.timestamp).toLocaleString()}
                            </p>
                        </li>
                    )) : (
                        <li className="p-5 text-sm text-neutral">No admin logs for your organization.</li>
                    )}
                </ul>
            </div>
        </div>
      );
      break;
    case Page.UserProfile:
       pageContent = (
        <div className="p-4 sm:p-6 lg:p-8 max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-textlight mb-4">My Profile</h2>
          <form onSubmit={handleUpdateProfile} className="bg-surface rounded-lg shadow p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <FormInput label="Display Name" id="profileDisplayName" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
            <FormInput label="System ID / Username" id="profileUniqueId" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required />
            <FormInput label="Email Address" id="profileEmail" value={userForm.email} type="email" disabled readOnly className="bg-gray-100" description="Email cannot be changed." />
            <FormInput label="Position / Title" id="profilePosition" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
            <div className="md:col-span-2">
              <FormTextarea label="My Skills & Interests" id="profileInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
            </div>
            <FormInput label="Phone Number" id="profilePhone" value={userForm.phone} type="tel" onChange={e => setUserForm({...userForm, phone: e.target.value})} />
            <FormSelect label="Notification Preference" id="profileNotification" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
              <option value="email">Email</option><option value="phone">Phone (SMS)</option><option value="none">None</option>
            </FormSelect>
             <div className="md:col-span-2 border-t pt-6 mt-4">
               <h3 className="text-lg font-semibold text-textlight mb-2">Change Password</h3>
               <p className="text-sm text-neutral mb-4">Leave fields blank to keep your current password.</p>
                <FormInput label="New Password" id="profilePassword" type="password" value={userForm.password} onChange={e => setUserForm({...userForm, password: e.target.value})} aria-describedby="passwordHelpProfile" />
                <p id="passwordHelpProfile" className="text-xs text-neutral mt-1">{passwordRequirementsText}</p>
                <FormInput label="Confirm New Password" id="profileConfirmPassword" type="password" value={userForm.confirmPassword} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} />
            </div>
            <div className="md:col-span-2 flex justify-end">
              <button type="submit" className="btn-primary">Update Profile</button>
            </div>
          </form>
        </div>
      );
      break;
    case Page.ViewAssignments:
        pageContent = (
            <div className="p-4 sm:p-6 lg:p-8">
                <h2 className="text-2xl font-bold text-textlight mb-4">My Assignments</h2>
                <div className="bg-surface rounded-lg shadow">
                    <ul className="divide-y divide-gray-200">
                        {assignments.map(assignment => {
                            // The backend populates taskId with a partial task object. We cast it to use it directly.
                            const task = assignment.taskId as Task;
                            // Find the full user object if available.
                            const user = users.find(u => u.id === assignment.personId);

                            if (!task) {
                                // This should not happen if the backend is working correctly, as it filters these out.
                                return (
                                    <li key={assignment.id || `${assignment.personId}-no-task`} className="p-4 text-sm text-neutral">
                                        Assignment data is incomplete. Task details are missing for assignment to {assignment.personName}.
                                    </li>
                                );
                            }

                            // Create a synthetic user object for rendering if the full object isn't in our state.
                            const userForRender: User = user || {
                                id: assignment.personId,
                                displayName: assignment.personName,
                                email: '', uniqueId: '', role: 'user', position: '',
                                organizationId: currentUser!.organizationId
                            };

                            return renderAssignmentItem(assignment, task, userForRender);
                        })}
                        {assignments.length === 0 && (
                            <li className="p-4 text-sm text-neutral">
                                {currentUser?.role === 'admin' ? "No assignments found in your organization." : "No tasks are currently assigned to you."}
                            </li>
                        )}
                    </ul>
                </div>
            </div>
        );
        break;
    case Page.ViewTasks:
       pageContent = (
         <div className="p-4 sm:p-6 lg:p-8">
            <h2 className="text-2xl font-bold text-textlight mb-4">Available Tasks</h2>
             <div className="bg-surface rounded-lg shadow">
               <ul className="divide-y divide-gray-200">
                {tasks.length > 0 ? tasks.map(task => (
                    <li key={task.id} className="p-4 sm:p-6">
                         <h3 className="text-lg font-semibold text-primary">{task.title}</h3>
                         <p className="text-sm text-neutral mt-1">Related Program: <span className="font-medium text-textlight">{task.programName || 'N/A'}</span></p>
                         <details className="mt-3 text-sm">
                            <summary className="cursor-pointer text-texthighlight hover:underline">View Details</summary>
                             <div className="mt-2 pl-4 border-l-2 border-bground space-y-2">
                                <p><strong className="font-medium text-textlight">Description:</strong> {task.description}</p>
                                <p><strong className="font-medium text-textlight">Required Skills:</strong> {task.requiredSkills}</p>
                                {task.deadline && <p><strong className="font-medium text-textlight">Suggested Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>}
                            </div>
                        </details>
                    </li>
                )) : (
                    <li className="p-4 text-sm text-neutral">No tasks are currently available.</li>
                )}
               </ul>
            </div>
         </div>
       );
      break;
    case Page.UserManagement:
       pageContent = (
         <div className="p-4 sm:p-6 lg:p-8">
            <h2 className="text-2xl font-bold text-textlight mb-4">User Management</h2>
            {/* Form for Creating/Editing Users */}
            {(editingUserId !== null || approvingPendingUser !== null || userForm.id === 'creating') && (
                 <div className="bg-surface rounded-lg shadow p-6 mb-8">
                    <h3 className="text-xl font-semibold text-textlight mb-4">
                        {editingUserId ? "Edit User" : approvingPendingUser ? `Approve Pending User: ${approvingPendingUser.displayName}` : "Create New User"}
                    </h3>
                     <form onSubmit={editingUserId ? handleAdminUpdateUser : handleCreateUserByAdmin} className="grid grid-cols-1 md:grid-cols-2 gap-6">
                         <FormInput label="Display Name" id="userFormDisplayName" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required disabled={!!approvingPendingUser} />
                         <FormInput label="Email Address" id="userFormEmail" value={userForm.email} type="email" onChange={e => setUserForm({...userForm, email: e.target.value})} required disabled={!!approvingPendingUser || !!editingUserId} />
                         <FormInput label="System ID / Username" id="userFormUniqueId" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required disabled={!!approvingPendingUser || !!editingUserId} />
                         <FormInput label="Position / Title" id="userFormPosition" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                         <div className="md:col-span-2">
                            <FormTextarea label="User Skills & Interests" id="userFormInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                         </div>
                         <FormInput label="Phone Number" id="userFormPhone" value={userForm.phone} type="tel" onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                         <FormSelect label="Notification Preference" id="userFormNotification" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                             <option value="email">Email</option><option value="phone">Phone (SMS)</option><option value="none">None</option>
                         </FormSelect>
                         <FormSelect label="Role" id="userFormRole" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value as Role})}>
                             <option value="user">User</option><option value="admin">Admin</option>
                         </FormSelect>
                         {!editingUserId && (
                             <div className="md:col-span-2 border-t pt-6 mt-4">
                                <h4 className="text-lg font-semibold text-textlight mb-2">{editingUserId ? "Change Password (Optional)" : "Set Initial Password"}</h4>
                                <FormInput label="Password" id="userFormPassword" type="password" value={userForm.password} onChange={e => setUserForm({...userForm, password: e.target.value})} required={!editingUserId} aria-describedby="passwordHelpUserMgmt" />
                                <p id="passwordHelpUserMgmt" className="text-xs text-neutral mt-1">{passwordRequirementsText}</p>
                                <FormInput label="Confirm Password" id="userFormConfirmPassword" type="password" value={userForm.confirmPassword} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} required={!editingUserId} />
                             </div>
                         )}
                         <div className="md:col-span-2 flex justify-end gap-3">
                              <button type="button" onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); }} className="btn-neutral">Cancel</button>
                              {approvingPendingUser ? (
                                <button type="button" onClick={handleApprovePendingUser} className="btn-success">Approve User</button>
                              ) : (
                                <button type="submit" className="btn-primary">{editingUserId ? 'Save Changes' : 'Create User'}</button>
                              )}
                         </div>
                     </form>
                 </div>
            )}
            {/* Pre-registration Link Section */}
            <div className="bg-surface rounded-lg shadow p-6 mb-8">
                 <h3 className="text-xl font-semibold text-textlight mb-2">Pre-registration Link</h3>
                 <p className="text-sm text-neutral mb-4">Generate a unique link to allow a new user to register for your organization. They will require your approval after they submit their details.</p>
                 <button onClick={handleGeneratePreRegistrationLink} className="btn-secondary">Generate Link</button>
                 {generatedLink && (
                     <div className="mt-4 p-3 bg-bground rounded-md">
                         <p className="text-sm text-textlight break-all">{generatedLink}</p>
                         <button onClick={() => copyToClipboard(generatedLink)} className="mt-2 text-sm text-primary font-medium hover:underline">Copy to Clipboard</button>
                     </div>
                 )}
            </div>

            {/* Pending Users List */}
            <div className="bg-surface rounded-lg shadow mb-8">
              <h3 className="text-xl font-semibold text-textlight p-4 border-b">Pending Approvals</h3>
               <ul className="divide-y divide-gray-200">
                  {pendingUsers.length > 0 ? pendingUsers.map(pu => (
                      <li key={pu.id} className="p-4 flex items-center justify-between">
                         <div>
                           <p className="font-medium">{pu.displayName} ({pu.uniqueId})</p>
                           <p className="text-sm text-neutral">{pu.email} - Submitted: {new Date(pu.submissionDate).toLocaleDateString()}</p>
                         </div>
                         <div className="flex gap-2">
                            <button onClick={() => { setApprovingPendingUser(pu); setUserForm({...initialUserFormData, id:'approving', displayName: pu.displayName, email: pu.email, uniqueId: pu.uniqueId, role: pu.role}); setEditingUserId(null); }} className="btn-success text-xs px-3 py-1.5">Approve</button>
                            <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger text-xs px-3 py-1.5">Reject</button>
                         </div>
                      </li>
                  )) : <li className="p-4 text-sm text-neutral">No users are currently pending approval.</li>}
               </ul>
            </div>
            
            {/* Active Users List */}
            <div className="bg-surface rounded-lg shadow">
                 <h3 className="text-xl font-semibold text-textlight p-4 border-b flex justify-between items-center">
                    <span>Active Users</span>
                    <button onClick={() => { setUserForm({...initialUserFormData, id: 'creating'}); setEditingUserId(null); setApprovingPendingUser(null);}} className="btn-primary text-sm flex items-center gap-1"><PlusCircleIcon className="w-4 h-4"/> New User</button>
                 </h3>
               <ul className="divide-y divide-gray-200">
                   {users.map(user => (
                       <li key={user.id} className="p-4 flex items-center justify-between">
                           <div>
                               <p className="font-medium">{user.displayName} <span className="text-xs text-white px-1.5 py-0.5 rounded-full bg-neutral">{user.role}</span></p>
                               <p className="text-sm text-neutral">{user.email} - Position: {user.position}</p>
                           </div>
                           <div className="flex gap-2">
                               <button onClick={() => { setEditingUserId(user.id); setUserForm({...user, password: '', confirmPassword: ''}); setApprovingPendingUser(null); }} className="btn-info text-xs px-3 py-1.5">Edit</button>
                               {currentUser?.id !== user.id && <button onClick={() => handleDeleteUser(user.id)} className="btn-danger text-xs px-3 py-1.5">Delete</button>}
                           </div>
                       </li>
                   ))}
               </ul>
            </div>
         </div>
       );
      break;
    case Page.ManagePrograms:
      pageContent = (
        <div className="p-4 sm:p-6 lg:p-8 max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-textlight mb-4">Manage Programs</h2>
          <form onSubmit={handleCreateProgram} className="bg-surface rounded-lg shadow p-6 mb-8 space-y-4">
             <h3 className="text-xl font-semibold text-textlight">Create New Program</h3>
             <FormInput label="Program Name" id="programName" value={programForm.name} onChange={e => setProgramForm({...programForm, name: e.target.value})} required />
             <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({...programForm, description: e.target.value})} required />
             <button type="submit" className="btn-primary">Create Program</button>
          </form>
           <div className="bg-surface rounded-lg shadow">
              <h3 className="text-xl font-semibold text-textlight p-4 border-b">Existing Programs</h3>
               <ul className="divide-y divide-gray-200">
                {programs.length > 0 ? programs.map(program => (
                    <li key={program.id} className="p-4 flex items-start justify-between">
                       <div>
                           <p className="font-medium">{program.name}</p>
                           <p className="text-sm text-neutral">{program.description}</p>
                       </div>
                       <button onClick={() => handleDeleteProgram(program.id)} className="btn-danger text-xs px-3 py-1.5 flex-shrink-0 ml-4"><TrashIcon className="w-4 h-4" /></button>
                    </li>
                )) : <li className="p-4 text-sm text-neutral">No programs created yet.</li>}
               </ul>
           </div>
        </div>
      );
      break;
    case Page.ManageTasks:
      pageContent = (
        <div className="p-4 sm:p-6 lg:p-8 max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-textlight mb-4">Manage Tasks</h2>
           <form onSubmit={handleCreateTask} className="bg-surface rounded-lg shadow p-6 mb-8 space-y-4">
               <h3 className="text-xl font-semibold text-textlight">Create New Task</h3>
               <FormInput label="Task Title" id="taskTitle" value={taskForm.title} onChange={e => setTaskForm({...taskForm, title: e.target.value})} required />
               <FormTextarea label="Task Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({...taskForm, description: e.target.value})} required />
               <FormTextarea label="Required Skills" id="taskSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({...taskForm, requiredSkills: e.target.value})} required />
               <FormSelect label="Related Program (Optional)" id="taskProgram" value={taskForm.programId} onChange={e => setTaskForm({...taskForm, programId: e.target.value})}>
                 <option value="">None</option>
                 {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
               </FormSelect>
               <FormInput label="Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline} onChange={e => setTaskForm({...taskForm, deadline: e.target.value})} />
               <button type="submit" className="btn-primary">Create Task</button>
           </form>
            <div className="bg-surface rounded-lg shadow">
              <h3 className="text-xl font-semibold text-textlight p-4 border-b">Existing Tasks</h3>
               <ul className="divide-y divide-gray-200">
                {tasks.length > 0 ? tasks.map(task => (
                    <li key={task.id} className="p-4 flex items-start justify-between">
                       <div>
                           <p className="font-medium">{task.title}</p>
                           <p className="text-sm text-neutral">{task.description}</p>
                           <p className="text-xs mt-1">Skills: {task.requiredSkills}</p>
                           {task.programName && <p className="text-xs mt-1 text-secondary">Program: {task.programName}</p>}
                       </div>
                       <button onClick={() => handleDeleteTask(task.id)} className="btn-danger text-xs px-3 py-1.5 flex-shrink-0 ml-4"><TrashIcon className="w-4 h-4"/></button>
                    </li>
                )) : <li className="p-4 text-sm text-neutral">No tasks created yet.</li>}
               </ul>
            </div>
        </div>
      );
      break;
    case Page.AssignWork:
      pageContent = (
        <div className="p-4 sm:p-6 lg:p-8 max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold text-textlight mb-4">Assign Work</h2>
            <div className="bg-surface rounded-lg shadow p-6">
                <div className="space-y-4">
                    <FormSelect label="1. Select Task to Assign" id="selectTaskForAssignment" value={selectedTaskForAssignment || ''} onChange={e => { setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); }}>
                        <option value="" disabled>-- Choose a task --</option>
                        {tasks.filter(t => !assignments.some(a => a.taskId === t.id && (a.status === 'accepted_by_user' || a.status === 'pending_acceptance'))).map(task => (
                            <option key={task.id} value={task.id}>{task.title}</option>
                        ))}
                    </FormSelect>

                    {selectedTaskForAssignment && (
                         <div className="p-4 bg-bground rounded-md">
                            <button onClick={handleGetAssignmentSuggestion} className="btn-secondary flex items-center gap-2" disabled={isLoadingSuggestion}>
                                <LightBulbIcon className="w-5 h-5"/>
                                {isLoadingSuggestion ? <LoadingSpinner/> : '2. Get AI Suggestion'}
                            </button>
                             {isLoadingSuggestion && <p className="text-sm text-neutral mt-2">Getting suggestion from Gemini...</p>}
                             {assignmentSuggestion && !isLoadingSuggestion && (
                                <div className="mt-3 text-sm text-textlight">
                                    <p><strong className="font-medium">AI Suggests:</strong> {assignmentSuggestion.suggestedPersonName || "No suitable person found."}</p>
                                    <p className="italic mt-1">"{assignmentSuggestion.justification}"</p>
                                </div>
                             )}
                         </div>
                    )}

                    {selectedTaskForAssignment && (
                        <form onSubmit={(e) => handleAssignTask(e, assignmentSuggestion?.suggestedPersonName)} className="pt-4 border-t space-y-4">
                           <FormSelect label="3. Assign to Person" id="assignPerson" name="assignPerson" required defaultValue={assignmentSuggestion?.suggestedPersonName ? users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName)?.id : ''}>
                                <option value="" disabled>-- Choose a person --</option>
                                {users.filter(u => u.role === 'user').map(user => (
                                    <option key={user.id} value={user.id}>{user.displayName} ({user.position})</option>
                                ))}
                           </FormSelect>
                            <FormInput label="Specific Deadline (Optional)" id="specificDeadline" name="specificDeadline" type="date" value={assignmentForm.specificDeadline} onChange={e => setAssignmentForm({...assignmentForm, specificDeadline: e.target.value})} description="Overrides the default task deadline for this assignment only."/>
                           <button type="submit" className="btn-primary">Assign Task</button>
                        </form>
                    )}
                </div>
            </div>
        </div>
      );
      break;
    default:
      pageContent = <div className="p-6"><p>Page not found.</p></div>;
  }


  return (
    <div className="min-h-screen bg-bground main-app-scope">
        <TopNavbar currentUser={currentUser} currentPage={currentPage} navigateTo={navigateTo} handleLogout={handleLogout} />
        <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            {error && <div className="mx-4 sm:mx-0 mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-md" role="alert"><p>{error}</p><button onClick={clearMessages} className="ml-2 font-bold">X</button></div>}
            {successMessage && <div className="mx-4 sm:mx-0 mb-4 p-3 bg-green-100 border-green-400 text-green-700 rounded-md" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 font-bold">X</button></div>}
            {infoMessage && <div className="mx-4 sm:mx-0 mb-4 p-3 bg-blue-100 border-blue-400 text-blue-700 rounded-md" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 font-bold">X</button></div>}
            {isLoadingAppData && <LoadingSpinner />}
            {!isLoadingAppData && pageContent}
        </main>
        {showUserTour && currentUser && <UserTour user={currentUser} onClose={handleTourClose} />}
    </div>
  );
};
