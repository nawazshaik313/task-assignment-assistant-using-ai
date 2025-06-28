
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
          activeUserWithFullProfile.role === 'admin'
            ? fetchData<User[]>('/users', {}, [])
            : Promise.resolve(activeUserWithFullProfile ? [activeUserWithFullProfile] : []),
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
    if (!selectedTaskForAssignment || !personIdToAssign) { setError("Task and person must be selected."); return; }
    const task = tasks.find(t => t.id === selectedTaskForAssignment); 
    const person = users.find(u => u.id === personIdToAssign); 
    if (!task || !person) { setError("Selected task or person not found in your organization."); return; }
    if (assignments.some(a => a.taskId === task.id && a.personId === person.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))) { setError(`${person.displayName} is already assigned this task or pending acceptance.`); return; }
    const justification = suggestedPersonDisplayName === person.displayName && assignmentSuggestion?.justification ? assignmentSuggestion.justification : 'Manually assigned by admin.';
    const newAssignmentData: Partial<Omit<Assignment, 'organizationId'>> = { taskId: task.id, personId: person.id, taskTitle: task.title, personName: person.displayName, justification, status: 'pending_acceptance', deadline: specificDeadline || task.deadline, };
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

  const updateAssignmentStatus = async (assignmentId: string, newStatus: AssignmentStatus, additionalData: Record<string, any> = {}) => {
    if (!currentUser || !currentUser.organizationId) {
      setError("Organization context missing.");
      return null;
    }
    clearMessages();
    const payload = { status: newStatus, ...additionalData };
    try {
      const updatedAssignment = await fetchData<Assignment>(`/assignments/${assignmentId}`, {
        method: 'PATCH',
        body: JSON.stringify(payload)
      });
      if (updatedAssignment && updatedAssignment.id) {
        setAssignments(prev => prev.map(a => (a.id === assignmentId ? updatedAssignment : a)));
        return updatedAssignment;
      } else {
        setError(`Failed to update task status. Server did not confirm the update.`);
        return null;
      }
    } catch (err: any) {
      setError(err.message || `Failed to update task status.`);
      throw err;
    }
  };


  const handleUserAcceptTask = async (assignmentId: string) => {
    try {
        const updatedAssignment = await updateAssignmentStatus(assignmentId, 'accepted_by_user');
        if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" accepted.`);
            const admin = getAdminToNotify(users.find(u=>u.id === currentUser?.referringAdminId)?.id); 
            if (admin?.notificationPreference === 'email' && admin.email) {
                emailService.sendTaskStatusUpdateToAdminEmail(admin.email, admin.displayName, currentUser!.displayName, updatedAssignment.taskTitle, "accepted");
            }
        }
    } catch (e) { /* error set by updateAssignmentStatus */ }
  };

  const handleUserDeclineTask = async (assignmentId: string) => {
     try {
        const updatedAssignment = await updateAssignmentStatus(assignmentId, 'declined_by_user');
         if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" declined.`);
            const admin = getAdminToNotify(users.find(u=>u.id === currentUser?.referringAdminId)?.id);
            if (admin?.notificationPreference === 'email' && admin.email) {
                emailService.sendTaskStatusUpdateToAdminEmail(admin.email, admin.displayName, currentUser!.displayName, updatedAssignment.taskTitle, "declined");
            }
        }
    } catch (e) { /* error set */ }
  };

  const handleUserSubmitTask = async (assignmentId: string, delayReason?: string) => {
    if (!currentUser) return;
    const assignment = assignments.find(a => a.id === assignmentId && a.status === 'accepted_by_user');
    if (!assignment) { setError("Task not found or not accepted."); return; }
    const submissionDate = new Date();
    let newStatus: AssignmentStatus = 'submitted_on_time';
    if (assignment.deadline && submissionDate > new Date(assignment.deadline)) {
      newStatus = 'submitted_late';
      if (!delayReason && assignmentToSubmitDelayReason === assignment.id) { setError("Reason required for late submission."); return; }
    }
    const additionalData: any = { userSubmissionDate: submissionDate.toISOString() };
    if (newStatus === 'submitted_late') additionalData.userDelayReason = delayReason || userSubmissionDelayReason;
    try {
        const updated = await updateAssignmentStatus(assignmentId, newStatus, additionalData);
        if (updated) {
            setSuccessMessage(`Task "${updated.taskTitle}" submitted.`);
            setUserSubmissionDelayReason(''); setAssignmentToSubmitDelayReason(null);
            const admin = getAdminToNotify(users.find(u=>u.id === currentUser.referringAdminId)?.id);
            if (admin?.notificationPreference === 'email' && admin.email) {
                emailService.sendTaskStatusUpdateToAdminEmail(admin.email, admin.displayName, currentUser.displayName, updated.taskTitle, `submitted (${newStatus.replace(/_/g, ' ')})`);
            }
        }
    } catch (e) { /* error set */ }
  };

  const handleAdminApproveTaskCompletion = async (assignmentId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
     try {
        const updated = await updateAssignmentStatus(assignmentId, 'completed_admin_approved');
        if (updated) {
            const user = users.find(u => u.id === updated.personId); 
            setSuccessMessage(`Completion of task "${updated.taskTitle}" by ${user?.displayName || 'user'} approved.`);
            if (user?.notificationPreference === 'email' && user.email) {
                emailService.sendTaskCompletionApprovedToUserEmail(user.email, user.displayName, updated.taskTitle, currentUser.displayName);
            }
            await addAdminLogEntry(`Admin approved task completion for "${updated.taskTitle}" by ${user?.displayName}.`);
        }
    } catch (e) { /* error set */ }
  };

  const addAdminLogEntry = async (logText: string, imagePreviewUrl?: string) => {
    if (!currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) return;
    const newLogData: Omit<AdminLogEntry, 'id' | 'organizationId'> = { adminId: currentUser.id, adminDisplayName: currentUser.displayName, timestamp: new Date().toISOString(), logText, imagePreviewUrl };
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

  if (isLoadingAppData && !currentUser && localStorage.getItem(JWT_TOKEN_KEY)) { 
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
          isVerifyingLink={isVerifyingLink}
        />
      );
    }

    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4 main-app-scope">
        {isLoadingAppData && localStorage.getItem(JWT_TOKEN_KEY) && <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-50 flex items-center justify-center z-50"><LoadingSpinner /><p className="text-white ml-2">Loading...</p></div>}
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
              <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm" disabled={isLoadingAppData && !!localStorage.getItem(JWT_TOKEN_KEY)}>
                {(isLoadingAppData && !!localStorage.getItem(JWT_TOKEN_KEY)) ? <LoadingSpinner /> : 'Sign In'}
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
                <label htmlFor="regRole" className="block text-sm font-medium text-textlight">Register as</label>
                <AuthFormSelect id="regRole" aria-label="Select role for registration" value={newRegistrationForm.role} onChange={(e) => setNewRegistrationForm({...newRegistrationForm, role: e.target.value as Role})}>
                  <option value="user">User (requires referral/invitation)</option>
                  <option value="admin">Administrator (creates a new site)</option>
                </AuthFormSelect>
              </div>
              {newRegistrationForm.role === 'admin' && (
                <div> <label htmlFor="regOrgName" className="block text-sm font-medium text-textlight">Organization/Site Name</label> <AuthFormInput type="text" id="regOrgName" aria-label="Organization or Site Name" placeholder="Your Organization Name" value={newRegistrationForm.organizationName} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, organizationName: e.target.value })} required /> <small className="text-xs text-gray-500">This will be the name of your new, separate site.</small> </div>
              )}
               <small className="text-xs text-gray-500">
                  {newRegistrationForm.role === 'admin' ? "Registering as an Administrator creates a new, isolated site." : 
                   "User accounts are typically created via pre-registration links from an existing site administrator."}
                </small>


              <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm" disabled={isLoadingAppData && !!localStorage.getItem(JWT_TOKEN_KEY)}>
                {(isLoadingAppData && !!localStorage.getItem(JWT_TOKEN_KEY)) ? <LoadingSpinner/> : 'Register'}
              </button>
            </form>
          )}
          <p className="text-center text-sm text-textlight mt-6">
            {authView === 'login' ? "Don't have an account?" : "Already have an account?"}{' '}
            <button type="button" onClick={() => { clearMessages(); setAuthView(authView === 'login' ? 'register' : 'login'); }} className="font-medium text-authLink hover:underline">
              {authView === 'login' ? 'Register here' : 'Sign in here'}
            </button>
          </p>
        </div>
        <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by SHAIK MOAHAMMED NAWAZ.</p>
        </footer>
      </div>
    );
  }


  return (
    <div className="flex flex-col h-screen bg-bground main-app-scope">
       {isLoadingAppData && <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-70 flex items-center justify-center z-[100]"><LoadingSpinner /><p className="text-white ml-3 text-lg">Loading data...</p></div>}
       {showUserTour && currentUser && <UserTour user={currentUser} onClose={handleCompleteUserTour} />}
      
      <TopNavbar
        currentUser={currentUser}
        currentPage={currentPage}
        navigateTo={navigateTo}
        handleLogout={handleLogout}
      />

      <main className="flex-1 p-6 overflow-y-auto"> {/* Removed `main-app-scope` from here as it's on the root */}
        <UIMessages />

        {currentPage === Page.Dashboard && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">Admin Dashboard</h2>
             <p className="text-md text-neutral">Organization ID: {currentUser.organizationId}</p>


            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Users</h3> <p className="text-3xl font-bold text-textlight">{users.length}</p> <p className="text-sm text-neutral">Total active users in your organization</p> </div>
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Pending Approvals</h3> <p className="text-3xl font-bold text-textlight">{pendingUsers.length}</p> <p className="text-sm text-neutral">Users awaiting approval in your organization</p> </div>
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Tasks</h3> <p className="text-3xl font-bold text-textlight">{tasks.length}</p> <p className="text-sm text-neutral">Total defined tasks in your organization</p> </div>
                <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Programs</h3> <p className="text-3xl font-bold text-textlight">{programs.length}</p> <p className="text-sm text-neutral">Total programs in your organization</p> </div>
                 <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Active Assignments</h3> <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'accepted_by_user' || a.status === 'pending_acceptance').length}</p> <p className="text-sm text-neutral">Tasks currently assigned in your organization</p> </div>
                 <div className="bg-surface p-5 rounded-lg shadow-md"> <h3 className="text-xl font-medium text-secondary mb-2">Completed Tasks</h3> <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'completed_admin_approved').length}</p> <p className="text-sm text-neutral">Successfully finished tasks in your organization</p> </div>
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
                <h3 className="text-xl font-semibold text-primary mb-4">Recent Admin Logs (Your Organization)</h3>
                {adminLogs.length === 0 ? <p className="text-neutral">No admin logs for your organization.</p> : (
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
               <FormInput label="Organization ID (Cannot be changed)" id="profileOrgId" type="text" value={userForm.organizationId} readOnly disabled description="Your site/organization identifier." />
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
            <h2 className="text-2xl font-semibold text-primary mb-1">User Management (Organization: {currentUser.organizationId})</h2>
            <p className="text-sm text-neutral mb-6">Manage accounts, approve registrations, view details for your organization.</p>

            {editingUserId || approvingPendingUser || new URLSearchParams(window.location.hash.split('?')[1]).get('action') === 'createUser' ? (
              <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-accent mb-4"> {editingUserId ? `Edit User: ${users.find(u=>u.id===editingUserId)?.displayName || ''}` : (approvingPendingUser ? `Approve: ${approvingPendingUser.displayName}` : 'Create New User (for your organization)')} </h3>
                <form onSubmit={editingUserId ? handleAdminUpdateUser : (approvingPendingUser ? handleApprovePendingUser : handleCreateUserByAdmin)} className="space-y-4">
                  <FormInput label="Email" id="userMgmtEmail" type="email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required />
                  <FormInput label="System ID / Username" id="userMgmtUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required />
                  <FormInput label="Display Name" id="userMgmtDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
                  <FormInput label="Position / Role Title" id="userMgmtPosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                  <FormTextarea label="Skills & Interests" id="userMgmtUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                  <FormInput label="Phone (Optional)" id="userMgmtPhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                  <FormSelect label="Notification Preference" id="userMgmtNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}> <option value="email">Email</option> <option value="phone" disabled>Phone (Not Implemented)</option> <option value="none">None</option> </FormSelect>
                  
                  <FormSelect label="Role" id="userMgmtRole" value={userForm.role} 
                    onChange={e => setUserForm({...userForm, role: e.target.value as Role})} 
                    disabled={!!approvingPendingUser || (editingUserId && users.find(u=>u.id===editingUserId)?.role === 'admin' && users.filter(u=>u.role==='admin').length <=1 )}>
                     <option value="user">User</option>
                     <option value="admin">Administrator (for this organization)</option>
                  </FormSelect>
                   {approvingPendingUser && <p className="text-xs text-neutral">Role for pending user is typically 'user' upon approval. Backend may enforce policies.</p>}
                   {(editingUserId && users.find(u=>u.id===editingUserId)?.role === 'admin' && users.filter(u=>u.role==='admin').length <=1 ) && <p className="text-xs text-neutral">Cannot demote the sole administrator of the organization.</p>}


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
            ) : ( <button onClick={() => { setUserForm({...initialUserFormData, role: 'user', organizationId: currentUser.organizationId}); clearMessages(); navigateTo(Page.UserManagement, {action: 'createUser'}); }} className="btn-primary mb-4 flex items-center"><PlusCircleIcon className="w-5 h-5 mr-2"/>Add New User</button> )}

             <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-3">Pre-registration Link (for your organization)</h3>
              <button onClick={handleGeneratePreRegistrationLink} className="btn-secondary flex items-center"><KeyIcon className="w-5 h-5 mr-2"/>Generate Link</button>
              {generatedLink && ( <div className="mt-3 p-3 bg-bground rounded"> <p className="text-sm text-textlight break-all">{generatedLink}</p> <button onClick={() => copyToClipboard(generatedLink)} className="text-xs btn-neutral mt-2">Copy</button> </div> )}
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Pending Approvals ({pendingUsers.length})</h3>
              {pendingUsers.length === 0 ? <p className="text-neutral">No users awaiting approval for your organization.</p> : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-bground"> <tr> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Name</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Email / System ID</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Intended Role / Date</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Actions</th> </tr> </thead>
                    <tbody className="bg-surface divide-y divide-gray-200">
                      {pendingUsers.map(pu => {
                        const canApprove = currentUser && currentUser.role === 'admin' && pu.organizationId === currentUser.organizationId;
                        return (
                          <tr key={pu.id}>
                            <td className="px-4 py-3 text-sm text-textlight">{pu.displayName}</td>
                            <td className="px-4 py-3 text-sm text-textlight">{pu.email} ({pu.uniqueId})</td>
                            <td className="px-4 py-3 text-sm text-textlight">{pu.role} <br/><span className="text-xs text-neutral">{new Date(pu.submissionDate).toLocaleDateString()}</span></td>
                            <td className="px-4 py-3 text-sm space-x-2">
                              <button
                                onClick={() => { setApprovingPendingUser(pu); setUserForm({ id:'', email: pu.email, uniqueId: pu.uniqueId, displayName: pu.displayName, position: '', userInterests: '', phone: '', notificationPreference: 'email', role: pu.role, password: '', confirmPassword: '', referringAdminId: pu.referringAdminId || currentUser?.id || '', organizationId: currentUser.organizationId }); setEditingUserId(null); navigateTo(Page.UserManagement, {action: 'approveUser', userId: pu.id}); clearMessages(); }}
                                className={`btn-success text-xs px-2 py-1 ${!canApprove ? 'opacity-50 cursor-not-allowed' : ''}`}
                                disabled={!canApprove}
                                title={!canApprove ? "Approval restricted." : "Approve this user"}
                              >
                                Approve
                              </button>
                              <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger text-xs px-2 py-1" disabled={!canApprove}>Reject</button>
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
              {users.length === 0 ? <p className="text-neutral">No active users in your organization.</p> : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-bground"> <tr> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Name</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Email / System ID</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Role / Position</th> <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase">Actions</th> </tr> </thead>
                    <tbody className="bg-surface divide-y divide-gray-200">
                      {users.map(user => ( <tr key={user.id}> <td className="px-4 py-3 text-sm font-medium text-textlight">{user.displayName}</td> <td className="px-4 py-3 text-sm text-textlight">{user.email}<br/><span className="text-xs text-neutral">{user.uniqueId}</span></td> <td className="px-4 py-3 text-sm text-textlight capitalize">{user.role}<br/><span className="text-xs text-neutral">{user.position}</span></td> <td className="px-4 py-3 text-sm space-x-2"> 
                        {currentUser.id !== user.id && ( 
                            <button onClick={() => { setEditingUserId(user.id); setUserForm({ ...user, password: '', confirmPassword: '' }); setApprovingPendingUser(null); navigateTo(Page.UserManagement, {action: 'editUser', userId: user.id}); clearMessages(); }} className="btn-info text-xs px-2 py-1"> Edit </button> 
                        )}
                        {currentUser.id !== user.id && ( 
                          <button onClick={() => handleDeleteUser(user.id)} className={`btn-danger text-xs px-2 py-1 ${user.role === 'admin' && users.filter(u => u.role === 'admin').length <= 1 ? 'opacity-50 cursor-not-allowed' : ''}`} disabled={user.role === 'admin' && users.filter(u => u.role === 'admin').length <=1 } title={user.role === 'admin'  && users.filter(u => u.role === 'admin').length <=1 ? "Cannot delete the sole admin of the organization." : "Delete user"}>Delete</button> 
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
            <h2 className="text-2xl font-semibold text-primary mb-6">Manage Programs (Organization: {currentUser.organizationId})</h2>
            <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Create Program</h3> <form onSubmit={handleCreateProgram} className="space-y-4"> <FormInput label="Program Name" id="programName" value={programForm.name} onChange={e => setProgramForm({...programForm, name: e.target.value})} required /> <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({...programForm, description: e.target.value})} required /> <button type="submit" className="btn-primary">Create</button> </form> </div>
            <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Existing Programs ({programs.length})</h3> {programs.length === 0 ? <p className="text-neutral">No programs in your organization.</p> : ( <ul className="space-y-3"> {programs.map(p => ( <li key={p.id} className="p-4 bg-bground rounded-md shadow flex justify-between items-start"> <div> <h4 className="font-semibold text-textlight">{p.name}</h4> <p className="text-sm text-neutral">{p.description}</p> </div> <button onClick={() => handleDeleteProgram(p.id)} className="btn-danger text-xs p-1 ml-2 self-start"><TrashIcon className="w-4 h-4"/></button> </li> ))} </ul> )} </div>
          </div>
        )}

        {currentPage === Page.ManageTasks && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Manage Tasks (Organization: {currentUser.organizationId})</h2>
             <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Create Task</h3> <form onSubmit={handleCreateTask} className="space-y-4"> <FormInput label="Task Title" id="taskTitle" value={taskForm.title} onChange={e => setTaskForm({...taskForm, title: e.target.value})} required /> <FormTextarea label="Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({...taskForm, description: e.target.value})} required /> <FormTextarea label="Required Skills (comma-separated)" id="taskRequiredSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({...taskForm, requiredSkills: e.target.value})} required placeholder="e.g., JS, Writing"/> <FormSelect label="Related Program (Optional)" id="taskProgramId" value={taskForm.programId} onChange={e => setTaskForm({...taskForm, programId: e.target.value})}> <option value="">None</option> {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)} </FormSelect> <FormInput label="Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline} onChange={e => setTaskForm({...taskForm, deadline: e.target.value})} /> <button type="submit" className="btn-primary">Create Task</button> </form> </div>
            <div className="bg-surface p-6 rounded-lg shadow-md"> <h3 className="text-xl font-semibold text-accent mb-4">Existing Tasks ({tasks.length})</h3> {tasks.length === 0 ? <p className="text-neutral">No tasks in your organization.</p> : ( <ul className="space-y-3"> {tasks.map(task => ( <li key={task.id} className="p-4 bg-bground rounded-md shadow"> <div className="flex justify-between items-start"> <div> <h4 className="font-semibold text-textlight">{task.title}</h4> <p className="text-sm text-neutral mt-1">{task.description}</p> <p className="text-xs text-neutral mt-1"><strong>Skills:</strong> {task.requiredSkills}</p> {task.programName && <p className="text-xs text-neutral mt-1"><strong>Program:</strong> {task.programName}</p>} {task.deadline && <p className="text-xs text-neutral mt-1"><strong>Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>} </div> <button onClick={() => handleDeleteTask(task.id)} className="btn-danger text-xs p-1 ml-2 self-start"><TrashIcon className="w-4 h-4"/></button> </div> <div className="mt-2 pt-2 border-t border-gray-300"> <p className="text-xs font-medium text-neutral">Assigned:</p> <ul className="text-xs list-disc list-inside pl-2"> {assignments.filter(a=>a.taskId===task.id).map(a=>(<li key={`${a.taskId}-${a.personId}`} className="text-neutral">{a.personName} - <span className={`font-semibold ${a.status==='completed_admin_approved'?'text-success':a.status==='declined_by_user'?'text-danger':a.status==='pending_acceptance'?'text-warning':'text-info'}`}>{a.status.replace(/_/g,' ')}</span></li>))} {assignments.filter(a=>a.taskId===task.id).length===0 && <li className="text-neutral">None.</li>}</ul></div></li>))}</ul>)}</div>
          </div>
        )}

        {currentPage === Page.AssignWork && currentUser.role === 'admin' && (() => {
            const usersAvailableForAssignment = users.filter(u => {
              if (u.role !== 'user') return false;
              // A user is unavailable if they have ANY task that is currently pending their acceptance or is accepted by them.
              const isBusy = assignments.some(a => a.personId === u.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'));
              return !isBusy;
            });

            return (
              <div className="space-y-6">
                <h2 className="text-2xl font-semibold text-primary mb-6">Assign Work (Organization: {currentUser.organizationId})</h2>
                <div className="bg-surface p-6 rounded-lg shadow-md">
                  <FormSelect label="1. Select Task to Assign" id="selectTaskForAssignment" value={selectedTaskForAssignment || ''} onChange={e => { setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); clearMessages(); }}> <option value="">-- Choose a task --</option> {tasks.map(t => (<option key={t.id} value={t.id}>{t.title}</option>))} </FormSelect>
                  {selectedTaskForAssignment && ( <div className="mt-4 p-3 bg-bground rounded"> <h4 className="font-medium text-textlight">Selected Task:</h4> <p className="text-sm text-neutral">{tasks.find(t=>t.id === selectedTaskForAssignment)?.description}</p> <p className="text-xs text-neutral">Skills: {tasks.find(t=>t.id === selectedTaskForAssignment)?.requiredSkills}</p> {tasks.find(t=>t.id === selectedTaskForAssignment)?.deadline && <p className="text-xs">Deadline: {new Date(tasks.find(t=>t.id === selectedTaskForAssignment)!.deadline!).toLocaleDateString()}</p>} </div> )}
                  
                  <h3 className="text-lg font-medium text-textlight mt-6">2. Get AI Suggestion (Recommended)</h3>
                  <button onClick={handleGetAssignmentSuggestion} className="btn-accent mt-2 flex items-center" disabled={!selectedTaskForAssignment || isLoadingSuggestion}> {isLoadingSuggestion ? <LoadingSpinner /> : <><LightBulbIcon className="w-5 h-5 mr-2"/>Get AI Suggestion</>} </button>
                  {assignmentSuggestion && ( <div className={`mt-4 p-3 rounded shadow-sm ${assignmentSuggestion.suggestedPersonName ? 'bg-green-50' : 'bg-yellow-50'}`}> <p className="text-sm font-medium">{assignmentSuggestion.suggestedPersonName ? `Suggests: ${assignmentSuggestion.suggestedPersonName}` : "AI:"}</p> <p className="text-xs text-neutral">{assignmentSuggestion.justification}</p> </div> )}
                  
                  <form onSubmit={(e) => handleAssignTask(e, assignmentSuggestion?.suggestedPersonName)} className="mt-6 space-y-4">
                    <h3 className="text-lg font-medium text-textlight">3. Assign to Person</h3>
                    <FormSelect label="Assign to" id="assignPerson" name="assignPerson" required defaultValue={assignmentSuggestion?.suggestedPersonName ? users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName)?.id : ""}>
                      <option value="">-- Select Person --</option>
                      {usersAvailableForAssignment.map(user => (
                        <option key={user.id} value={user.id}>{user.displayName} ({user.position})</option>
                      ))}
                    </FormSelect>
                    <FormInput label="Specific Deadline (Optional)" id="specificDeadline" name="specificDeadline" type="date" value={assignmentForm.specificDeadline} onChange={e => setAssignmentForm({...assignmentForm, specificDeadline: e.target.value})} />
                    <button type="submit" className="btn-primary" disabled={!selectedTaskForAssignment}>Assign Task</button>
                  </form>
                </div>
              </div>
            );
        })()}

        {currentPage === Page.ViewAssignments && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Assignments</h2>
            {assignments.filter(a => currentUser.role === 'admin' || a.personId === currentUser.id).length === 0 ? ( <p className="text-neutral bg-surface p-4 rounded-md shadow"> {currentUser.role === 'admin' ? "No assignments in your organization." : "No tasks assigned to you."} </p> ) : (
              <ul className="space-y-4">
                {assignments.filter(a => currentUser.role === 'admin' || a.personId === currentUser.id).sort((x,y) => (x.deadline && y.deadline) ? new Date(x.deadline).getTime() - new Date(y.deadline).getTime() : 0).map(assignment => {
                    const task = typeof assignment.taskId === 'object' ? assignment.taskId : tasks.find(t => t.id === assignment.taskId);
                    const isLate = assignment.deadline && new Date() > new Date(assignment.deadline) && (assignment.status === 'pending_acceptance' || assignment.status === 'accepted_by_user');
                    const isSubmittedLate = assignment.status === 'submitted_late';
                    return ( <li key={assignment.id} className="bg-surface p-4 rounded-lg shadow-md"> <h3 className={`text-lg font-semibold ${isLate && !isSubmittedLate ? 'text-danger' : 'text-textlight'}`}>{assignment.taskTitle}</h3> {currentUser.role === 'admin' && <p className="text-sm text-neutral">To: <strong>{assignment.personName}</strong></p>} <p className="text-xs text-neutral mt-1">Status: <span className={`font-medium ${assignment.status==='completed_admin_approved'?'text-success':assignment.status==='declined_by_user'?'text-danger':assignment.status.startsWith('submitted')?'text-info':assignment.status==='pending_acceptance'?'text-warning':'text-blue-500' }`}>{assignment.status.replace(/_/g,' ')}</span> {isLate && !isSubmittedLate && <span className="text-danger text-xs font-bold ml-2">(OVERDUE)</span>} {isSubmittedLate && <span className="text-warning text-xs font-bold ml-2">(LATE)</span>} </p> {task && <p className="text-sm text-neutral mt-1">{task.description}</p>} {task?.requiredSkills && <p className="text-xs">Skills: {task.requiredSkills}</p>} {assignment.deadline && <p className="text-xs">Deadline: {new Date(assignment.deadline).toLocaleDateString()}</p>} {assignment.justification && assignment.justification !== 'Manually assigned by admin.' && <p className="text-xs italic">AI: {assignment.justification}</p>} {assignment.userSubmissionDate && <p className="text-xs">Submitted: {new Date(assignment.userSubmissionDate).toLocaleString()}</p>} {assignment.userDelayReason && <p className="text-xs">Delay reason: {assignment.userDelayReason}</p>}
                        <div className="mt-3 pt-3 border-t border-gray-200 space-x-2 flex flex-wrap gap-y-2">
                          {assignment.status === 'pending_acceptance' && assignment.personId === currentUser.id && ( <> <button onClick={() => handleUserAcceptTask(assignment.id)} className="btn-success text-sm">Accept</button> <button onClick={() => handleUserDeclineTask(assignment.id)} className="btn-danger text-sm">Decline</button> </> )}
                          {assignment.status === 'accepted_by_user' && assignment.personId === currentUser.id && ( <> {isLate && assignmentToSubmitDelayReason !== assignment.id && ( <button onClick={() => setAssignmentToSubmitDelayReason(assignment.id)} className="btn-warning text-sm">Submit Late</button> )} {assignmentToSubmitDelayReason === assignment.id && isLate && ( <div className="w-full space-y-2 my-2 p-2 border border-warning bg-yellow-50"> <FormTextarea label="Reason for Late Submission:" id={`delayReason-${assignment.id}`} value={userSubmissionDelayReason} onChange={e => setUserSubmissionDelayReason(e.target.value)} /> <button onClick={() => handleUserSubmitTask(assignment.id, userSubmissionDelayReason)} className="btn-primary text-sm">Confirm</button> <button onClick={() => { setAssignmentToSubmitDelayReason(null); setUserSubmissionDelayReason(''); }} className="btn-neutral text-sm ml-2">Cancel</button> </div> )} {!isLate && ( <button onClick={() => handleUserSubmitTask(assignment.id)} className="btn-primary text-sm">Mark Completed</button> )} </> )}
                          {currentUser.role === 'admin' && (assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') && ( <button onClick={() => handleAdminApproveTaskCompletion(assignment.id)} className="btn-success text-sm">Approve Completion</button> )}
                        </div> </li> );
                  })} </ul> )}
          </div>
        )}

        {currentPage === Page.ViewTasks && (
            <div className="space-y-6"> <h2 className="text-2xl font-semibold text-primary mb-6">Available Tasks (Your Organization)</h2> {tasks.length === 0 ? ( <p className="text-neutral bg-surface p-4 rounded-md shadow">No tasks defined in your organization.</p> ) : (
                <ul className="space-y-4">
                    {tasks.map(task => {
                        const taskAssignments = assignments.filter(a => a.taskId === task.id);
                        const relevantAssignments = taskAssignments.filter(a => a.status !== 'declined_by_user');
                        let availability: string;
                        let color: string;

                        if (relevantAssignments.length === 0) {
                            availability = "Available";
                            color = "text-success";
                        } else if (relevantAssignments.every(a => a.status === 'completed_admin_approved')) {
                            availability = "Completed";
                            color = "text-success";
                        } else if (relevantAssignments.some(a => a.status === 'accepted_by_user' || a.status.startsWith('submitted'))) {
                            availability = "In Progress";
                            color = "text-info";
                        } else if (relevantAssignments.some(a => a.status === 'pending_acceptance')) {
                            availability = "Pending Acceptance";
                            color = "text-warning";
                        } else {
                            // Fallback for mixed states (e.g., some completed, some pending)
                            availability = "In Progress";
                            color = "text-info";
                        }

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
