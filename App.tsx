
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import * as emailService from './src/utils/emailService'; // Corrected import path
import { validatePassword } from './src/utils/validation'; // Corrected import path
// import * //as cloudDataService from './services/cloudDataService'; // Deactivated
import LoadingSpinner from './components/LoadingSpinner';
import { UsersIcon, ClipboardListIcon, LightBulbIcon, CheckCircleIcon, TrashIcon, PlusCircleIcon, KeyIcon, BriefcaseIcon, LogoutIcon, UserCircleIcon } from './components/Icons';
import PreRegistrationFormPage from './components/PreRegistrationFormPage';
import UserTour from './components/UserTour';
// import Sidebar from './components/Sidebar'; // Sidebar is replaced by TopNavbar
import TopNavbar from './components/TopNavbar'; // Import the new TopNavbar component

const API_BASE_URL = 'https://task-management-backend-17a5.onrender.com';
const JWT_TOKEN_KEY = 'task-assign-jwt';

// --- START OF NEW AUTH FORM COMPONENTS ---
const AuthFormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { 
  id: string; 
  'aria-label': string;
  value: string; // Explicitly define value
  onChange: (event: React.ChangeEvent<HTMLInputElement>) => void; // Explicitly define onChange
}> = ({ id, value, onChange, ...props }) => ( // Destructure value and onChange
  <input
    id={id}
    value={value} // Pass explicitly
    onChange={onChange} // Pass explicitly
    {...props} // Spread other props like type, placeholder, required, etc.
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
        // Throwing here will be caught by the outer catch, which then returns defaultReturnVal.
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
        return defaultReturnVal; // This is a valid return path
      }
      // Throwing here will be caught by the outer catch, which then returns defaultReturnVal.
      throw new Error(errorData?.message || errorData?.error || responseText || `Request failed with status ${response.status}`);
    }

    if (!responseText) {
      return defaultReturnVal;
    }

    const parsedData = JSON.parse(responseText);
    return parsedData as T;
  } catch (error: any) { // Catch errors from fetch() itself or explicit throws from the try block
    console.error(`Error in fetchData for ${endpoint}: ${error.message}`);
     if (error.message.includes("Failed to fetch")) {
        // Log a more specific message for network errors that will be "swallowed" into a defaultReturnVal
        console.error(`Network error: Could not connect to the server at ${API_BASE_URL}. Endpoint: ${endpoint}. Details: ${error.message}`);
    }
    // For all errors caught here, return defaultReturnVal to satisfy TypeScript's "must return a value" rule.
    // The actual error is logged to the console.
    return defaultReturnVal;
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
  const [isRefreshingDashboard, setIsRefreshingDashboard] = useState<boolean>(false);


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
    companyName: '', // For admin UI when creating new "site", changed from organizationName
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

  const setCurrentUser = (user: User | null) => {
    setCurrentUserInternal(user);
    if (user && user.token) {
      localStorage.setItem(JWT_TOKEN_KEY, user.token);
    } else if (!user) {
      localStorage.removeItem(JWT_TOKEN_KEY);
    }
  };

  const addAdminLogEntry = useCallback(async (logText: string, imagePreviewUrl?: string) => {
    if (!currentUser || currentUser.role !== 'admin') {
      console.warn("Admin log attempt by non-admin or no current user.");
      return;
    }

    const logData = {
      logText,
      imagePreviewUrl,
    };

    try {
      const newLog = await fetchData<AdminLogEntry>('/admin-logs', {
        method: 'POST',
        body: JSON.stringify(logData),
      });

      if (newLog && newLog.id) {
        setAdminLogs(prevLogs => [newLog, ...prevLogs].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
        console.log('[App.tsx] Admin log entry added locally:', newLog);
      } else {
        console.error("[App.tsx] Failed to create admin log entry or API returned invalid data. NewLog:", newLog);
        // setError("Failed to record admin activity."); // Optional: if you want to show users this error
      }
    } catch (error: any) {
      // This catch block is mostly for unexpected errors if fetchData itself changes to throw
      console.error('Unexpected error in addAdminLogEntry:', error);
      // setError(`Failed to record admin activity: ${error.message}`); // Optional
    }
  }, [currentUser]);


  const loadInitialData = useCallback(async (loggedInUserTokenData?: User) => { // Token data includes orgId
    setIsLoadingAppData(true);
    setError(null); // Clear previous errors on new load attempt
    try {
      let activeUserWithFullProfile: User | null = null;

      if (loggedInUserTokenData && loggedInUserTokenData.token && loggedInUserTokenData.organizationId) {
          setCurrentUserInternal(loggedInUserTokenData); // Tentatively set currentUser based on token
          // Ensure token from loggedInUserTokenData is in localStorage for subsequent fetchData calls
          localStorage.setItem(JWT_TOKEN_KEY, loggedInUserTokenData.token);
          const userFromServer = await fetchData<BackendUser>('/users/current', {}, null);
          if (userFromServer && userFromServer.organizationId === loggedInUserTokenData.organizationId) {
            activeUserWithFullProfile = { ...userFromServer, id: userFromServer.id || userFromServer._id!, token: loggedInUserTokenData.token };
            setCurrentUserInternal(activeUserWithFullProfile); // Final set from server
          } else {
            console.warn("loadInitialData: Backend validation of token failed or org ID mismatch. Logging out.", { tokenOrg: loggedInUserTokenData.organizationId, serverUser: userFromServer });
            localStorage.removeItem(JWT_TOKEN_KEY);
            setCurrentUserInternal(null);
          }
      } else if (!loggedInUserTokenData) { // No pre-decoded token, check localStorage directly
        const token = localStorage.getItem(JWT_TOKEN_KEY);
        if (token) {
           const userFromServer = await fetchData<BackendUser>('/users/current', {}, null);
           if (userFromServer && userFromServer.organizationId) {
             activeUserWithFullProfile = { ...userFromServer, id: userFromServer.id || userFromServer._id!, token };
             setCurrentUserInternal(activeUserWithFullProfile);
           } else {
             console.warn("loadInitialData: Token from localStorage invalid or user lacks orgId on backend. Logging out.", { serverUser: userFromServer });
             localStorage.removeItem(JWT_TOKEN_KEY);
             setCurrentUserInternal(null);
           }
        }
        // If no token in localStorage, activeUserWithFullProfile remains null.
      } else { // loggedInUserTokenData exists, but is missing token or orgId (should be caught by initial useEffect)
        console.warn("loadInitialData: loggedInUserTokenData provided but incomplete. Logging out.", { loggedInUserTokenData });
        localStorage.removeItem(JWT_TOKEN_KEY);
        setCurrentUserInternal(null);
      }

      if (activeUserWithFullProfile) {
        const [
          loadedUsers, loadedPendingUsers, loadedTasks, loadedPrograms, loadedAssignments, loadedAdminLogs,
        ] = await Promise.all([
          fetchData<User[]>('/users', {}, []),
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
        console.log('[App.tsx] Initial Loaded Admin Logs:', loadedAdminLogs);
      } else {
        // No active user, clear all data arrays
        setUsers([]); setPendingUsers([]); setTasks([]); setPrograms([]); setAssignments([]); setAdminLogs([]);
      }
      // console.log("Initial data processed. currentUser:", activeUserWithFullProfile ? activeUserWithFullProfile.email : "null");
    } catch (err: any) {
      console.error("Critical error during initial data load:", err);
      setError("Failed to load application data. Error: " + err.message);
      if (err.message.includes("Authentication/Authorization failed") ||
          err.message.includes("Token is missing organization information") ||
          err.message.includes("Invalid or expired token")) {
        setCurrentUser(null); // This will also remove JWT_TOKEN_KEY
        // Navigation to Login will be handled by the hashChange effect
      }
    } finally {
      setIsLoadingAppData(false);
    }
  }, [addAdminLogEntry]); // addAdminLogEntry is stable due to useCallback, but including if it were to change or for explicitness with linters. Usually, only state setters or passed-down functions that might change.


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
                    console.warn("Token found in localStorage but was incomplete (missing id or organizationId). Clearing token.");
                    localStorage.removeItem(JWT_TOKEN_KEY);
                    setCurrentUserInternal(null);
                    setIsLoadingAppData(false); // Ensure loading state is updated
                }
            } catch (e) {
                console.error("Failed to parse token from localStorage. Clearing token.", e);
                localStorage.removeItem(JWT_TOKEN_KEY);
                setCurrentUserInternal(null);
                setIsLoadingAppData(false); // Ensure loading state is updated
            }
        } else {
             // No token in localStorage, loadInitialData will handle setting isLoadingAppData to false.
            loadInitialData();
        }
    }
  }, [currentUser, loadInitialData]);


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
                ...initialPreRegistrationFormState, // Reset other fields
                referringAdminId: '',
                referringAdminDisplayName: 'N/A (No ID Provided)',
                isReferralLinkValid: false
            }));
        } else {
            fetchData<{ success: boolean; isValidRef: boolean; displayName?: string; organizationId?: string; message?: string }>(
                `/users/validate-admin-ref/${refAdminIdFromHash}`,
                {},
                null
            ).then(validationResult => {
                if (validationResult && validationResult.success && validationResult.isValidRef && validationResult.displayName) {
                    setPreRegistrationForm(prev => ({
                        ...initialPreRegistrationFormState, // Reset other fields like uniqueId, password etc.
                        referringAdminId: refAdminIdFromHash,
                        referringAdminDisplayName: validationResult.displayName,
                        isReferralLinkValid: true
                    }));
                } else {
                    setPreRegistrationForm(prev => ({
                        ...initialPreRegistrationFormState,
                        referringAdminId: refAdminIdFromHash,
                        referringAdminDisplayName: `Invalid Admin Link (${validationResult?.message || 'Validation failed'})`,
                        isReferralLinkValid: false
                    }));
                }
            }).catch(err => {
                console.error("Error validating admin ref for pre-registration:", err);
                setPreRegistrationForm(prev => ({
                    ...initialPreRegistrationFormState,
                    referringAdminId: refAdminIdFromHash,
                    referringAdminDisplayName: 'Error validating link',
                    isReferralLinkValid: false
                }));
            });
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

      const defaultPageDetermination = currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
      let newPage = (Object.values(Page).includes(targetPageFromHashPath as Page) ? targetPageFromHashPath : defaultPageDetermination) as Page;

      if ([Page.Login, Page.PreRegistration, Page.AdminRegistrationEmail, Page.AdminRegistrationProfile, Page.InitialAdminSetup].includes(newPage as Page)) {
        newPage = defaultPageDetermination;
      }

      _setCurrentPageInternal(newPage); // Set page first

      // If admin navigates to Dashboard or UserManagement, re-fetch key lists for freshness
      if (currentUser && currentUser.role === 'admin' &&
          (newPage === Page.Dashboard || newPage === Page.UserManagement) &&
          (isLoadingAppData === false)
      ) {
          const currentTokenInStorage = localStorage.getItem(JWT_TOKEN_KEY);
          if (!currentTokenInStorage) {
              console.warn(`Admin data re-fetch for ${newPage} aborted: Token disappeared from localStorage just before fetch.`);
              setError("Your session may have expired or the token was cleared. Please log in again.");
              setCurrentUser(null);
              navigateTo(Page.Login);
              // Do not return here, let the rest of processHash run which might also redirect to Login.
          } else {
            Promise.all([
                fetchData<User[]>('/users', {}, []),
                fetchData<PendingUser[]>('/pending-users', {}, [])
            ]).then(([loadedUsers, loadedPendingUsers]) => {
                if (loadedUsers) setUsers(loadedUsers);
                if (loadedPendingUsers) setPendingUsers(loadedPendingUsers);
            }).catch(err => {
                console.error("Error re-fetching admin data on navigation:", err);
                setError("Could not refresh admin data: " + err.message);
                 if (err.message.toLowerCase().includes("access token missing") || err.message.toLowerCase().includes("invalid or expired token")) {
                    setCurrentUser(null);
                    navigateTo(Page.Login);
                }
            });
          }
      }


      const currentTopLevelPagePath = window.location.hash.substring(1).split('?')[0].toUpperCase();
      const targetParams = paramsString ? Object.fromEntries(params) : undefined;

      if (newPage !== currentTopLevelPagePath && Object.values(Page).includes(newPage)) {
           navigateTo(newPage, targetParams);
      }

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

  const { name, email, password, confirmPassword, uniqueId, position, role, companyName } = newRegistrationForm; // Changed organizationName to companyName

  if (!name.trim() || !email.trim() || !password.trim() || !confirmPassword.trim() || !uniqueId.trim()) {
    setError("Full Name, Email, Password, Confirm Password, and System ID are required.");
    return;
  }
  if (role === 'admin' && !companyName.trim()) { // Changed organizationName to companyName
      setError("Company Name is required when registering as an Administrator for a new site.");
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
    displayName: name.trim(),
    email: email.trim(),
    password: password, // Do not trim password
    role: role,
    uniqueId: uniqueId.trim(),
    position: position.trim() || (role === 'admin' ? 'Administrator' : 'User Position'),
    companyName: role === 'admin' ? companyName.trim() : undefined, // Changed organizationName to companyName
  };

  const endpoint = '/users/register';

  try {
    const response = await fetchData<{ success: boolean; user: BackendUser | BackendPendingUser; message?: string, errors?: Record<string,string> }>(endpoint, {
      method: 'POST',
      body: JSON.stringify(registrationData),
    });

    if (response && response.success && response.user) {
      const createdEntity = response.user;

      if ('role' in createdEntity && createdEntity.role === 'admin') { // Assuming BackendUser for admin
         setSuccessMessage(`Administrator account for company '${companyName}' registered successfully! You can now log in.`); // Changed organizationName to companyName
      } else { // Could be BackendPendingUser or BackendUser if auto-approved user
         setSuccessMessage(`User account for ${createdEntity.displayName} registered. If admin approval is needed, you'll be notified.`);
      }

      // Pass companyName to email service if admin
      const companyNameToEmail = role === 'admin' ? companyName : '';
      emailService.sendWelcomeRegistrationEmail(createdEntity.email, createdEntity.displayName, createdEntity.role, companyNameToEmail); // Pass companyName
      setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user', uniqueId: '', position: '', companyName: '' }); // Changed organizationName to companyName
      setAuthView('login');
    } else {
      let mainError = response?.message || "Registration failed. Please check details and try again.";
      if(response?.errors){
        const fieldErrors = Object.entries(response.errors).map(([field, msg]) => `${field}: ${msg}`).join('; ');
        mainError = `${mainError} (${fieldErrors})`;
      }
      setError(mainError);
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
    uniqueId: uniqueId.trim(),
    displayName: displayName.trim(),
    email: email.trim(),
    password: password, // Do not trim password
    role: 'user' as Role, // Pre-registrations are for 'user' role.
    referringAdminId: referringAdminId || undefined
    // organizationId will be determined by backend based on referringAdminId
  };

  try {
    const response = await fetchData<{ success: boolean; user: BackendPendingUser; message?: string, errors?: Record<string,string> }>('/pending-users', {
      method: 'POST',
      body: JSON.stringify(newPendingUserData),
    });

    if (response && response.success && response.user) {
      setSuccessMessage("Pre-registration submitted successfully! Your account is pending administrator approval.");
      // Reset form but keep referral info for display if they stay on page
      setPreRegistrationForm(prev => ({
          ...initialPreRegistrationFormState,
          referringAdminId: prev.referringAdminId,
          referringAdminDisplayName: prev.referringAdminDisplayName,
          isReferralLinkValid: prev.isReferralLinkValid
      }));


      emailService.sendPreRegistrationSubmittedToUserEmail(response.user.email, response.user.displayName, preRegistrationForm.referringAdminDisplayName);
      // Backend should notify the specific referring admin
    } else {
      let mainError = response?.message || "Failed to submit pre-registration.";
      if(response?.errors){
        const fieldErrors = Object.entries(response.errors).map(([field, msg]) => `${field}: ${msg}`).join('; ');
        mainError = `${mainError} (${fieldErrors})`;
      }
      setError(mainError);
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
     if (!/\S+@\S+\.\S+/.test(email.trim())) {
      setError("Please enter a valid email address.");
      return;
    }

    try {
      const response = await fetchData<{ success: boolean; user: User; token: string; message?: string }>('/users/login', {
        method: 'POST',
        body: JSON.stringify({ email: email.trim(), password: password }), // Trim email, do not trim password
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
        // The hashChange useEffect is better suited to handle navigation post-login based on updated currentUser.
        const targetPage = loggedInUserWithTokenAndOrg.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
        navigateTo(targetPage);

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
      uniqueId: uniqueId.trim(),
      displayName: displayName.trim(),
      position: position.trim(),
      userInterests: userInterests?.trim(),
      phone: phone?.trim(),
      notificationPreference,
    };

    if (password) {
        if (password !== confirmPassword) {
            setError("New passwords do not match."); return;
        }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) {
            setError(passwordValidationResult.errors.join(" ")); return;
        }
        updatePayload.password = password; // Do not trim password
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
    if (!/\S+@\S+\.\S+/.test(email.trim())) {
        setError("Please enter a valid email address for the user."); return;
    }

    const updatePayload: Partial<User> & { password?: string } = {
      email: email.trim(),
      uniqueId: uniqueId.trim(),
      displayName: displayName.trim(),
      position: position.trim(),
      userInterests: userInterests?.trim(),
      phone: phone?.trim(),
      notificationPreference, role,
      organizationId: currentUser.organizationId
    };

    if (password) {
        if (password !== confirmPassword) { setError("New passwords do not match."); return; }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) { setError(passwordValidationResult.errors.join(" ")); return; }
        updatePayload.password = password; // Do not trim password
    }

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string }>(`/users/${editingUserId}`, {
        method: 'PUT',
        body: JSON.stringify(updatePayload),
      });

      if (response && response.success && response.user) {
        const baseUpdatedUser: User = {...response.user, id: response.user.id || response.user._id!, organizationId: currentUser.organizationId };
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
    if (!/\S+@\S+\.\S+/.test(email.trim())) { setError("Please enter a valid email address."); return; }
    if (password !== confirmPassword) { setError("Passwords do not match."); return; }
    const passVal = validatePassword(password);
    if (!passVal.isValid) { setError(passVal.errors.join(" ")); return; }

    const newUserData = {
      email: email.trim(),
      uniqueId: uniqueId.trim(),
      password: password, // Do not trim
      role: role,
      displayName: displayName.trim(),
      position: position.trim(),
      userInterests: userInterests?.trim(),
      phone: phone?.trim(),
      notificationPreference,
      referringAdminId: currentUser.id,
      organizationId: currentUser.organizationId
    };

    try {
      const response = await fetchData<{ success: boolean; user: BackendUser; message?: string, errors?: Record<string,string> }>('/users/register', {
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
        let mainError = response?.message || "Failed to create user.";
        if(response?.errors){
          const fieldErrors = Object.entries(response.errors).map(([field, msg]) => `${field}: ${msg}`).join('; ');
          mainError = `${mainError} (${fieldErrors})`;
        }
        setError(mainError);
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
        position: userForm.position.trim() || 'Default Position',
        userInterests: userForm.userInterests?.trim() || '',
        phone: userForm.phone?.trim() || '',
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

  const handleGeneratePreRegistrationLink = async () => {
    if (!currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) {
      setError("Only admins can generate pre-registration links."); return;
    }
    const link = `${window.location.origin}${window.location.pathname}#${Page.PreRegistration}?refAdminId=${currentUser.id}`;
    setGeneratedLink(link);
    setSuccessMessage("Pre-registration link generated. Share it with the intended user.");
    await addAdminLogEntry(`Admin ${currentUser.displayName} generated a pre-registration link.`);
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
    const newProgramData: Omit<Program, 'id'> = { name: programForm.name.trim(), description: programForm.description.trim() };
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
    const newTaskData: Partial<Omit<Task, 'id'>> = { ...taskForm, title: taskForm.title.trim(), description: taskForm.description.trim(), requiredSkills: taskForm.requiredSkills.trim(), deadline: taskForm.deadline ? new Date(taskForm.deadline).toISOString().split('T')[0] : undefined, programName: associatedProgram?.name };
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
      const updatedAssignments = await fetchData<Assignment[]>('/assignments', {}, []);
      setAssignments(updatedAssignments || []);
      setSuccessMessage(`Task "${taskToDelete?.title}" deleted.`);
      if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} deleted task: ${taskToDelete?.title}.`);
    } catch (err:any) { setError(err.message || "Failed to delete task."); }
  };

  const handleAssignTask = async (e: React.FormEvent, taskId: string, personId: string) => {
    e.preventDefault();
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin' || !currentUser.organizationId) {
      setError("Only admins can assign tasks.");
      return;
    }
    if (!taskId || !personId) {
      setError("Task and person must be selected for assignment.");
      return;
    }

    const taskToAssign = tasks.find(t => t.id === taskId);
    const personToAssign = users.find(u => u.id === personId);

    if (!taskToAssign || !personToAssign) {
      setError("Selected task or person not found.");
      return;
    }

    const existingAssignmentForTask = assignments.find(a => a.taskId === taskId && a.personId === personId && a.organizationId === currentUser.organizationId);
    if (existingAssignmentForTask) {
        setError(`${personToAssign.displayName} is already assigned to task "${taskToAssign.title}".`);
        return;
    }

    const newAssignmentData = {
      taskId,
      personId,
      justification: assignmentSuggestion?.suggestedPersonName === personToAssign.displayName ? assignmentSuggestion.justification : 'Manual assignment',
      deadline: assignmentForm.specificDeadline ? new Date(assignmentForm.specificDeadline).toISOString() : taskToAssign.deadline,
      status: 'pending_acceptance' as AssignmentStatus,
    };

    try {
      const createdAssignment = await fetchData<Assignment>('/assignments', {
        method: 'POST',
        body: JSON.stringify(newAssignmentData),
      });

      if (createdAssignment && createdAssignment.taskId) {
        setAssignments(prev => [...prev, createdAssignment]);
        setSuccessMessage(`Task "${taskToAssign.title}" assigned to ${personToAssign.displayName}.`);
        setSelectedTaskForAssignment(null);
        setAssignmentSuggestion(null);
        setAssignmentForm({ specificDeadline: ''});
        await addAdminLogEntry(`Admin ${currentUser.displayName} assigned task "${taskToAssign.title}" to ${personToAssign.displayName}.`);
      } else {
        setError("Failed to assign task. API did not return a valid assignment.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to assign task.");
    }
  };


  const handleUpdateAssignmentStatus = async (taskId: string, personId: string, status: AssignmentStatus, userDelayReason?: string) => {
    clearMessages();
    if (!currentUser || !currentUser.organizationId) {
      setError("User context or organization ID missing.");
      return;
    }

    const assignmentToUpdate = assignments.find(a => a.taskId === taskId && a.personId === personId && a.organizationId === currentUser.organizationId);
    if (!assignmentToUpdate) {
      setError("Assignment not found.");
      return;
    }

    let payload: any = { taskId, personId, status };
    if (status === 'submitted_on_time' || status === 'submitted_late') {
      payload.userSubmissionDate = new Date().toISOString();
      if (status === 'submitted_late' && userDelayReason) {
        payload.userDelayReason = userDelayReason;
      }
    }

    try {
      const updatedAssignment = await fetchData<Assignment>('/assignments', { 
        method: 'PATCH', 
        body: JSON.stringify(payload),
      });

      if (updatedAssignment && updatedAssignment.taskId) {
        setAssignments(prev => prev.map(a => a.taskId === taskId && a.personId === personId ? updatedAssignment : a));
        setSuccessMessage(`Assignment "${updatedAssignment.taskTitle}" status updated to ${status.replace(/_/g, ' ')}.`);

        const taskTitle = updatedAssignment.taskTitle;
        const assignedUser = users.find(u => u.id === personId);

        if (currentUser.role === 'admin' && status === 'completed_admin_approved' && assignedUser) {
           await addAdminLogEntry(`Admin ${currentUser.displayName} approved task completion for "${taskTitle}" by ${assignedUser.displayName}.`);
        } else if (currentUser.role === 'user' && assignedUser) {
           await addAdminLogEntry(`User ${currentUser.displayName} updated status of task "${taskTitle}" to ${status.replace(/_/g, ' ')}.`);
        }

        setAssignmentToSubmitDelayReason(null); 
        setUserSubmissionDelayReason('');

      } else {
        setError("Failed to update assignment status. API response was invalid.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to update assignment status.");
    }
  };


  const handleFetchAssignmentSuggestion = async (taskId: string) => {
    const task = tasks.find(t => t.id === taskId);
    if (!task) {
      setError("Task not found for suggestion.");
      return;
    }
    setIsLoadingSuggestion(true);
    setAssignmentSuggestion(null);
    setError(null);

    const suggestion = await getAssignmentSuggestion(task, users, programs, assignments);
    setAssignmentSuggestion(suggestion);
    setIsLoadingSuggestion(false);
    if (!suggestion?.suggestedPersonName) {
      setInfoMessage(suggestion?.justification || "AI could not suggest a suitable person, or no one is available.");
    } else {
      setInfoMessage(`AI Suggestion: ${suggestion.suggestedPersonName}. Justification: ${suggestion.justification}`);
    }
  };

  const handleCompleteUserTour = (completed: boolean) => {
    setShowUserTour(false);
    if (currentUser) {
      localStorage.setItem(`hasCompletedUserTour_${currentUser.id}`, 'true');
      if (completed) {
        setSuccessMessage("Tour completed! We hope you find the app easy to use.");
      } else {
        setInfoMessage("Tour skipped. You can always refer to help sections or ask an admin if you have questions.");
      }
    }
  };


  const handleAddAdminLogWithImage = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!currentUser || currentUser.role !== 'admin' || (!adminLogText.trim() && !adminLogImageFile)) {
            setError("Admin log text or an image is required.");
            return;
        }
        setIsSubmittingLog(true);
        clearMessages();

        let imageUrl: string | undefined = undefined;
        if (adminLogImageFile) {
            console.warn("Image upload simulation: In a real app, upload image and get URL here.");
            imageUrl = `https://via.placeholder.com/150/0000FF/808080?Text=Preview+${adminLogImageFile.name.substring(0,10)}`; // Placeholder
        }

        try {
            await addAdminLogEntry(adminLogText.trim() || `Image: ${adminLogImageFile?.name || 'N/A'}`, imageUrl);
            setSuccessMessage("Admin log entry added.");
            setAdminLogText('');
            setAdminLogImageFile(null);
        } catch (error: any) {
            setError("Failed to add admin log: " + error.message);
        } finally {
            setIsSubmittingLog(false);
        }
    };

    const refreshAdminDashboardData = useCallback(async () => {
        if (!currentUser || currentUser.role !== 'admin') {
          setInfoMessage("Only admins can refresh dashboard data.");
          return;
        }
        clearMessages();
        setIsRefreshingDashboard(true);
        try {
          const [loadedUsers, loadedPendingUsers, loadedAdminLogsRefresh] = await Promise.all([
            fetchData<User[]>('/users', {}, []),
            fetchData<PendingUser[]>('/pending-users', {}, []),
            fetchData<AdminLogEntry[]>('/admin-logs', {}, [])
          ]);

          if (loadedUsers) setUsers(loadedUsers);
          if (loadedPendingUsers) setPendingUsers(loadedPendingUsers);
          
          if (loadedAdminLogsRefresh) {
            setAdminLogs(loadedAdminLogsRefresh);
            console.log('[App.tsx] Refreshed Admin Logs:', loadedAdminLogsRefresh);
          } else {
            setAdminLogs([]); 
            console.log('[App.tsx] Refreshed Admin Logs: No logs returned or fetch failed, set to empty.');
          }
          setSuccessMessage("Dashboard data refreshed.");
        } catch (err: any) {
          console.error("Error refreshing dashboard data:", err);
          setError("Failed to refresh dashboard data: " + err.message);
        } finally {
          setIsRefreshingDashboard(false);
        }
      }, [currentUser, clearMessages]);


  if (isLoadingAppData) {
    return <div className="flex items-center justify-center min-h-screen bg-background"><LoadingSpinner /></div>;
  }

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


  if (!currentUser) {
    const AuthViewComponent = () => (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
        <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-md">
           {error && <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
          {successMessage && <div className="mb-4 p-3 bg-green-100 border border-green-400 text-green-700 rounded-md shadow-lg" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
          {infoMessage && <div className="mb-4 p-3 bg-blue-100 border border-blue-400 text-blue-700 rounded-md shadow-lg" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}

          {authView === 'login' ? (
            <>
              <h2 className="text-3xl font-bold text-textlight mb-6 text-center">Login</h2>
              <form onSubmit={handleLogin} className="space-y-5">
                <div>
                  <label htmlFor="loginEmail" className="block text-sm font-medium text-textlight">Email Address</label>
                  <AuthFormInput id="loginEmail" aria-label="Login Email" type="email" value={newLoginForm.email} onChange={(e) => setNewLoginForm({ ...newLoginForm, email: e.target.value })} required placeholder="you@example.com" />
                </div>
                <div>
                  <label htmlFor="loginPassword" className="block text-sm font-medium text-textlight">Password</label>
                  <AuthFormInput id="loginPassword" aria-label="Login Password" type="password" value={newLoginForm.password} onChange={(e) => setNewLoginForm({ ...newLoginForm, password: e.target.value })} required placeholder="Enter your password" />
                </div>
                <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm">Sign In</button>
              </form>
              <p className="text-center text-sm text-textlight mt-6">
                Need an account?{' '}
                <button type="button" onClick={() => { setAuthView('register'); clearMessages(); }} className="font-medium text-authLink hover:underline">Register here</button>
                 <span className="mx-1 text-neutral">|</span>
                <button type="button" onClick={() => navigateTo(Page.PreRegistration)} className="font-medium text-authLink hover:underline">Invited? Pre-register</button>
              </p>
            </>
          ) : ( 
            <>
              <h2 className="text-3xl font-bold text-textlight mb-6 text-center">Create Account</h2>
              <form onSubmit={handleNewRegistration} className="space-y-4">
                <div>
                  <label htmlFor="regName" className="block text-sm font-medium text-textlight">Full Name</label>
                  <AuthFormInput id="regName" aria-label="Registration Full Name" type="text" value={newRegistrationForm.name} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, name: e.target.value })} required placeholder="Jane Doe"/>
                </div>
                <div>
                  <label htmlFor="regEmail" className="block text-sm font-medium text-textlight">Email Address</label>
                  <AuthFormInput id="regEmail" aria-label="Registration Email" type="email" value={newRegistrationForm.email} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, email: e.target.value })} required placeholder="you@example.com" />
                </div>
                 <div>
                  <label htmlFor="regUniqueId" className="block text-sm font-medium text-textlight">System ID / Username</label>
                  <AuthFormInput id="regUniqueId" aria-label="Registration System ID" type="text" value={newRegistrationForm.uniqueId} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, uniqueId: e.target.value })} required placeholder="e.g., jdoe23" />
                </div>
                <div>
                  <label htmlFor="regPassword" className="block text-sm font-medium text-textlight">Password</label>
                  <AuthFormInput id="regPassword" aria-label="Registration Password" type="password" value={newRegistrationForm.password} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, password: e.target.value })} required placeholder="Create a password" aria-describedby="passwordHelpRegister" />
                   <p id="passwordHelpRegister" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
                </div>
                <div>
                  <label htmlFor="regConfirmPassword" className="block text-sm font-medium text-textlight">Confirm Password</label>
                  <AuthFormInput id="regConfirmPassword" aria-label="Registration Confirm Password" type="password" value={newRegistrationForm.confirmPassword} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, confirmPassword: e.target.value })} required placeholder="Confirm your password" />
                </div>
                <div>
                    <label htmlFor="regRole" className="block text-sm font-medium text-textlight">Registering as</label>
                    <AuthFormSelect id="regRole" aria-label="Registration Role" value={newRegistrationForm.role} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, role: e.target.value as Role })}>
                        <option value="user">User (General)</option>
                        <option value="admin">Administrator (New Site/Company)</option>
                    </AuthFormSelect>
                </div>
                {newRegistrationForm.role === 'admin' && (
                    <div>
                        <label htmlFor="regCompanyName" className="block text-sm font-medium text-textlight">Company Name</label>
                        <AuthFormInput id="regCompanyName" aria-label="Registration Company Name" type="text" value={newRegistrationForm.companyName} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, companyName: e.target.value })} required={newRegistrationForm.role === 'admin'} placeholder="Your Company LLC" />
                    </div>
                )}
                {newRegistrationForm.role === 'user' && (
                     <div>
                        <label htmlFor="regPosition" className="block text-sm font-medium text-textlight">Your Position/Role (Optional)</label>
                        <AuthFormInput id="regPosition" aria-label="Registration Position" type="text" value={newRegistrationForm.position} onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, position: e.target.value })} placeholder="e.g., Software Engineer, Volunteer Coordinator" />
                    </div>
                )}
                <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm">Register</button>
              </form>
              <p className="text-center text-sm text-textlight mt-6">
                Already have an account?{' '}
                <button type="button" onClick={() => { setAuthView('login'); clearMessages(); }} className="font-medium text-authLink hover:underline">Sign in</button>
              </p>
            </>
          )}
        </div>
         <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by AI.</p>
        </footer>
      </div>
    );
    return <AuthViewComponent />;
  }

  return (
    <div className="flex h-screen bg-background">
      <TopNavbar currentUser={currentUser} currentPage={currentPage} navigateTo={navigateTo} handleLogout={handleLogout} />
      <main className="flex-1 p-6 overflow-y-auto mt-16 main-app-scope"> 
        {error && <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-4 text-sm font-bold text-red-800 hover:text-red-900">Dismiss</button></div>}
        {successMessage && <div className="mb-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded-md shadow-lg" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-4 text-sm font-bold text-green-800 hover:text-green-900">Dismiss</button></div>}
        {infoMessage && <div className="mb-4 p-4 bg-blue-100 border border-blue-400 text-blue-700 rounded-md shadow-lg" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-4 text-sm font-bold text-blue-800 hover:text-blue-900">Dismiss</button></div>}

        {currentPage === Page.Dashboard && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h2 className="text-3xl font-semibold text-primary mb-6">Admin Dashboard</h2>
                <button
                    onClick={refreshAdminDashboardData}
                    className="btn-secondary text-sm px-4 py-2"
                    disabled={isRefreshingDashboard}
                    aria-label="Refresh dashboard data"
                >
                    {isRefreshingDashboard ? <LoadingSpinner/> : 'Refresh Data'}
                </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <div className="bg-surface p-6 rounded-lg shadow-lg">
                <h3 className="text-xl font-medium text-textlight mb-2">Users</h3>
                <p className="text-3xl font-bold text-primary">{users.length}</p>
                <p className="text-sm text-neutral">Total registered users</p>
              </div>
              <div className="bg-surface p-6 rounded-lg shadow-lg">
                <h3 className="text-xl font-medium text-textlight mb-2">Pending Approvals</h3>
                <p className="text-3xl font-bold text-primary">{pendingUsers.length}</p>
                <p className="text-sm text-neutral">Users awaiting approval</p>
              </div>
              <div className="bg-surface p-6 rounded-lg shadow-lg">
                <h3 className="text-xl font-medium text-textlight mb-2">Tasks</h3>
                <p className="text-3xl font-bold text-primary">{tasks.length}</p>
                <p className="text-sm text-neutral">Total available tasks</p>
              </div>
              <div className="bg-surface p-6 rounded-lg shadow-lg">
                <h3 className="text-xl font-medium text-textlight mb-2">Programs</h3>
                <p className="text-3xl font-bold text-primary">{programs.length}</p>
                <p className="text-sm text-neutral">Managed programs</p>
              </div>
               <div className="bg-surface p-6 rounded-lg shadow-lg">
                <h3 className="text-xl font-medium text-textlight mb-2">Active Assignments</h3>
                <p className="text-3xl font-bold text-primary">{assignments.filter(a => ['pending_acceptance', 'accepted_by_user'].includes(a.status)).length}</p>
                <p className="text-sm text-neutral">Tasks currently in progress or awaiting acceptance</p>
              </div>
            </div>
            <div className="bg-surface p-6 rounded-lg shadow-lg mt-6">
                <h3 className="text-xl font-medium text-textlight mb-4">Admin Activity Log</h3>
                <form onSubmit={handleAddAdminLogWithImage} className="mb-4 space-y-3">
                    <FormTextarea
                        id="adminLogText"
                        label="New Log Entry (Optional if uploading image)"
                        value={adminLogText}
                        onChange={(e) => setAdminLogText(e.target.value)}
                        placeholder="Describe admin action or event..."
                    />
                    <div>
                        <label htmlFor="adminLogImage" className="block text-sm font-medium text-textlight">Upload Image (Optional)</label>
                        <input
                            id="adminLogImage"
                            type="file"
                            accept="image/*"
                            onChange={(e) => setAdminLogImageFile(e.target.files ? e.target.files[0] : null)}
                            className="mt-1 block w-full text-sm text-neutral file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-primary file:text-white hover:file:bg-primary-dark"
                        />
                         {adminLogImageFile && <p className="text-xs text-neutral mt-1">Selected: {adminLogImageFile.name}</p>}
                    </div>
                    <button type="submit" className="btn-primary" disabled={isSubmittingLog}>
                        {isSubmittingLog ? <LoadingSpinner/> : "Add Log Entry"}
                    </button>
                </form>
                <div className="max-h-96 overflow-y-auto space-y-3">
                    {adminLogs.length > 0 ? adminLogs.map(log => (
                        <div key={log.id} className="p-3 bg-bground rounded-md shadow">
                            <p className="text-sm text-textlight"><strong className="font-medium">{log.adminDisplayName}</strong>: {log.logText}</p>
                            {log.imagePreviewUrl && (
                                <img src={log.imagePreviewUrl} alt="Admin log image" className="mt-2 rounded max-h-40"/>
                            )}
                            <p className="text-xs text-neutral mt-1">{new Date(log.timestamp).toLocaleString()}</p>
                        </div>
                    )) : <p className="text-neutral">No admin activities logged yet.</p>}
                </div>
            </div>
          </div>
        )}

        {currentPage === Page.UserProfile && (
          <div className="max-w-2xl mx-auto bg-surface p-8 rounded-lg shadow-xl">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Profile</h2>
            <form onSubmit={handleUpdateProfile} className="space-y-6">
              <FormInput label="System ID / Username" id="profileUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({ ...userForm, uniqueId: e.target.value })} required />
              <FormInput label="Display Name" id="profileDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({ ...userForm, displayName: e.target.value })} required />
              <FormInput label="Email Address (cannot be changed)" id="profileEmail" type="email" value={userForm.email} readOnly disabled className="bg-gray-100 cursor-not-allowed" />
              <FormInput label="Position / Role Title" id="profilePosition" type="text" value={userForm.position} onChange={e => setUserForm({ ...userForm, position: e.target.value })} required />
              <FormTextarea label="My Interests (helps with task matching)" id="profileUserInterests" value={userForm.userInterests} onChange={e => setUserForm({ ...userForm, userInterests: e.target.value })} />
              <FormInput label="Phone Number (Optional)" id="profilePhone" type="tel" value={userForm.phone} onChange={e => setUserForm({ ...userForm, phone: e.target.value })} />
              <FormSelect label="Notification Preference" id="profileNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({ ...userForm, notificationPreference: e.target.value as NotificationPreference })}>
                <option value="email">Email</option>
                <option value="phone">Phone (if number provided - SMS not implemented)</option>
                <option value="none">None</option>
              </FormSelect>
              <hr className="my-4 border-neutral"/>
              <p className="text-sm text-textlight">Update Password (leave blank to keep current password):</p>
              <FormInput label="New Password" id="profilePassword" type="password" value={userForm.password || ''} onChange={e => setUserForm({...userForm, password: e.target.value })} aria-describedby="passwordHelpProfile" />
               <p id="passwordHelpProfile" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
              <FormInput label="Confirm New Password" id="profileConfirmPassword" type="password" value={userForm.confirmPassword || ''} onChange={e => setUserForm({ ...userForm, confirmPassword: e.target.value })} />
              <button type="submit" className="btn-primary w-full py-2.5">Update Profile</button>
            </form>
          </div>
        )}

        {currentPage === Page.UserManagement && currentUser.role === 'admin' && (
          <div className="space-y-8">
            <div>
              <h2 className="text-3xl font-semibold text-primary mb-6">User Management</h2>
              <div className="flex justify-between items-center mb-4">
                <button onClick={() => { setUserForm(initialUserFormData); setEditingUserId(null); navigateTo(Page.UserManagement, {action: 'create'});}} className="btn-primary inline-flex items-center">
                  <PlusCircleIcon className="w-5 h-5 mr-2"/> Create New User
                </button>
                 <button onClick={handleGeneratePreRegistrationLink} className="btn-secondary inline-flex items-center">
                    <KeyIcon className="w-5 h-5 mr-2" /> Generate Pre-Registration Link
                </button>
              </div>
              {generatedLink && (
                  <div className="mb-4 p-3 bg-blue-100 border border-blue-400 text-blue-700 rounded-md shadow flex justify-between items-center">
                      <div>
                        <p className="font-medium">Generated Link (Share with user):</p>
                        <input type="text" readOnly value={generatedLink} className="w-full mt-1 p-2 border border-blue-300 rounded bg-blue-50 text-sm" />
                      </div>
                      <button onClick={() => copyToClipboard(generatedLink)} className="ml-4 btn-neutral text-sm px-3 py-1.5">Copy</button>
                  </div>
              )}

              {new URLSearchParams(window.location.hash.split('?')[1]).get('action') === 'create' && !editingUserId && (
                 <div className="bg-surface p-6 rounded-lg shadow-xl mt-6">
                    <h3 className="text-xl font-medium text-textlight mb-4">Create New User Form</h3>
                    <form onSubmit={handleCreateUserByAdmin} className="space-y-4">
                        <FormInput label="Email" id="adminCreateEmail" type="email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required />
                        <FormInput label="System ID / Username" id="adminCreateUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required />
                        <FormInput label="Display Name" id="adminCreateDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
                        <FormInput label="Position" id="adminCreatePosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                        <FormSelect label="Role" id="adminCreateRole" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value as Role})}>
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </FormSelect>
                        <FormTextarea label="User Interests (Optional)" id="adminCreateUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                        <FormInput label="Phone (Optional)" id="adminCreatePhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                        <FormSelect label="Notification Preference" id="adminCreateNotifPref" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                            <option value="email">Email</option><option value="phone">Phone</option><option value="none">None</option>
                        </FormSelect>
                        <FormInput label="Password" id="adminCreatePassword" type="password" value={userForm.password || ''} onChange={e => setUserForm({...userForm, password: e.target.value})} required aria-describedby="passwordHelpAdminCreate" />
                        <p id="passwordHelpAdminCreate" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
                        <FormInput label="Confirm Password" id="adminCreateConfirmPassword" type="password" value={userForm.confirmPassword || ''} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} required />
                        <div className="flex space-x-3">
                           <button type="submit" className="btn-primary">Create User</button>
                           <button type="button" onClick={() => navigateTo(Page.UserManagement)} className="btn-neutral">Cancel</button>
                        </div>
                    </form>
                </div>
              )}
               {editingUserId && (
                 <div className="bg-surface p-6 rounded-lg shadow-xl mt-6">
                    <h3 className="text-xl font-medium text-textlight mb-4">Edit User: {users.find(u=>u.id === editingUserId)?.displayName}</h3>
                     <form onSubmit={handleAdminUpdateUser} className="space-y-4">
                        <FormInput label="Email" id="adminEditEmail" type="email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required />
                        <FormInput label="System ID / Username" id="adminEditUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required />
                        <FormInput label="Display Name" id="adminEditDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
                        <FormInput label="Position" id="adminEditPosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                        <FormSelect label="Role" id="adminEditRole" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value as Role})}>
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </FormSelect>
                        <FormTextarea label="User Interests (Optional)" id="adminEditUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                        <FormInput label="Phone (Optional)" id="adminEditPhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                        <FormSelect label="Notification Preference" id="adminEditNotifPref" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                            <option value="email">Email</option><option value="phone">Phone</option><option value="none">None</option>
                        </FormSelect>
                        <FormInput label="New Password (Optional)" id="adminEditPassword" type="password" value={userForm.password || ''} onChange={e => setUserForm({...userForm, password: e.target.value})} aria-describedby="passwordHelpAdminEdit" />
                        <p id="passwordHelpAdminEdit" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
                        <FormInput label="Confirm New Password" id="adminEditConfirmPassword" type="password" value={userForm.confirmPassword || ''} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} />
                        <div className="flex space-x-3">
                           <button type="submit" className="btn-primary">Save Changes</button>
                           <button type="button" onClick={() => { setEditingUserId(null); navigateTo(Page.UserManagement);}} className="btn-neutral">Cancel</button>
                        </div>
                    </form>
                </div>
              )}
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-xl overflow-x-auto">
              <h3 className="text-xl font-medium text-textlight mb-4">Registered Users</h3>
               <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Name</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">System ID</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Email</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Role</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Position</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-surface divide-y divide-gray-200 text-sm text-textlight">
                    {users.map(user => (
                      <tr key={user.id}>
                        <td className="px-6 py-4 whitespace-nowrap">{user.displayName}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{user.uniqueId}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{user.email}</td>
                        <td className="px-6 py-4 whitespace-nowrap capitalize">{user.role}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{user.position}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                          <button onClick={() => { setEditingUserId(user.id); setUserForm({...user, password:'', confirmPassword:''}); navigateTo(Page.UserManagement, {action: 'edit', userId: user.id});}} className="text-primary hover:text-primary-dark">Edit</button>
                          {currentUser.id !== user.id && user.role !== 'admin' && ( 
                             <button onClick={() => handleDeleteUser(user.id)} className="text-danger hover:text-red-700">Delete</button>
                          )}
                           {currentUser.id !== user.id && user.role === 'admin' && users.filter(u=>u.role==='admin').length > 1 && ( 
                             <button onClick={() => handleDeleteUser(user.id)} className="text-danger hover:text-red-700">Delete</button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
            </div>

            {approvingPendingUser && (
                <div className="bg-surface p-6 rounded-lg shadow-xl mt-6">
                    <h3 className="text-xl font-medium text-textlight mb-4">Review & Approve: {approvingPendingUser.displayName} ({approvingPendingUser.email})</h3>
                    <form onSubmit={(e) => { e.preventDefault(); handleApprovePendingUser(); }} className="space-y-4">
                        <p className="text-sm text-neutral">System ID: {approvingPendingUser.uniqueId}</p>
                        <FormInput label="Position (Required)" id="approvePosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                        <FormSelect label="Assign Role (Required)" id="approveRole" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value as Role})} required>
                             <option value="user">User</option>
                             <option value="admin">Admin (Use with caution)</option>
                        </FormSelect>
                        <FormTextarea label="User Interests (Optional)" id="approveUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                        <FormInput label="Phone (Optional)" id="approvePhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                        <FormSelect label="Notification Preference" id="approveNotifPref" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                            <option value="email">Email</option><option value="phone">Phone</option><option value="none">None</option>
                        </FormSelect>
                         <div className="flex space-x-3">
                           <button type="submit" className="btn-success">Approve User</button>
                           <button type="button" onClick={() => setApprovingPendingUser(null)} className="btn-neutral">Cancel</button>
                        </div>
                    </form>
                </div>
            )}
            <div className="bg-surface p-6 rounded-lg shadow-xl mt-8 overflow-x-auto">
              <h3 className="text-xl font-medium text-textlight mb-4">Pending User Registrations</h3>
              {pendingUsers.length > 0 ? (
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Display Name</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Email</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Desired System ID</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Submission Date</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Referring Admin</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-surface divide-y divide-gray-200 text-sm text-textlight">
                    {pendingUsers.map(pu => (
                      <tr key={pu.id}>
                        <td className="px-6 py-4 whitespace-nowrap">{pu.displayName}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{pu.email}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{pu.uniqueId}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{new Date(pu.submissionDate).toLocaleDateString()}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{users.find(u => u.id === pu.referringAdminId)?.displayName || 'N/A'}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                          <button onClick={() => { setApprovingPendingUser(pu); setUserForm({...initialUserFormData, email: pu.email, uniqueId: pu.uniqueId, displayName: pu.displayName, role: pu.role}); }} className="text-green-600 hover:text-green-800">Approve</button>
                          <button onClick={() => handleRejectPendingUser(pu.id)} className="text-danger hover:text-red-700">Reject</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <p className="text-neutral">No pending user registrations.</p>}
            </div>
          </div>
        )}

        {currentPage === Page.ManagePrograms && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">Manage Programs</h2>
            <div className="bg-surface p-6 rounded-lg shadow-xl">
              <h3 className="text-xl font-medium text-textlight mb-4">Create New Program</h3>
              <form onSubmit={handleCreateProgram} className="space-y-4">
                <FormInput label="Program Name" id="programName" value={programForm.name} onChange={e => setProgramForm({ ...programForm, name: e.target.value })} required />
                <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({ ...programForm, description: e.target.value })} required />
                <button type="submit" className="btn-primary">Create Program</button>
              </form>
            </div>
            <div className="bg-surface p-6 rounded-lg shadow-xl mt-6 overflow-x-auto">
              <h3 className="text-xl font-medium text-textlight mb-4">Existing Programs</h3>
              {programs.length > 0 ? (
                 <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Name</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Description</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="bg-surface divide-y divide-gray-200 text-sm text-textlight">
                        {programs.map(program => (
                            <tr key={program.id}>
                                <td className="px-6 py-4 whitespace-nowrap font-medium">{program.name}</td>
                                <td className="px-6 py-4 "><p className="w-96 truncate" title={program.description}>{program.description}</p></td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <button onClick={() => handleDeleteProgram(program.id)} className="text-danger hover:text-red-700 flex items-center text-sm">
                                        <TrashIcon className="w-4 h-4 mr-1"/> Delete
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                 </table>
              ) : <p className="text-neutral">No programs created yet.</p>}
            </div>
          </div>
        )}

        {currentPage === Page.ManageTasks && currentUser.role === 'admin' && (
           <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">Manage Tasks</h2>
            <div className="bg-surface p-6 rounded-lg shadow-xl">
              <h3 className="text-xl font-medium text-textlight mb-4">Create New Task</h3>
              <form onSubmit={handleCreateTask} className="space-y-4">
                <FormInput label="Task Title" id="taskTitle" value={taskForm.title} onChange={e => setTaskForm({ ...taskForm, title: e.target.value })} required />
                <FormTextarea label="Task Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({ ...taskForm, description: e.target.value })} required />
                <FormInput label="Required Skills (comma-separated)" id="taskSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({ ...taskForm, requiredSkills: e.target.value })} required />
                <FormSelect label="Related Program (Optional)" id="taskProgram" value={taskForm.programId} onChange={e => setTaskForm({ ...taskForm, programId: e.target.value })}>
                  <option value="">None</option>
                  {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </FormSelect>
                <FormInput label="Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline} onChange={e => setTaskForm({ ...taskForm, deadline: e.target.value })} />
                <button type="submit" className="btn-primary">Create Task</button>
              </form>
            </div>
             <div className="bg-surface p-6 rounded-lg shadow-xl mt-6 overflow-x-auto">
                <h3 className="text-xl font-medium text-textlight mb-4">Existing Tasks</h3>
                {tasks.length > 0 ? (
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Title</th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Program</th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Skills</th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Deadline</th>
                                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="bg-surface divide-y divide-gray-200 text-sm text-textlight">
                            {tasks.map(task => (
                                <tr key={task.id}>
                                    <td className="px-6 py-4 whitespace-nowrap font-medium">{task.title}</td>
                                    <td className="px-6 py-4 whitespace-nowrap">{task.programName || 'N/A'}</td>
                                    <td className="px-6 py-4 whitespace-nowrap">{task.requiredSkills}</td>
                                    <td className="px-6 py-4 whitespace-nowrap">{task.deadline ? new Date(task.deadline).toLocaleDateString() : 'N/A'}</td>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <button onClick={() => handleDeleteTask(task.id)} className="text-danger hover:text-red-700 flex items-center text-sm">
                                            <TrashIcon className="w-4 h-4 mr-1"/> Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : <p className="text-neutral">No tasks created yet.</p>}
             </div>
          </div>
        )}

        {currentPage === Page.AssignWork && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">Assign Work</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-surface p-6 rounded-lg shadow-xl space-y-4">
                    <h3 className="text-xl font-medium text-textlight">1. Select a Task</h3>
                    {tasks.length === 0 && <p className="text-neutral">No tasks available to assign. Create tasks in 'Manage Tasks'.</p>}
                    <ul className="max-h-96 overflow-y-auto space-y-2">
                    {tasks
                        .filter(task => !assignments.some(a => a.taskId === task.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user' || a.status === 'completed_admin_approved'))) 
                        .map(task => (
                        <li key={task.id}>
                            <button
                            onClick={() => { setSelectedTaskForAssignment(task.id); handleFetchAssignmentSuggestion(task.id); }}
                            className={`w-full text-left p-3 rounded-md border ${selectedTaskForAssignment === task.id ? 'bg-primary text-white border-primary-dark ring-2 ring-primary-focus' : 'bg-bground hover:bg-gray-200 border-neutral'}`}
                            >
                            <p className="font-semibold">{task.title}</p>
                            <p className="text-xs text-neutral-dark">{task.requiredSkills} - Deadline: {task.deadline ? new Date(task.deadline).toLocaleDateString() : 'N/A'}</p>
                            </button>
                        </li>
                    ))}
                    </ul>
                </div>

                {selectedTaskForAssignment && (
                    <div className="bg-surface p-6 rounded-lg shadow-xl space-y-4">
                        <h3 className="text-xl font-medium text-textlight">2. Assign Task: <span className="text-secondary">{tasks.find(t=>t.id ===selectedTaskForAssignment)?.title}</span></h3>
                        {isLoadingSuggestion && <LoadingSpinner />}
                        {assignmentSuggestion && assignmentSuggestion.suggestedPersonName && (
                            <div className="p-3 bg-blue-50 border border-blue-200 rounded-md">
                                <p className="text-sm text-blue-700"><LightBulbIcon className="w-5 h-5 inline mr-1 text-blue-500" /> <strong>AI Suggestion:</strong> {assignmentSuggestion.suggestedPersonName}</p>
                                <p className="text-xs text-blue-600 mt-1">Justification: {assignmentSuggestion.justification}</p>
                            </div>
                        )}
                         {assignmentSuggestion && !assignmentSuggestion.suggestedPersonName && assignmentSuggestion.justification && (
                            <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-md">
                                 <p className="text-sm text-yellow-700"><LightBulbIcon className="w-5 h-5 inline mr-1 text-yellow-500" /> <strong>AI Note:</strong> {assignmentSuggestion.justification}</p>
                            </div>
                        )}
                        <form onSubmit={(e) => {
                            const selectedPersonId = (e.target as HTMLFormElement).elements.namedItem('assignPerson') as HTMLSelectElement;
                            handleAssignTask(e, selectedTaskForAssignment, selectedPersonId.value);
                            }} className="space-y-4"
                        >
                            <FormSelect label="Select Person" id="assignPerson" name="assignPerson" defaultValue={users.find(u => u.displayName === assignmentSuggestion?.suggestedPersonName)?.id || ""}>
                            <option value="" disabled>-- Choose a person --</option>
                            {users
                                .filter(user => user.role === 'user' && !assignments.some(a => a.personId === user.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))) 
                                .map(user => (
                                <option key={user.id} value={user.id}>
                                    {user.displayName} ({user.position}) - Interests: {user.userInterests?.substring(0,30) || 'N/A'}...
                                </option>
                            ))}
                            </FormSelect>
                             <FormInput
                                label="Specific Deadline for this Assignment (Optional - overrides task default)"
                                id="specificDeadline"
                                type="date"
                                value={assignmentForm.specificDeadline || ''}
                                onChange={e => setAssignmentForm({...assignmentForm, specificDeadline: e.target.value})}
                            />
                            <button type="submit" className="btn-primary w-full"  disabled={users.filter(user => user.role === 'user' && !assignments.some(a => a.personId === user.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))).length === 0}>
                                Assign Task
                            </button>
                             {users.filter(user => user.role === 'user' && !assignments.some(a => a.personId === user.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))).length === 0 && (
                                <p className="text-sm text-warning">No users currently available for new assignments.</p>
                            )}
                        </form>
                    </div>
                )}
            </div>
          </div>
        )}

        {currentPage === Page.ViewAssignments && (
          <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">My Task Assignments</h2>
            {assignments.filter(a => currentUser.role === 'admin' || a.personId === currentUser.id).length === 0 && (
              <p className="text-neutral bg-surface p-4 rounded-md shadow">You currently have no tasks assigned to you. {currentUser.role === 'user' ? "Check 'Available Tasks' or wait for an admin to assign work." : "You can assign tasks from the 'Assign Work' page."}</p>
            )}
            <ul className="space-y-4">
              {assignments
                .filter(a => currentUser.role === 'admin' || a.personId === currentUser.id) 
                .sort((a,b) => new Date(b.deadline || 0).getTime() - new Date(a.deadline || 0).getTime()) 
                .map(assignment => {
                const taskDetails = tasks.find(t => t.id === assignment.taskId);
                const isUserAssignment = assignment.personId === currentUser.id;
                const canAdminApprove = currentUser.role === 'admin' && ['submitted_on_time', 'submitted_late'].includes(assignment.status);

                return (
                  <li key={`${assignment.taskId}-${assignment.personId}`} className={`bg-surface p-5 rounded-lg shadow-lg border-l-4
                    ${assignment.status === 'completed_admin_approved' ? 'border-green-500'
                      : assignment.status === 'declined_by_user' ? 'border-red-500'
                      : (assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') ? 'border-blue-500'
                      : assignment.status === 'accepted_by_user' ? 'border-yellow-500'
                      : 'border-gray-300'}`
                  }>
                    <div className="flex justify-between items-start">
                        <div>
                            <h3 className="text-xl font-semibold text-textlight">{assignment.taskTitle}</h3>
                            {currentUser.role === 'admin' && <p className="text-sm text-neutral">Assigned to: {assignment.personName}</p>}
                            <p className="text-sm text-neutral mt-1">Status: <span className="font-medium">{assignment.status.replace(/_/g, ' ')}</span></p>
                            {taskDetails?.description && <p className="text-sm text-textlight mt-1">Description: {taskDetails.description}</p>}
                            {taskDetails?.requiredSkills && <p className="text-sm text-textlight mt-1">Skills: {taskDetails.requiredSkills}</p>}
                            {assignment.deadline && <p className="text-sm text-neutral mt-1">Deadline: {new Date(assignment.deadline).toLocaleDateString()}</p>}
                            {assignment.justification && currentUser.role === 'admin' && <p className="text-xs text-neutral mt-1 italic">Assign Justification: {assignment.justification}</p>}
                            {assignment.userSubmissionDate && <p className="text-xs text-neutral mt-1">Submitted: {new Date(assignment.userSubmissionDate).toLocaleString()}</p>}
                            {assignment.userDelayReason && <p className="text-xs text-warning mt-1">Delay Reason: {assignment.userDelayReason}</p>}
                        </div>
                         <div className="text-sm text-neutral shrink-0 ml-4">
                            ID: <span className="font-mono text-xs">{assignment.taskId.slice(-6)}</span>
                        </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-gray-200 flex flex-wrap gap-2">
                      {isUserAssignment && assignment.status === 'pending_acceptance' && (
                        <>
                          <button onClick={() => handleUpdateAssignmentStatus(assignment.taskId, assignment.personId, 'accepted_by_user')} className="btn-success text-sm px-3 py-1.5">Accept Task</button>
                          <button onClick={() => handleUpdateAssignmentStatus(assignment.taskId, assignment.personId, 'declined_by_user')} className="btn-danger text-sm px-3 py-1.5">Decline Task</button>
                        </>
                      )}
                      {isUserAssignment && assignment.status === 'accepted_by_user' && (
                        <>
                          <button onClick={() => {
                              const isLate = assignment.deadline && new Date() > new Date(assignment.deadline);
                              if (isLate) {
                                  setAssignmentToSubmitDelayReason(`${assignment.taskId}-${assignment.personId}`);
                              } else {
                                  handleUpdateAssignmentStatus(assignment.taskId, assignment.personId, 'submitted_on_time');
                              }
                          }} className="btn-primary text-sm px-3 py-1.5">Mark as Completed / Submit</button>

                          {assignmentToSubmitDelayReason === `${assignment.taskId}-${assignment.personId}` && (
                            <div className="w-full mt-2 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
                                <FormTextarea label="Submitted Past Deadline - Reason for Delay:" id={`delayReason-${assignment.taskId}`} value={userSubmissionDelayReason} onChange={e => setUserSubmissionDelayReason(e.target.value)} required />
                                <button onClick={() => handleUpdateAssignmentStatus(assignment.taskId, assignment.personId, 'submitted_late', userSubmissionDelayReason)} className="btn-warning text-sm px-3 py-1.5 mt-2">Submit with Reason</button>
                            </div>
                          )}
                        </>
                      )}
                      {canAdminApprove && (
                        <button onClick={() => handleUpdateAssignmentStatus(assignment.taskId, assignment.personId, 'completed_admin_approved')} className="btn-success text-sm px-3 py-1.5">Approve Completion</button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {currentPage === Page.ViewTasks && (
            <div className="space-y-6">
                <h2 className="text-3xl font-semibold text-primary mb-6">Available Tasks</h2>
                {tasks.length === 0 && <p className="text-neutral bg-surface p-4 rounded-md shadow">No tasks currently listed. Admins can add tasks via 'Manage Tasks'.</p>}
                <ul className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {tasks.map(task => {
                    const currentAssignment = assignments.find(a => a.taskId === task.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user' || a.status === 'completed_admin_approved'));
                    return (
                    <li key={task.id} className={`bg-surface p-5 rounded-lg shadow-lg border-l-4 ${currentAssignment ? 'border-yellow-400 opacity-70' : 'border-blue-400'}`}>
                        <h3 className="text-xl font-semibold text-textlight">{task.title}</h3>
                        <p className="text-sm text-neutral mt-1">Program: {task.programName || 'N/A'}</p>
                        <p className="text-sm text-textlight mt-2">{task.description}</p>
                        <p className="text-sm text-textlight mt-2"><strong>Required Skills:</strong> {task.requiredSkills}</p>
                        {task.deadline && <p className="text-sm text-neutral mt-1">Default Deadline: {new Date(task.deadline).toLocaleDateString()}</p>}
                        {currentAssignment && (
                            <div className="mt-3 pt-3 border-t border-gray-200">
                                <p className="text-xs text-warning">
                                    Currently assigned to: {currentAssignment.personName} (Status: {currentAssignment.status.replace(/_/g, ' ')})
                                </p>
                            </div>
                        )}
                        {currentUser.role === 'admin' && !currentAssignment && (
                             <button
                                onClick={() => { setSelectedTaskForAssignment(task.id); handleFetchAssignmentSuggestion(task.id); navigateTo(Page.AssignWork);}}
                                className="mt-4 btn-secondary text-sm px-3 py-1.5"
                            >
                                Assign This Task
                            </button>
                        )}
                    </li>
                );})}
                </ul>
            </div>
        )}

        {showUserTour && currentUser && <UserTour user={currentUser} onClose={handleCompleteUserTour} />}
      </main>
    </div>
  );
};
