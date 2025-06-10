
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import * as emailService from './src/utils/emailService';
import { validatePassword } from './src/utils/validation';
// import * //as cloudDataService from './services/cloudDataService'; // Deactivated
import LoadingSpinner from './components/LoadingSpinner';
import { UsersIcon, ClipboardListIcon, LightBulbIcon, CheckCircleIcon, TrashIcon, PlusCircleIcon, KeyIcon, BriefcaseIcon, LogoutIcon, UserCircleIcon } from './components/Icons';
import PreRegistrationFormPage from './components/PreRegistrationFormPage';
import UserTour from './components/UserTour';

const API_BASE_URL = 'https://task-management-backend-17a5.onrender.com'; 

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
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        // Add any auth tokens here if needed, e.g., 'Authorization': `Bearer ${token}`
      },
      ...options,
    });

    if (response.status === 204) { // No Content
      return defaultReturnVal !== null ? defaultReturnVal : null; 
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
      // For 404 errors, return the default (often null or empty array) to prevent app crashes
      if (response.status === 404) {
        return defaultReturnVal;
      }
      throw new Error(errorData?.message || errorData?.error || responseText || `Request failed with status ${response.status}`);
    }
    
    // If response is OK (200-299 range) but not 204
    if (!responseText) {
      return defaultReturnVal !== null ? defaultReturnVal : null;
    }

    return JSON.parse(responseText) as T;
  } catch (error) {
    console.error(`Network or parsing error for ${endpoint}:`, error);
     if (error instanceof Error && error.message.includes("Failed to fetch")) {
        throw new Error(`Network error: Could not connect to the server at ${API_BASE_URL}. Please check your internet connection and the server status.`);
    }
    throw error; // Re-throw to be caught by calling function
  }
};


export const App = (): JSX.Element => {
  const [currentPage, _setCurrentPageInternal] = useState<Page>(Page.Login); 
  
  const [users, setUsers] = useState<User[]>([]);
  const [pendingUsers, setPendingUsers] = useState<PendingUser[]>([]);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [programs, setPrograms] = useState<Program[]>([]);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [adminLogs, setAdminLogs] = useState<AdminLogEntry[]>([]);
  const [isLoadingAppData, setIsLoadingAppData] = useState<boolean>(true);


  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [newLoginForm, setNewLoginForm] = useState({ email: '', password: '' });
  const [newRegistrationForm, setNewRegistrationForm] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'user' as Role,
  });
  
  const [adminRegistrationForm, setAdminRegistrationForm] = useState(initialAdminRegistrationState);
  const [preRegistrationForm, setPreRegistrationFormInternal] = useLocalStorage('task-assign-preRegistrationForm',initialPreRegistrationFormState);
  
  const initialUserFormData = { 
      email: '', uniqueId: '', password: '', confirmPassword: '', 
      displayName: '', position: '', userInterests: '', 
      phone: '', notificationPreference: 'none' as NotificationPreference,
      role: 'user' as Role, referringAdminId: ''
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

  useEffect(() => {
    const loadAllData = async () => {
      setIsLoadingAppData(true);
      try {
        // Attempt to get current user first (e.g., from a session cookie)
        // Backend should return 401 or similar if not logged in, fetchData should handle this.
        const sessionUser = await fetchData<User>('/users/current', {}, null);
        if (sessionUser) {
          setCurrentUser(sessionUser);
        }

        // Fetch all other data. If any of these fail with 404, fetchData returns empty array or null.
        const [
          loadedUsers,
          loadedPendingUsers,
          loadedTasks,
          loadedPrograms,
          loadedAssignments,
          loadedAdminLogs,
        ] = await Promise.all([
          fetchData<User[]>('/users', {}, []),
          fetchData<PendingUser[]>('/pending-users', {}, []),
          fetchData<Task[]>('/tasks', {}, []),
          fetchData<Program[]>('/programs', {}, []),
          fetchData<Assignment[]>('/assignments', {}, []),
          fetchData<AdminLogEntry[]>('/admin-logs', {}, []),
        ]);

        setUsers(loadedUsers || []);
        setPendingUsers(loadedPendingUsers || []);
        setTasks(loadedTasks || []);
        setPrograms(loadedPrograms || []);
        setAssignments(loadedAssignments || []);
        setAdminLogs(loadedAdminLogs || []);
        
        // Update newRegistrationForm.role if this is the first load and no users exist
        if ((loadedUsers || []).length === 0) {
            setNewRegistrationForm(prev => ({ ...prev, role: 'admin' }));
        } else {
            setNewRegistrationForm(prev => ({ ...prev, role: 'user' }));
        }
        console.log("Initial data fetched from backend.");

      } catch (err: any) {
        console.error("Critical error during initial data load from backend:", err);
        setError("Failed to load initial application data from the server. Error: " + err.message + ". Please ensure the backend is running and accessible.");
         // Set empty arrays for data if critical load fails to prevent further errors
        setUsers([]);
        setPendingUsers([]);
        setTasks([]);
        setPrograms([]);
        setAssignments([]);
        setAdminLogs([]);
      } finally {
        setIsLoadingAppData(false);
      }
    };
    loadAllData();
  }, []);


  // Wrapper for setPreRegistrationForm to persist to localStorage
  const setPreRegistrationForm = (value: React.SetStateAction<typeof initialPreRegistrationFormState>) => {
    setPreRegistrationFormInternal(value);
  };

  const navigateTo = useCallback((page: Page, params?: Record<string, string>) => { let hash = `#${page}`; if (params && Object.keys(params).length > 0) { hash += `?${new URLSearchParams(params).toString()}`; } if (window.location.hash !== hash) { window.location.hash = hash; } else { _setCurrentPageInternal(page); /* Ensure internal state updates if hash is same */ } }, []);

  useEffect(() => {
    if (isLoadingAppData) return; 

    const processHash = () => {
      clearMessages();
      const hash = window.location.hash.substring(1);
      const [pagePath, paramsString] = hash.split('?');
      const params = new URLSearchParams(paramsString || '');
      const targetPageFromHashPath = pagePath.toUpperCase() as Page | string;

      if (targetPageFromHashPath === Page.PreRegistration) {
        const refAdminIdFromHash = params.get('refAdminId');
        if (refAdminIdFromHash) {
          // We might not have all users loaded yet to find admin display name,
          // Backend could provide this if link was opaque, or we just show ID.
          const adminUser = users.find(u => u.id === refAdminIdFromHash && u.role === 'admin');
          setPreRegistrationForm(prev => ({
            ...initialPreRegistrationFormState, 
            referringAdminId: refAdminIdFromHash,
            referringAdminDisplayName: adminUser ? adminUser.displayName : `Admin ID: ${refAdminIdFromHash}`,
            isReferralLinkValid: true 
          }));
        } else {
          setPreRegistrationForm(prev => ({ ...initialPreRegistrationFormState, isReferralLinkValid: false }));
          setError("Pre-registration link is invalid or missing administrator reference.");
        }
        _setCurrentPageInternal(Page.PreRegistration);
        return; 
      }

      if (!currentUser) {
        _setCurrentPageInternal(Page.Login);
        if (targetPageFromHashPath && targetPageFromHashPath !== Page.Login.toUpperCase()) {
           if(window.location.hash !== `#${Page.Login}`) navigateTo(Page.Login);
        }
        return;
      }

      const defaultPageDetermination = currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
      let newPage = (targetPageFromHashPath || defaultPageDetermination) as Page;

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
            // Check currentPage again because it might have changed due to async navigation
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
        role: currentUser.role,
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

// Registration Handler
const handleNewRegistration = async (e: React.FormEvent) => {
  e.preventDefault();
  clearMessages();

  const { name, email, password, confirmPassword, role: formRole } = newRegistrationForm;

  if (!name.trim() || !email.trim() || !password.trim() || !confirmPassword.trim()) {
    setError("All fields are required.");
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

  if (users.some(u => u.email === email) || pendingUsers.some(pu => pu.email === email)) {
    setError("This email is already registered or pending approval.");
    return;
  }

  const actualRoleToRegister = users.length === 0 ? 'admin' : formRole;

  if (actualRoleToRegister === 'admin' && users.length === 0) {
    // Direct Admin Creation & Auto-Login
    const newAdminUserData: Omit<User, 'id'> = {
      displayName: name,
      email,
      password, // Backend will hash this password
      role: 'admin',
      uniqueId: email, // Default uniqueId to email for simplicity
      position: 'Administrator', // Default position
      userInterests: '',
      phone: '',
      notificationPreference: 'email',
    };

    try {
      const createdAdmin = await fetchData<User>('/users', {
        method: 'POST',
        body: JSON.stringify(newAdminUserData),
      });

      if (createdAdmin && createdAdmin.id) {
        setUsers(prev => [...prev, createdAdmin]);
        setCurrentUser(createdAdmin); 
        setSuccessMessage("Admin account registered successfully! Welcome to the dashboard.");
        // Reset form, ensuring role defaults to 'user' for subsequent registrations
        setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' }); 
        
        emailService.sendWelcomeRegistrationEmail(createdAdmin.email, createdAdmin.displayName, createdAdmin.role);
        
        navigateTo(Page.Dashboard);
      } else {
        setError("Failed to register admin. Server did not confirm creation or returned unexpected data.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to register admin. Please try again later.");
    }
  } else {
    // Existing Pending User Logic for general users or subsequent admins
    const newPendingUserData = {
      displayName: name,
      email,
      password, // Backend will hash this password
      role: actualRoleToRegister, 
      uniqueId: email, // Use email as uniqueId for pending users too for consistency
      submissionDate: new Date().toISOString(),
    };

    try {
      const response = await fetchData<{ success: boolean; user: (PendingUser & { _id?: string }) }>('/pending-users', {
        method: 'POST',
        body: JSON.stringify(newPendingUserData),
      });

      const createdPendingUser = response?.user;
      
      if (createdPendingUser) {
        // Normalize _id from backend to id for client-side state
        const normalizedId = createdPendingUser._id || createdPendingUser.id;
        if (normalizedId) {
          createdPendingUser.id = normalizedId; 

          setPendingUsers(prev => [...prev, createdPendingUser]);
          setSuccessMessage("Registration submitted successfully! Your account is pending administrator approval.");
          setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' });

          emailService.sendRegistrationPendingToUserEmail(createdPendingUser.email, createdPendingUser.displayName);

          const adminToNotify = getAdminToNotify();
          if (adminToNotify) {
            emailService.sendNewPendingRegistrationToAdminEmail(
              adminToNotify.email,
              adminToNotify.displayName,
              createdPendingUser.displayName,
              createdPendingUser.email
            );
          }
        } else {
           setError("Failed to submit registration. Server response was missing necessary ID information.");
        }
      } else {
        setError("Failed to submit registration. The server did not confirm creation or returned unexpected data.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to submit registration. Please try again later.");
    }
  }
};
  
// Pre-Registration Handler
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

  if (
    users.some(u => u.uniqueId === uniqueId || u.email === email) ||
    pendingUsers.some(pu => pu.uniqueId === uniqueId || pu.email === email)
  ) {
    setError("This System ID or Email is already registered or pending approval. Please choose a different one or contact an administrator.");
    return;
  }

  const newPendingUserData = {
    uniqueId,
    displayName,
    email,
    password,
    role: 'user' as Role, // Pre-registration is always for 'user' role initially
    referringAdminId: referringAdminId || undefined,
    submissionDate: new Date().toISOString(),
  };

  try {
    const response = await fetchData<{ success: boolean; user: (PendingUser & { _id?: string }) }>('/pending-users', {
      method: 'POST',
      body: JSON.stringify(newPendingUserData),
    });

    const createdPendingUser = response?.user;

    if (createdPendingUser) {
      const normalizedId = createdPendingUser._id || createdPendingUser.id;
      if (normalizedId) {
        createdPendingUser.id = normalizedId; // Ensure the 'id' field is populated

        setPendingUsers(prev => [...prev, createdPendingUser]);
        setSuccessMessage("Pre-registration submitted successfully! Your account is pending administrator approval. You will be notified via email.");
        setPreRegistrationForm(prev => ({
          ...initialPreRegistrationFormState,
          referringAdminId: prev.referringAdminId,
          referringAdminDisplayName: prev.referringAdminDisplayName,
          isReferralLinkValid: prev.isReferralLinkValid
        }));

        const referringAdmin = users.find(u => u.id === referringAdminId);
        emailService.sendPreRegistrationSubmittedToUserEmail(
          createdPendingUser.email,
          createdPendingUser.displayName,
          referringAdmin?.displayName || 'the administrator'
        );

        if (referringAdmin) {
          emailService.sendPreRegistrationNotificationToAdminEmail(
            referringAdmin.email,
            referringAdmin.displayName,
            createdPendingUser.displayName,
            createdPendingUser.uniqueId
          );
        } else {
          const generalAdmin = getAdminToNotify();
          if (generalAdmin) {
            emailService.sendPreRegistrationNotificationToAdminEmail(
              generalAdmin.email,
              generalAdmin.displayName,
              createdPendingUser.displayName,
              createdPendingUser.uniqueId
            );
          }
        }
      } else {
        setError("Failed to submit pre-registration. Server response was missing necessary ID information.");
      }
    } else {
      setError("Failed to submit pre-registration. Server did not confirm creation or returned unexpected data.");
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
      const loggedInUser = await fetchData<User>('/users/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (loggedInUser && loggedInUser.id) {
        setCurrentUser(loggedInUser);
        
        // Re-fetch all data after login for consistency
        setIsLoadingAppData(true);
        const [ updatedUsers, updatedPendingUsers, updatedTasks, updatedPrograms, updatedAssignments, updatedAdminLogs] = await Promise.all([
          fetchData<User[]>('/users', {}, []),
          fetchData<PendingUser[]>('/pending-users', {}, []),
          fetchData<Task[]>('/tasks', {}, []),
          fetchData<Program[]>('/programs', {}, []),
          fetchData<Assignment[]>('/assignments', {}, []),
          fetchData<AdminLogEntry[]>('/admin-logs', {}, []),
        ]);
        setUsers(updatedUsers || []);
        setPendingUsers(updatedPendingUsers || []);
        setTasks(updatedTasks || []);
        setPrograms(updatedPrograms || []);
        setAssignments(updatedAssignments || []);
        setAdminLogs(updatedAdminLogs || []);
        
        if ((updatedUsers || []).length === 0 && loggedInUser.role !== 'admin') {
             // This should ideally not happen if login implies user exists.
             // But as a safeguard for the role logic if it's the first user somehow.
            setNewRegistrationForm(prev => ({ ...prev, role: 'admin' }));
        } else if ((updatedUsers || []).length > 0 && newRegistrationForm.role === 'admin') {
            // If users exist, default registration role should be user
            setNewRegistrationForm(prev => ({ ...prev, role: 'user' }));
        }


        setIsLoadingAppData(false);

        setSuccessMessage(`Welcome back, ${loggedInUser.displayName}!`);
        setNewLoginForm({ email: '', password: '' }); 

        const targetPage = loggedInUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
        navigateTo(targetPage);
        
        if (loggedInUser.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${loggedInUser.id}`)) {
          setShowUserTour(true);
        }
      } else {
        setError("Invalid email or password, or login failed on server.");
      }
    } catch (err: any) {
      setError(err.message || "Login failed. Please check your credentials or server status.");
    }
  };

  const handleLogout = async () => {
    clearMessages();
    try {
      await fetchData('/users/logout', { method: 'POST' }); // Backend handles session invalidation
    } catch (err: any) {
      console.warn("Logout API call failed (user will be logged out client-side anyway):", err.message);
      // Potentially inform user if logout API fails but still proceed with client-side logout
    }
    setCurrentUser(null); 
    setUsers([]); 
    setPendingUsers([]);
    setTasks([]);
    setPrograms([]);
    setAssignments([]);
    setAdminLogs([]);
    setSuccessMessage("You have been logged out successfully.");
    // After logout, if no users are left (unlikely scenario, but for completeness)
    // or to reset registration form state to expect 'admin' if it's now empty.
    // However, it's safer to default to 'user' and let the initial load adjust if needed.
    setNewRegistrationForm(prev => ({ ...prev, role: users.length > 0 ? 'user' : 'admin' })); 
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
    
    // Client-side check (backend should also validate)
    if (users.some(u => u.uniqueId === uniqueId && u.id !== currentUser.id)) {
        setError("This System ID is already taken. Please choose another.");
        return;
    }
    
    const updatePayload: Partial<User> = {
      uniqueId,
      displayName,
      position,
      userInterests: userInterests || '',
      phone: phone || '',
      notificationPreference: notificationPreference || 'none',
    };
    
    if (password) { 
        if (password !== confirmPassword) {
            setError("New passwords do not match.");
            return;
        }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) {
            setError(passwordValidationResult.errors.join(" "));
            return;
        }
        updatePayload.password = password; // Send new password
    }
    
    try {
      const updatedUserFromServer = await fetchData<User>(`/users/${currentUser.id}`, {
        method: 'PUT',
        body: JSON.stringify(updatePayload),
      });

      if (updatedUserFromServer && updatedUserFromServer.id) {
        setUsers(users.map(u => u.id === currentUser.id ? updatedUserFromServer : u));
        setCurrentUser(updatedUserFromServer); 
        setSuccessMessage("Profile updated successfully!");
        setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' })); 
        await addAdminLogEntry(`User profile updated for ${updatedUserFromServer.displayName} (ID: ${updatedUserFromServer.uniqueId}).`);
      } else {
        setError("Failed to update profile. Server did not confirm update or returned unexpected data.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to update profile.");
    }
  };
  
  const handleAdminUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!editingUserId || !currentUser || currentUser.role !== 'admin') return;

    const { email, uniqueId, displayName, position, userInterests, phone, notificationPreference, role, password, confirmPassword } = userForm;
    
    if (!email.trim() || !uniqueId.trim() || !displayName.trim() || !position.trim()) {
        setError("Email, System ID, Display Name, and Position are required.");
        return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
        setError("Please enter a valid email address for the user.");
        return;
    }

    if (users.some(u => u.uniqueId === uniqueId && u.id !== editingUserId)) {
        setError("This System ID is already taken by another user. Please choose another.");
        return;
    }
    if (users.some(u => u.email === email && u.id !== editingUserId)) {
        setError("This Email is already taken by another user. Please choose another.");
        return;
    }
    
    const updatePayload: Partial<User> = {
      email,
      uniqueId,
      displayName,
      position,
      userInterests: userInterests || '',
      phone: phone || '',
      notificationPreference: notificationPreference || 'none',
      role,
    };

    if (password) { 
        if (password !== confirmPassword) {
            setError("New passwords do not match for the user being edited.");
            return;
        }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) {
            setError(`Password validation failed for user: ${passwordValidationResult.errors.join(" ")}`);
            return;
        }
        updatePayload.password = password; 
    }

    try {
      const updatedUserFromServer = await fetchData<User>(`/users/${editingUserId}`, {
        method: 'PUT',
        body: JSON.stringify(updatePayload),
      });

      if (updatedUserFromServer && updatedUserFromServer.id) {
        setUsers(users.map(u => u.id === editingUserId ? updatedUserFromServer : u));
        setSuccessMessage(`User ${updatedUserFromServer.displayName} updated successfully!`);
        setUserForm(initialUserFormData);
        setEditingUserId(null);
        navigateTo(Page.UserManagement);
        await addAdminLogEntry(`User profile updated by admin for ${updatedUserFromServer.displayName} (ID: ${updatedUserFromServer.uniqueId}). Role changed to ${updatedUserFromServer.role}.`);
      } else {
        setError("Failed to update user. Server did not confirm update or returned unexpected data.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to update user.");
    }
  };

  const handleApprovePendingUser = async (pendingUserIdToApprove: string) => {
    clearMessages();
    const userToApprove = pendingUsers.find(pu => pu.id === pendingUserIdToApprove);
    if (!userToApprove || !currentUser || currentUser.role !== 'admin') {
      setError("Cannot approve user. User not found or insufficient permissions.");
      return;
    }
    
    // Check for existing System ID (uniqueId) or Email in active users
    if (users.some(u => u.uniqueId === userToApprove.uniqueId)) {
        setError(`Cannot approve user ${userToApprove.displayName}: System ID "${userToApprove.uniqueId}" is already in use by an active user. The pending user may need to re-register with a different System ID or an admin can edit the pending user's details before approval (if that feature exists).`);
        return;
    }
    if (users.some(u => u.email === userToApprove.email)) {
        setError(`Cannot approve user ${userToApprove.displayName}: Email "${userToApprove.email}" is already in use by an active user.`);
        return;
    }

    try {
      // The backend's /pending-users/approve/:id endpoint should handle creating the User and deleting the PendingUser.
      // It should return the newly created User object.
      const approvedUser = await fetchData<User>(`/pending-users/approve/${userToApprove.id}`, {
        method: 'POST', // Or PUT, depending on backend API design for approval
        body: JSON.stringify({ 
            // Optionally send admin-editable fields if approval allows modification
            // For now, assume backend uses existing pending user data
            role: userToApprove.role, 
            position: userToApprove.role === 'admin' ? 'Administrator (Approved)' : 'User (Approved)', // Example default position
         }) 
      });

      if (approvedUser && approvedUser.id) {
        setUsers(prev => [...prev, approvedUser]);
        setPendingUsers(prev => prev.filter(pu => pu.id !== userToApprove.id));
        setSuccessMessage(`User ${approvedUser.displayName} approved and account activated!`);
        emailService.sendAccountActivatedByAdminEmail(approvedUser.email, approvedUser.displayName, currentUser.displayName);
        await addAdminLogEntry(`User ${approvedUser.displayName} (ID: ${approvedUser.uniqueId}) approved by ${currentUser.displayName}.`);
        
        // If the approved user was an admin, and they were the first user (though this scenario is now handled by direct creation),
        // ensure registration form role is set to user.
        if (users.length === 1 && approvedUser.role === 'admin') {
            setNewRegistrationForm(prev => ({ ...prev, role: 'user'}));
        }

      } else {
        setError("Failed to approve user. Server did not confirm approval or returned incomplete data.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to approve user.");
    }
    setApprovingPendingUser(null); // Clear modal state regardless of outcome
  };

  const handleRejectPendingUser = async (pendingUserIdToReject: string) => {
    clearMessages();
    const userToReject = pendingUsers.find(pu => pu.id === pendingUserIdToReject);
    if (!userToReject || !currentUser || currentUser.role !== 'admin') {
       setError("Cannot reject user. User not found or insufficient permissions.");
      return;
    }

    try {
      // Backend's /pending-users/:id endpoint with DELETE method should remove the pending user.
      // Expecting 204 No Content or a success message.
      await fetchData(`/pending-users/${userToReject.id}`, { method: 'DELETE' });
      
      setPendingUsers(prev => prev.filter(pu => pu.id !== userToReject.id));
      setSuccessMessage(`Registration for ${userToReject.displayName} (Email: ${userToReject.email}) has been rejected.`);
      // Optionally, send an email to the user about the rejection (consider privacy implications)
      // emailService.sendRegistrationRejectedEmail(userToReject.email, userToReject.displayName);
      await addAdminLogEntry(`Pending registration for ${userToReject.displayName} (Email: ${userToReject.email}) rejected by ${currentUser.displayName}.`);

    } catch (err:any) {
      setError(err.message || "Failed to reject pending user. Please try again.");
    }
  };


  const handleCreateProgram = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin') return;
    if (!programForm.name.trim()) {
        setError("Program name is required.");
        return;
    }

    try {
        const newProgramData = { name: programForm.name, description: programForm.description };
        const createdProgram = await fetchData<Program>('/programs', {
            method: 'POST',
            body: JSON.stringify(newProgramData),
        });

        if (createdProgram && createdProgram.id) {
            setPrograms(prev => [...prev, createdProgram]);
            setSuccessMessage(`Program "${createdProgram.name}" created successfully!`);
            setProgramForm({ name: '', description: '' });
            await addAdminLogEntry(`Program "${createdProgram.name}" created by ${currentUser.displayName}.`);
        } else {
            setError("Failed to create program. Server did not confirm creation.");
        }
    } catch (err: any) {
        setError(err.message || "Failed to create program.");
    }
  };

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin') return;
    if (!taskForm.title.trim() || !taskForm.description.trim() || !taskForm.requiredSkills.trim()) {
        setError("Task title, description, and required skills are required.");
        return;
    }
    
    const newTaskData: Omit<Task, 'id' | 'programName'> = { 
        title: taskForm.title, 
        description: taskForm.description, 
        requiredSkills: taskForm.requiredSkills,
        programId: taskForm.programId || undefined,
        deadline: taskForm.deadline || undefined,
    };

    try {
        const createdTask = await fetchData<Task>('/tasks', {
            method: 'POST',
            body: JSON.stringify(newTaskData),
        });

        if (createdTask && createdTask.id) {
            // If backend doesn't return programName, we might need to find it or adjust UI
            const programName = taskForm.programId ? programs.find(p => p.id === taskForm.programId)?.name : undefined;
            const taskWithProgramName = { ...createdTask, programName };

            setTasks(prev => [...prev, taskWithProgramName]);
            setSuccessMessage(`Task "${createdTask.title}" created successfully!`);
            setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' });
            await addAdminLogEntry(`Task "${createdTask.title}" created by ${currentUser.displayName}.`);
        } else {
             setError("Failed to create task. Server did not confirm creation.");
        }
    } catch (err: any) {
        setError(err.message || "Failed to create task.");
    }
  };

  const handleDeleteTask = async (taskId: string) => {
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin') return;

    const taskToDelete = tasks.find(t => t.id === taskId);
    if (!taskToDelete) {
        setError("Task not found for deletion.");
        return;
    }

    // Check if task is part of any active assignments
    const isActiveAssignment = assignments.some(a => a.taskId === taskId && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'));
    if (isActiveAssignment) {
        setError(`Task "${taskToDelete.title}" cannot be deleted as it is part of an active assignment. Please resolve assignments first.`);
        return;
    }

    if (window.confirm(`Are you sure you want to delete the task "${taskToDelete.title}"? This will also remove any non-active assignments related to it.`)) {
        try {
            await fetchData(`/tasks/${taskId}`, { method: 'DELETE' });
            setTasks(prev => prev.filter(t => t.id !== taskId));
            // Also remove any associated assignments (backend might do this via cascading delete)
            // For client-side consistency:
            setAssignments(prev => prev.filter(a => a.taskId !== taskId));
            setSuccessMessage(`Task "${taskToDelete.title}" and its non-active assignments deleted successfully.`);
            await addAdminLogEntry(`Task "${taskToDelete.title}" deleted by ${currentUser.displayName}.`);
        } catch (err: any) {
            setError(err.message || "Failed to delete task.");
        }
    }
  };

  const handleGetAssignmentSuggestion = async () => {
    clearMessages();
    if (!selectedTaskForAssignment) {
      setError("Please select a task first.");
      return;
    }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    if (!task) {
      setError("Selected task not found.");
      return;
    }

    setIsLoadingSuggestion(true);
    setAssignmentSuggestion(null); 
    try {
      const suggestion = await getAssignmentSuggestion(task, users, programs, assignments);
      setAssignmentSuggestion(suggestion);
      if (suggestion && suggestion.suggestedPersonName) {
        setInfoMessage(`AI Suggestion: ${suggestion.suggestedPersonName}. Justification: ${suggestion.justification}`);
      } else if (suggestion) {
         setInfoMessage(`AI: ${suggestion.justification}`); // e.g., "No suitable person found..."
      } else {
         setError("AI suggestion service returned an unexpected response.");
      }
    } catch (err: any) {
      setError(err.message || "Error getting AI suggestion.");
    } finally {
      setIsLoadingSuggestion(false);
    }
  };

  const handleCreateAssignment = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    clearMessages();
    const assignedPersonId = (e.currentTarget.elements.namedItem('assignedPerson') as HTMLSelectElement)?.value;
    const taskToAssignId = selectedTaskForAssignment;

    if (!currentUser || currentUser.role !== 'admin') return;
    if (!assignedPersonId || !taskToAssignId) {
      setError("Please select a task and a person to assign.");
      return;
    }

    const person = users.find(u => u.id === assignedPersonId);
    const task = tasks.find(t => t.id === taskToAssignId);

    if (!person || !task) {
      setError("Selected person or task not found.");
      return;
    }
    
    // Check if this user already has this task assigned (and not in a final state)
    const existingAssignment = assignments.find(a => 
        a.personId === person.id && 
        a.taskId === task.id &&
        a.status !== 'completed_admin_approved' &&
        a.status !== 'declined_by_user'
    );

    if (existingAssignment) {
        setError(`${person.displayName} is already assigned or has previously been assigned this task ("${task.title}") and it's not in a final state. Status: ${existingAssignment.status.replace(/_/g, ' ')}.`);
        return;
    }
    
    // Check if user already has any active task
    const userHasActiveTask = assignments.some(a => 
        a.personId === person.id && 
        (a.status === 'pending_acceptance' || a.status === 'accepted_by_user')
    );
    if (userHasActiveTask) {
        if (!window.confirm(`${person.displayName} already has an active task. Are you sure you want to assign another one?`)) {
            return;
        }
    }


    const newAssignmentData: Omit<Assignment, 'id'> = {
      taskId: task.id,
      personId: person.id,
      taskTitle: task.title,
      personName: person.displayName,
      justification: assignmentSuggestion?.suggestedPersonName === person.displayName ? assignmentSuggestion.justification : 'Manual assignment by admin.',
      status: 'pending_acceptance',
      deadline: assignmentForm.specificDeadline || task.deadline || undefined,
    };

    try {
        const createdAssignment = await fetchData<Assignment>('/assignments', {
            method: 'POST',
            body: JSON.stringify(newAssignmentData),
        });
        
        if (createdAssignment && createdAssignment.taskId) { // Assuming taskId is a good check for successful creation
            setAssignments(prev => [...prev, createdAssignment]);
            setSuccessMessage(`Task "${task.title}" assigned to ${person.displayName} successfully!`);
            setSelectedTaskForAssignment(null);
            setAssignmentSuggestion(null);
            setAssignmentForm({ specificDeadline: '' });
            emailService.sendTaskProposalEmail(person.email, person.displayName, task.title, currentUser.displayName, newAssignmentData.deadline);
            await addAdminLogEntry(`Task "${task.title}" assigned to ${person.displayName} by ${currentUser.displayName}.`);
        } else {
            setError("Failed to create assignment. Server did not confirm creation.");
        }
    } catch (err: any) {
        setError(err.message || "Failed to create assignment.");
    }
  };
  
const handleUserAcceptOrDeclineTask = async (assignmentId: string, action: 'accept' | 'decline') => {
    clearMessages();
    if (!currentUser) return;

    const assignment = assignments.find(a => a.taskId === assignmentId && a.personId === currentUser.id); // taskID is used as assignmentId in some contexts
    if (!assignment) {
      setError("Assignment not found or you are not the assignee.");
      return;
    }
    
    const assignmentToUpdate = assignments.find(a => a.taskId === assignment.taskId && a.personId === assignment.personId && a.status === 'pending_acceptance');
    if (!assignmentToUpdate) {
        setError("This task is no longer pending acceptance or assignment details are incorrect.");
        return;
    }

    const newStatus: AssignmentStatus = action === 'accept' ? 'accepted_by_user' : 'declined_by_user';
    
    try {
        // The backend should return the updated assignment object
        const updatedAssignment = await fetchData<Assignment>(`/assignments/${assignmentToUpdate.taskId}/person/${assignmentToUpdate.personId}/status`, { // Using a more specific endpoint if available
            method: 'PUT',
            body: JSON.stringify({ status: newStatus }),
        });

        if (updatedAssignment && updatedAssignment.status === newStatus) {
            setAssignments(prev => prev.map(a => (a.taskId === assignmentToUpdate.taskId && a.personId === assignmentToUpdate.personId) ? updatedAssignment : a));
            setSuccessMessage(`Task "${assignmentToUpdate.taskTitle}" has been ${action === 'accept' ? 'accepted' : 'declined'}.`);
            
            const adminToNotify = getAdminToNotify(currentUser.referringAdminId); // Notify referring admin or a general one
            if (adminToNotify) {
                emailService.sendTaskStatusUpdateToAdminEmail(
                    adminToNotify.email, 
                    adminToNotify.displayName, 
                    currentUser.displayName, 
                    assignmentToUpdate.taskTitle, 
                    action === 'accept' ? 'accepted' : 'declined'
                );
            }
            await addAdminLogEntry(`Task "${assignmentToUpdate.taskTitle}" ${action === 'accept' ? 'accepted' : 'declined'} by user ${currentUser.displayName}.`);

        } else {
             setError(`Failed to ${action} task. Server response was unexpected.`);
        }
    } catch (err: any) {
        setError(err.message || `Failed to ${action} task.`);
    }
};

const handleUserSubmitTask = async (assignmentId: string, delayReason?: string) => {
    clearMessages();
    if (!currentUser) return;
    
    const assignment = assignments.find(a => a.taskId === assignmentId && a.personId === currentUser.id);
     if (!assignment) {
      setError("Assignment not found or you are not the assignee.");
      return;
    }

    if (assignment.status !== 'accepted_by_user') {
        setError(`This task ("${assignment.taskTitle}") cannot be submitted as it's not in 'Accepted by User' status. Current status: ${assignment.status.replace(/_/g, ' ')}`);
        return;
    }
    
    const submissionDate = new Date();
    const deadlineDate = assignment.deadline ? new Date(assignment.deadline) : null;
    
    // Adjust deadline to end of day for comparison if only date is given
    if (deadlineDate) {
        deadlineDate.setHours(23, 59, 59, 999); 
    }

    let newStatus: AssignmentStatus = 'submitted_on_time';
    if (deadlineDate && submissionDate > deadlineDate) {
        newStatus = 'submitted_late';
        if (!delayReason && assignmentToSubmitDelayReason === assignment.taskId) { // Check if modal was shown for this task
            setError("Submission is late. Please provide a reason for the delay.");
            setUserSubmissionDelayReason(''); // Ensure input is clear for this specific task
            setAssignmentToSubmitDelayReason(assignment.taskId); // Keep modal open or re-trigger if needed
            return;
        }
    }
    
    const payload: { status: AssignmentStatus; userSubmissionDate: string; userDelayReason?: string } = {
        status: newStatus,
        userSubmissionDate: submissionDate.toISOString(),
    };
    if (newStatus === 'submitted_late' && delayReason) {
        payload.userDelayReason = delayReason;
    }

    try {
        const updatedAssignment = await fetchData<Assignment>(`/assignments/${assignment.taskId}/person/${assignment.personId}/status`, {
             method: 'PUT',
             body: JSON.stringify(payload),
        });

        if (updatedAssignment && updatedAssignment.status === newStatus) {
            setAssignments(prev => prev.map(a => (a.taskId === assignment.taskId && a.personId === assignment.personId) ? updatedAssignment : a));
            setSuccessMessage(`Task "${assignment.taskTitle}" submitted successfully! Awaiting admin approval.`);
            setUserSubmissionDelayReason(''); 
            setAssignmentToSubmitDelayReason(null);

            const adminToNotify = getAdminToNotify(currentUser.referringAdminId);
            if (adminToNotify) {
                emailService.sendTaskStatusUpdateToAdminEmail(
                    adminToNotify.email, 
                    adminToNotify.displayName, 
                    currentUser.displayName, 
                    assignment.taskTitle, 
                    `submitted (${newStatus.replace(/_/g, ' ')})`
                );
            }
             await addAdminLogEntry(`Task "${assignment.taskTitle}" submitted by user ${currentUser.displayName} (${newStatus.replace(/_/g, ' ')}).`);
        } else {
            setError("Failed to submit task. Server response was unexpected.");
        }

    } catch (err: any) {
        setError(err.message || "Failed to submit task.");
    }
};


const handleAdminApproveTaskCompletion = async (assignmentId: string) => { // Here assignmentId is likely task_id from context
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin') return;

    const assignment = assignments.find(a => a.taskId === assignmentId && (a.status === 'submitted_on_time' || a.status === 'submitted_late'));
     if (!assignment) {
      setError("Submitted assignment not found or not in a submittable state.");
      return;
    }
    
    const newStatus: AssignmentStatus = 'completed_admin_approved';
    
    try {
        const updatedAssignment = await fetchData<Assignment>(`/assignments/${assignment.taskId}/person/${assignment.personId}/status`, {
            method: 'PUT',
            body: JSON.stringify({ status: newStatus }),
        });

        if (updatedAssignment && updatedAssignment.status === newStatus) {
            setAssignments(prev => prev.map(a => (a.taskId === assignment.taskId && a.personId === assignment.personId) ? updatedAssignment : a));
            setSuccessMessage(`Task "${assignment.taskTitle}" (submitted by ${assignment.personName}) has been approved as completed.`);
            
            const userToNotify = users.find(u => u.id === assignment.personId);
            if (userToNotify) {
                 emailService.sendTaskCompletionApprovedToUserEmail(userToNotify.email, userToNotify.displayName, assignment.taskTitle, currentUser.displayName);
            }
            await addAdminLogEntry(`Task completion for "${assignment.taskTitle}" (user: ${assignment.personName}) approved by ${currentUser.displayName}.`);
        } else {
            setError("Failed to approve task completion. Server response was unexpected.");
        }
    } catch (err: any) {
        setError(err.message || "Failed to approve task completion.");
    }
};


const addAdminLogEntry = async (logText: string, imageFile?: File | null): Promise<void> => {
    if (!currentUser || currentUser.role !== 'admin') return;

    // For now, we'll just log the text. Image upload would require multipart/form-data.
    // This simplified version assumes backend can handle text-only logs or logs with image URLs (if pre-uploaded).
    
    const newLogEntryData: Omit<AdminLogEntry, 'id' | 'timestamp' | 'imagePreviewUrl'> = {
        adminId: currentUser.id,
        adminDisplayName: currentUser.displayName,
        logText: logText,
    };

    // If image handling is added:
    // const formData = new FormData();
    // formData.append('adminId', currentUser.id);
    // formData.append('adminDisplayName', currentUser.displayName);
    // formData.append('logText', logText);
    // if (imageFile) {
    //   formData.append('logImage', imageFile);
    // }
    // const createdLog = await fetchData<AdminLogEntry>('/admin-logs', {
    //   method: 'POST',
    //   body: formData, // Requires fetchData to handle FormData
    //   headers: { /* Remove 'Content-Type': 'application/json' for FormData */ }
    // });

    try {
        const createdLog = await fetchData<AdminLogEntry>('/admin-logs', {
            method: 'POST',
            body: JSON.stringify(newLogEntryData), 
        });

        if (createdLog && createdLog.id) {
            setAdminLogs(prev => [createdLog, ...prev]); // Prepend to show newest first
            // For UI if form was separate:
            // setAdminLogText(''); 
            // setAdminLogImageFile(null);
            // setSuccessMessage("Log entry added."); // Might be too noisy for automatic logs
        } else {
            console.error("Failed to add admin log entry: Server did not confirm creation.");
            // setError("Failed to add admin log entry automatically."); // Avoid flooding UI with errors for background logs
        }
    } catch (err: any) {
        console.error("Error adding admin log automatically:", err.message);
        // setError(err.message || "Error adding admin log automatically.");
    }
};

const handleManualAdminLogSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin' || !adminLogText.trim()) {
        setError("Log text cannot be empty.");
        return;
    }
    setIsSubmittingLog(true);
    try {
        // This specific function call will use the state `adminLogText` and `adminLogImageFile`
        // For now, imageFile is not fully handled in addAdminLogEntry's simplified version.
        // To make this work with images, addAdminLogEntry would need to be adapted for FormData.
        
        // Simplified: just use addAdminLogEntry with text.
        // If image upload is implemented, pass adminLogImageFile to a modified addAdminLogEntry.
        
        const newLogEntryData: Omit<AdminLogEntry, 'id' | 'timestamp' | 'imagePreviewUrl'> = {
            adminId: currentUser.id,
            adminDisplayName: currentUser.displayName,
            logText: adminLogText,
            // imagePreviewUrl: will be set by backend if image is uploaded
        };

        let endpoint = '/admin-logs';
        let options: RequestInit = {
            method: 'POST',
        };

        let requestBody: any;

        if (adminLogImageFile) {
            endpoint = '/admin-logs/upload'; // Assuming a different endpoint for uploads
            const formData = new FormData();
            formData.append('adminId', currentUser.id);
            formData.append('adminDisplayName', currentUser.displayName);
            formData.append('logText', adminLogText);
            formData.append('logImage', adminLogImageFile);
            requestBody = formData;
            // For FormData, Content-Type header is set automatically by browser, so remove manual one
            options.headers = {}; 
        } else {
            requestBody = JSON.stringify(newLogEntryData);
            options.headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        }
        options.body = requestBody;


        const createdLog = await fetchData<AdminLogEntry>(endpoint, options);


        if (createdLog && createdLog.id) {
            setAdminLogs(prev => [createdLog, ...prev]);
            setSuccessMessage("Admin log entry added successfully!");
            setAdminLogText('');
            setAdminLogImageFile(null);
            const fileInput = document.getElementById('adminLogImage') as HTMLInputElement;
            if (fileInput) fileInput.value = '';
        } else {
            setError("Failed to add admin log entry. Server did not confirm creation.");
        }
    } catch (err: any) {
        setError(err.message || "Failed to add admin log entry.");
    } finally {
        setIsSubmittingLog(false);
    }
};


const generatePreRegistrationLink = () => {
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin') {
        setError("Only administrators can generate pre-registration links.");
        return;
    }
    const link = `${window.location.origin}${window.location.pathname}#${Page.PreRegistration}?refAdminId=${currentUser.id}`;
    setGeneratedLink(link);
    setSuccessMessage("Pre-registration link generated successfully. Copy it below.");
    navigator.clipboard.writeText(link)
        .then(() => setInfoMessage("Link copied to clipboard!"))
        .catch(() => setInfoMessage("Link generated. Please copy it manually."));
    addAdminLogEntry(`Pre-registration link generated by ${currentUser.displayName}.`);
};

const completeUserTour = (completed: boolean) => {
    setShowUserTour(false);
    if (currentUser && completed) {
        localStorage.setItem(`hasCompletedUserTour_${currentUser.id}`, 'true');
        setSuccessMessage("Great! You've completed the tour. Feel free to explore.");
    } else if (currentUser) {
        setInfoMessage("You can always restart the tour from your profile or help section if needed.");
        // Optionally, allow re-showing later, e.g., don't set the flag or set a "skipped" flag.
    }
};


// --- Render Logic & Components ---
if (isLoadingAppData) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-bground p-4">
        <LoadingSpinner />
        <p className="text-textlight mt-4">Loading application data...</p>
      </div>
    );
}

// Pre-Registration Page (Special case, typically no nav bar)
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


// Login / Registration Page (No nav bar)
if (!currentUser && currentPage === Page.Login) {
  const isFirstUserScenario = users.length === 0;
  const roleForNewRegistration = isFirstUserScenario ? 'admin' : newRegistrationForm.role;

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
       <div className="absolute top-4 right-4">
            {/* Theme toggle can go here if needed */}
       </div>
      <div className="bg-surface p-6 md:p-8 rounded-xl shadow-2xl w-full max-w-md">
        <h1 className="text-3xl font-bold text-center text-primary mb-2">Task Assignment Assistant</h1>
        <p className="text-center text-neutral text-sm mb-6">Powered by AI for smarter task distribution.</p>
        
        {error && <div className="mb-4 p-3 bg-red-100 border border-red-400 text-danger rounded-md shadow-md" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-xs font-semibold">X</button></div>}
        {successMessage && <div className="mb-4 p-3 bg-green-100 border border-green-400 text-success rounded-md shadow-md" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-xs font-semibold">X</button></div>}
        {infoMessage && <div className="mb-4 p-3 bg-blue-100 border border-blue-400 text-info rounded-md shadow-md" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-xs font-semibold">X</button></div>}

        {authView === 'login' ? (
          <form onSubmit={handleLogin} className="space-y-5">
            <h2 className="text-2xl font-semibold text-textlight text-center mb-5">Login</h2>
            <div>
              <label htmlFor="login-email" className="block text-sm font-medium text-textlight sr-only">Email address</label>
              <AuthFormInput
                id="login-email"
                aria-label="Email address for login"
                name="email"
                type="email"
                autoComplete="email"
                required
                placeholder="Email Address"
                value={newLoginForm.email}
                onChange={(e) => setNewLoginForm({ ...newLoginForm, email: e.target.value })}
              />
            </div>
            <div>
              <label htmlFor="login-password" className="block text-sm font-medium text-textlight sr-only">Password</label>
              <AuthFormInput
                id="login-password"
                aria-label="Password for login"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                placeholder="Password"
                value={newLoginForm.password}
                onChange={(e) => setNewLoginForm({ ...newLoginForm, password: e.target.value })}
              />
            </div>
            <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm">
              Sign In
            </button>
            <p className="text-center text-sm">
              <button type="button" className="font-medium text-authLink hover:underline">
                Forgot password?
              </button>
            </p>
          </form>
        ) : (
          <form onSubmit={handleNewRegistration} className="space-y-4">
            <h2 className="text-2xl font-semibold text-textlight text-center mb-4">
                {isFirstUserScenario ? "Admin Registration (First User)" : "Create Account"}
            </h2>
             {isFirstUserScenario && (
                <p className="text-center text-sm text-neutral mb-3">
                    As the first user, you will be registered as an Administrator.
                </p>
            )}
            <div>
              <label htmlFor="reg-name" className="block text-sm font-medium text-textlight sr-only">Full Name</label>
              <AuthFormInput
                id="reg-name"
                aria-label="Full Name for registration"
                name="name"
                type="text"
                autoComplete="name"
                required
                placeholder="Full Name"
                value={newRegistrationForm.name}
                onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, name: e.target.value })}
              />
            </div>
            <div>
              <label htmlFor="reg-email" className="block text-sm font-medium text-textlight sr-only">Email address</label>
              <AuthFormInput
                id="reg-email"
                aria-label="Email address for registration"
                name="email"
                type="email"
                autoComplete="email"
                required
                placeholder="Email Address"
                value={newRegistrationForm.email}
                onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, email: e.target.value })}
              />
            </div>
            <div>
              <label htmlFor="reg-password" className="block text-sm font-medium text-textlight sr-only">Password</label>
              <AuthFormInput
                id="reg-password"
                aria-label="Password for registration"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                placeholder="Create Password"
                value={newRegistrationForm.password}
                onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, password: e.target.value })}
                aria-describedby="passwordHelpRegAuth"
              />
              <p id="passwordHelpRegAuth" className="mt-1 text-xs text-neutral px-1">{passwordRequirementsText}</p>
            </div>
            <div>
              <label htmlFor="reg-confirm-password" className="block text-sm font-medium text-textlight sr-only">Confirm Password</label>
              <AuthFormInput
                id="reg-confirm-password"
                aria-label="Confirm password for registration"
                name="confirmPassword"
                type="password"
                autoComplete="new-password"
                required
                placeholder="Confirm Password"
                value={newRegistrationForm.confirmPassword}
                onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, confirmPassword: e.target.value })}
              />
            </div>
            {!isFirstUserScenario && (
              <div>
                <label htmlFor="reg-role" className="block text-sm font-medium text-textlight sr-only">Role</label>
                 <AuthFormSelect
                    id="reg-role"
                    aria-label="Select role for registration"
                    name="role"
                    value={newRegistrationForm.role}
                    onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, role: e.target.value as Role })}
                    required
                >
                    <option value="user">User</option>
                    <option value="admin">Administrator (Requires Approval)</option>
                </AuthFormSelect>
              </div>
            )}
             <input type="hidden" name="role" value={roleForNewRegistration} />


            <button type="submit" className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm">
              {isFirstUserScenario ? "Register Admin Account" : "Register"}
            </button>
          </form>
        )}
        <p className="mt-6 text-center text-sm">
          {authView === 'login' ? "Don't have an account?" : "Already have an account?"}{' '}
          <button
            onClick={() => { clearMessages(); setAuthView(authView === 'login' ? 'register' : 'login'); }}
            className="font-medium text-authLink hover:underline"
          >
            {authView === 'login' ? 'Sign Up' : 'Sign In'}
          </button>
        </p>
         <p className="mt-3 text-center text-sm">
            Invited by an admin?{' '}
            <button
                onClick={() => navigateTo(Page.PreRegistration)} // This will set hash, effect will pick it up
                className="font-medium text-authLink hover:underline"
            >
                Use Pre-registration Link
            </button>
        </p>
      </div>
      <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by AI.</p>
      </footer>
    </div>
  );
}


// Main Application View (with Navigation)
return (
    <div className="min-h-screen bg-bground flex flex-col main-app-scope">
      {showUserTour && currentUser && <UserTour user={currentUser} onClose={completeUserTour} />}
      <header className="bg-surface shadow-md sticky top-0 z-50">
        <nav className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <LightBulbIcon className="h-8 w-8 text-primary" />
              <span className="ml-3 font-bold text-xl text-textlight">Task Assistant</span>
            </div>
            <div className="flex items-center space-x-3">
              <span className="text-sm text-neutral hidden sm:block">
                Welcome, {currentUser?.displayName || 'Guest'} ({currentUser?.role})
              </span>
              <button
                onClick={() => navigateTo(Page.UserProfile)}
                className="p-2 rounded-full text-neutral hover:text-primary hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-primary"
                aria-label="My Profile"
              >
                <UserCircleIcon className="h-6 w-6" />
              </button>
              <button
                onClick={handleLogout}
                className="p-2 rounded-full text-neutral hover:text-danger hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-danger"
                aria-label="Logout"
              >
                <LogoutIcon className="h-6 w-6" />
              </button>
            </div>
          </div>
        </nav>
      </header>

      <div className="flex-grow container mx-auto p-4 sm:p-6 lg:p-8 flex">
        {/* Sidebar Navigation */}
        <aside className="w-64 pr-8 space-y-3 sticky top-16 self-start"> {/* sticky + self-start for non-scrolling sidebar */}
          <h3 className="text-xs font-semibold text-neutral uppercase tracking-wider">Menu</h3>
          {currentUser?.role === 'admin' && (
            <>
              <button onClick={() => navigateTo(Page.Dashboard)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.Dashboard ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
                <BriefcaseIcon className="h-5 w-5" />
                <span>Admin Dashboard</span>
              </button>
              <button onClick={() => navigateTo(Page.UserManagement)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.UserManagement ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
                <UsersIcon className="h-5 w-5" />
                <span>User Management</span>
              </button>
              <button onClick={() => navigateTo(Page.ManagePrograms)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.ManagePrograms ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
                <KeyIcon className="h-5 w-5" /> {/* Placeholder icon */}
                <span>Manage Programs</span>
              </button>
               <button onClick={() => navigateTo(Page.ManageTasks)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.ManageTasks ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
                <ClipboardListIcon className="h-5 w-5" />
                <span>Manage Tasks</span>
              </button>
              <button onClick={() => navigateTo(Page.AssignWork)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.AssignWork ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
                <CheckCircleIcon className="h-5 w-5" />
                <span>Assign Work</span>
              </button>
            </>
          )}
          <button onClick={() => navigateTo(Page.ViewAssignments)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.ViewAssignments ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
            <ClipboardListIcon className="h-5 w-5" />
            <span>{currentUser?.role === 'admin' ? 'All Assignments' : 'My Assignments'}</span>
          </button>
           <button onClick={() => navigateTo(Page.ViewTasks)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.ViewTasks ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
            <LightBulbIcon className="h-5 w-5" />
            <span>{currentUser?.role === 'admin' ? 'All Tasks List' : 'Available Tasks'}</span>
          </button>
          <button onClick={() => navigateTo(Page.UserProfile)} className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors ${currentPage === Page.UserProfile ? 'bg-primary text-white shadow-lg' : 'text-textlight hover:bg-gray-200 hover:text-texthighlight'}`}>
            <UserCircleIcon className="h-5 w-5" />
            <span>My Profile</span>
          </button>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 bg-surface p-6 rounded-xl shadow-xl overflow-y-auto">
          {error && <div className="mb-4 p-4 bg-red-100 border-l-4 border-danger text-danger" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-xs font-bold">X</button></div>}
          {successMessage && <div className="mb-4 p-4 bg-green-100 border-l-4 border-success text-green-700" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-xs font-bold">X</button></div>}
          {infoMessage && <div className="mb-4 p-4 bg-blue-100 border-l-4 border-info text-blue-700" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-xs font-bold">X</button></div>}
          
          {/* --- Admin Dashboard --- */}
          {currentPage === Page.Dashboard && currentUser?.role === 'admin' && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">Admin Dashboard</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="bg-gray-50 p-5 rounded-lg shadow hover:shadow-lg transition-shadow">
                  <h3 className="text-lg font-medium text-primary mb-2">Total Users</h3>
                  <p className="text-3xl font-bold text-textlight">{users.length}</p>
                </div>
                <div className="bg-gray-50 p-5 rounded-lg shadow hover:shadow-lg transition-shadow">
                  <h3 className="text-lg font-medium text-primary mb-2">Pending Approvals</h3>
                  <p className="text-3xl font-bold text-textlight">{pendingUsers.length}</p>
                  {pendingUsers.length > 0 && <button onClick={() => navigateTo(Page.UserManagement)} className="text-sm text-blue-500 hover:underline mt-1">Review</button>}
                </div>
                <div className="bg-gray-50 p-5 rounded-lg shadow hover:shadow-lg transition-shadow">
                  <h3 className="text-lg font-medium text-primary mb-2">Total Tasks</h3>
                  <p className="text-3xl font-bold text-textlight">{tasks.length}</p>
                </div>
                <div className="bg-gray-50 p-5 rounded-lg shadow hover:shadow-lg transition-shadow">
                  <h3 className="text-lg font-medium text-primary mb-2">Active Assignments</h3>
                  <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'accepted_by_user' || a.status === 'pending_acceptance').length}</p>
                </div>
                 <div className="bg-gray-50 p-5 rounded-lg shadow hover:shadow-lg transition-shadow">
                  <h3 className="text-lg font-medium text-primary mb-2">Completed Tasks (Approved)</h3>
                  <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'completed_admin_approved').length}</p>
                </div>
                 <div className="bg-gray-50 p-5 rounded-lg shadow hover:shadow-lg transition-shadow">
                  <h3 className="text-lg font-medium text-primary mb-2">Total Programs</h3>
                  <p className="text-3xl font-bold text-textlight">{programs.length}</p>
                </div>
              </div>

              <div className="mt-8">
                <h3 className="text-xl font-semibold text-textlight mb-4">Recent Admin Activity</h3>
                {adminLogs.length > 0 ? (
                  <div className="space-y-3 max-h-96 overflow-y-auto bg-gray-50 p-4 rounded-md">
                    {adminLogs.slice(0, 10).map(log => ( // Show recent 10
                      <div key={log.id} className="p-3 border border-gray-200 rounded-md bg-white text-sm">
                        <p className="text-textlight">
                          <span className="font-medium text-primary">{log.adminDisplayName}</span>: {log.logText}
                          {log.imagePreviewUrl && (
                            <a href={log.imagePreviewUrl} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline ml-2">(View Image)</a>
                          )}
                        </p>
                        <p className="text-xs text-neutral mt-1">{new Date(log.timestamp).toLocaleString()}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-neutral">No admin activity logged yet.</p>
                )}
              </div>
              
              <div className="mt-8">
                <h3 className="text-xl font-semibold text-textlight mb-4">Manual Admin Log Entry</h3>
                <form onSubmit={handleManualAdminLogSubmit} className="space-y-4 bg-gray-50 p-6 rounded-lg shadow">
                    <div>
                        <label htmlFor="adminLogText" className="block text-sm font-medium text-textlight">Log Message</label>
                        <textarea
                            id="adminLogText"
                            value={adminLogText}
                            onChange={(e) => setAdminLogText(e.target.value)}
                            required
                            rows={3}
                            className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight"
                            placeholder="Enter log details manually..."
                        />
                    </div>
                    <div>
                        <label htmlFor="adminLogImage" className="block text-sm font-medium text-textlight">Attach Image (Optional)</label>
                        <input
                            type="file"
                            id="adminLogImage"
                            accept="image/*"
                            onChange={(e) => setAdminLogImageFile(e.target.files ? e.target.files[0] : null)}
                            className="mt-1 block w-full text-sm text-neutral file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-primary file:text-white hover:file:bg-blue-600"
                        />
                         {adminLogImageFile && <p className="text-xs text-neutral mt-1">Selected: {adminLogImageFile.name}</p>}
                    </div>
                    <button type="submit" className="btn-primary" disabled={isSubmittingLog}>
                        {isSubmittingLog ? <LoadingSpinner /> : 'Add Log Entry'}
                    </button>
                </form>
              </div>

            </div>
          )}

          {/* --- User Profile Page --- */}
          {currentPage === Page.UserProfile && currentUser && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">My Profile</h2>
              <form onSubmit={handleUpdateProfile} className="space-y-6 max-w-lg bg-gray-50 p-6 rounded-lg shadow-md">
                <FormInput label="Email Address" id="profileEmail" type="email" value={userForm.email} disabled aria-describedby="emailHelp" description="Email cannot be changed after registration." />
                <FormInput label="System ID / Username" id="profileUniqueId" type="text" value={userForm.uniqueId} onChange={(e) => setUserForm({...userForm, uniqueId: e.target.value})} required />
                <FormInput label="Display Name" id="profileDisplayName" type="text" value={userForm.displayName} onChange={(e) => setUserForm({...userForm, displayName: e.target.value})} required />
                <FormInput label="Position / Role Title" id="profilePosition" type="text" value={userForm.position} onChange={(e) => setUserForm({...userForm, position: e.target.value})} required />
                <FormTextarea label="My Skills & Interests (comma-separated)" id="profileUserInterests" value={userForm.userInterests} onChange={(e) => setUserForm({...userForm, userInterests: e.target.value})} placeholder="e.g., Event Planning, Public Speaking, Web Development, Graphic Design" />
                <FormInput label="Phone (Optional)" id="profilePhone" type="tel" value={userForm.phone} onChange={(e) => setUserForm({...userForm, phone: e.target.value})} />
                <FormSelect label="Notification Preference" id="profileNotificationPref" value={userForm.notificationPreference} onChange={(e) => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                  <option value="email">Email</option>
                  <option value="phone">Phone (if available)</option>
                  <option value="none">None</option>
                </FormSelect>
                <FormInput label="New Password (leave blank to keep current)" id="profilePassword" type="password" value={userForm.password} onChange={(e) => setUserForm({...userForm, password: e.target.value})} autoComplete="new-password" aria-describedby="passwordHelpProfile"/>
                <p id="passwordHelpProfile" className="text-xs text-neutral -mt-4 px-1">{passwordRequirementsText}</p>
                <FormInput label="Confirm New Password" id="profileConfirmPassword" type="password" value={userForm.confirmPassword} onChange={(e) => setUserForm({...userForm, confirmPassword: e.target.value})} autoComplete="new-password" />
                <div className="flex justify-end">
                  <button type="submit" className="btn-primary">Update Profile</button>
                </div>
              </form>
            </div>
          )}
          
          {/* --- User Management Page (Admin) --- */}
          {currentPage === Page.UserManagement && currentUser?.role === 'admin' && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">User Management</h2>

              {/* Section for Pending Users */}
              <div className="mb-8">
                <h3 className="text-xl font-semibold text-primary mb-4">Pending Approvals ({pendingUsers.length})</h3>
                {pendingUsers.length > 0 ? (
                  <div className="space-y-4">
                    {pendingUsers.map(pu => (
                      <div key={pu.id} className="bg-yellow-50 p-4 rounded-lg shadow-md border border-yellow-200">
                        <div className="flex flex-col sm:flex-row justify-between sm:items-center">
                            <div>
                                <p className="font-semibold text-textlight">{pu.displayName} ({pu.uniqueId})</p>
                                <p className="text-sm text-neutral">Email: {pu.email} | Role: {pu.role}</p>
                                <p className="text-xs text-neutral">Submitted: {new Date(pu.submissionDate).toLocaleDateString()}</p>
                                {pu.referringAdminId && <p className="text-xs text-neutral">Referred by: {users.find(u=>u.id === pu.referringAdminId)?.displayName || 'Admin ID: '+pu.referringAdminId}</p>}
                            </div>
                            <div className="mt-3 sm:mt-0 space-x-0 sm:space-x-2 space-y-2 sm:space-y-0 flex flex-col sm:flex-row">
                                <button onClick={() => { setApprovingPendingUser(pu); clearMessages(); }} className="btn-success px-3 py-1.5 text-sm">Approve</button>
                                <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger px-3 py-1.5 text-sm">Reject</button>
                            </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-neutral">No users are currently pending approval.</p>
                )}
              </div>
              
              {/* Modal for Approval with Role/Position Setting */}
                {approvingPendingUser && (
                    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[70]" aria-modal="true" role="dialog">
                        <div className="bg-surface p-6 rounded-lg shadow-xl w-full max-w-lg">
                            <h3 className="text-lg font-semibold text-textlight mb-4">Approve User: {approvingPendingUser.displayName}</h3>
                            {error && <p className="text-danger text-sm mb-3">{error}</p>}
                            <p className="text-sm text-neutral mb-1">System ID: {approvingPendingUser.uniqueId}</p>
                            <p className="text-sm text-neutral mb-1">Email: {approvingPendingUser.email}</p>
                            <p className="text-sm text-neutral mb-4">Intended Role: {approvingPendingUser.role}</p>
                            
                            {/* Form fields for potential admin overrides during approval could go here if needed */}
                            {/* For example, to set an initial position or confirm/change role */}
                            {/* <FormInput label="Position" id="approvePosition" type="text" ... /> */}
                            {/* <FormSelect label="Role" id="approveRole" ... > <option value="user">User</option> <option value="admin">Admin</option> </FormSelect> */}

                            <div className="mt-6 flex justify-end space-x-3">
                                <button onClick={() => setApprovingPendingUser(null)} className="btn-neutral">Cancel</button>
                                <button onClick={() => handleApprovePendingUser(approvingPendingUser.id)} className="btn-success">Confirm Approval</button>
                            </div>
                        </div>
                    </div>
                )}


              {/* Section for Active Users */}
              <div>
                <h3 className="text-xl font-semibold text-primary mb-4">Active Users ({users.length})</h3>
                 <div className="mb-6">
                  <button onClick={generatePreRegistrationLink} className="btn-info inline-flex items-center">
                    <PlusCircleIcon className="w-5 h-5 mr-2"/> Generate Pre-registration Link for New User
                  </button>
                  {generatedLink && (
                    <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded">
                      <p className="text-sm text-textlight font-medium">Generated Link (copied to clipboard):</p>
                      <input type="text" readOnly value={generatedLink} className="w-full p-2 mt-1 border border-neutral rounded bg-gray-100 text-sm" onClick={(e) => (e.target as HTMLInputElement).select()}/>
                    </div>
                  )}
                </div>
                {users.length > 0 ? (
                  <div className="space-y-4">
                    {users.map(user => (
                      <div key={user.id} className="bg-gray-50 p-4 rounded-lg shadow-md border border-gray-200">
                         <div className="flex flex-col sm:flex-row justify-between sm:items-center">
                            <div>
                                <p className="font-semibold text-textlight">{user.displayName} ({user.uniqueId})</p>
                                <p className="text-sm text-neutral">Email: {user.email} | Role: {user.role} | Position: {user.position}</p>
                                <p className="text-xs text-neutral">Interests: {user.userInterests || 'Not specified'}</p>
                            </div>
                            <div className="mt-3 sm:mt-0">
                                <button 
                                    onClick={() => { 
                                        setEditingUserId(user.id); 
                                        setUserForm({
                                            email: user.email, uniqueId: user.uniqueId, displayName: user.displayName,
                                            position: user.position, userInterests: user.userInterests || '',
                                            phone: user.phone || '', notificationPreference: user.notificationPreference || 'none',
                                            role: user.role, password: '', confirmPassword: '', referringAdminId: user.referringAdminId || ''
                                        });
                                        clearMessages(); // Clear any previous form errors
                                        // Smooth scroll to form could be added here
                                    }} 
                                    className="btn-neutral px-3 py-1.5 text-sm"
                                >
                                    Edit
                                </button>
                                {/* Add delete user button if needed, with safeguards */}
                            </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-neutral">No active users found.</p>
                )}
              </div>
              
              {/* Form for Editing User (Admin) */}
                {editingUserId && (
                <div className="mt-8 pt-6 border-t border-gray-300">
                    <h3 className="text-xl font-semibold text-textlight mb-4">Edit User: {userForm.displayName}</h3>
                    <form onSubmit={handleAdminUpdateUser} className="space-y-5 bg-white p-6 rounded-lg shadow-lg">
                    <FormInput label="Email Address" id="adminEditEmail" type="email" value={userForm.email} onChange={(e) => setUserForm({...userForm, email: e.target.value})} required />
                    <FormInput label="System ID / Username" id="adminEditUniqueId" type="text" value={userForm.uniqueId} onChange={(e) => setUserForm({...userForm, uniqueId: e.target.value})} required />
                    <FormInput label="Display Name" id="adminEditDisplayName" type="text" value={userForm.displayName} onChange={(e) => setUserForm({...userForm, displayName: e.target.value})} required />
                    <FormInput label="Position / Role Title" id="adminEditPosition" type="text" value={userForm.position} onChange={(e) => setUserForm({...userForm, position: e.target.value})} required />
                    <FormTextarea label="User Skills & Interests" id="adminEditUserInterests" value={userForm.userInterests} onChange={(e) => setUserForm({...userForm, userInterests: e.target.value})} />
                    <FormInput label="Phone" id="adminEditPhone" type="tel" value={userForm.phone} onChange={(e) => setUserForm({...userForm, phone: e.target.value})} />
                    <FormSelect label="Notification Preference" id="adminEditNotificationPref" value={userForm.notificationPreference} onChange={(e) => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                        <option value="email">Email</option>
                        <option value="phone">Phone</option>
                        <option value="none">None</option>
                    </FormSelect>
                    <FormSelect label="Role" id="adminEditRole" value={userForm.role} onChange={(e) => setUserForm({...userForm, role: e.target.value as Role})}>
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </FormSelect>
                    <FormInput label="New Password (leave blank to keep current)" id="adminEditPassword" type="password" value={userForm.password} onChange={(e) => setUserForm({...userForm, password: e.target.value})} autoComplete="new-password" aria-describedby="passwordHelpAdminEdit"/>
                     <p id="passwordHelpAdminEdit" className="text-xs text-neutral -mt-4 px-1">{passwordRequirementsText}</p>
                    <FormInput label="Confirm New Password" id="adminEditConfirmPassword" type="password" value={userForm.confirmPassword} onChange={(e) => setUserForm({...userForm, confirmPassword: e.target.value})} autoComplete="new-password" />
                    <div className="flex justify-end space-x-3">
                        <button type="button" onClick={() => { setEditingUserId(null); setUserForm(initialUserFormData); clearMessages(); }} className="btn-neutral">Cancel</button>
                        <button type="submit" className="btn-primary">Save Changes</button>
                    </div>
                    </form>
                </div>
                )}

            </div>
          )}
          
          {/* --- Manage Programs (Admin) --- */}
          {currentPage === Page.ManagePrograms && currentUser?.role === 'admin' && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">Manage Programs</h2>
              <form onSubmit={handleCreateProgram} className="mb-8 space-y-4 bg-gray-50 p-6 rounded-lg shadow-md">
                <h3 className="text-lg font-medium text-primary">Create New Program</h3>
                <FormInput label="Program Name" id="programName" type="text" value={programForm.name} onChange={e => setProgramForm({...programForm, name: e.target.value})} required />
                <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({...programForm, description: e.target.value})} />
                <button type="submit" className="btn-primary">Create Program</button>
              </form>
              <div>
                <h3 className="text-lg font-medium text-primary mb-3">Existing Programs ({programs.length})</h3>
                {programs.length > 0 ? (
                    <div className="space-y-3">
                    {programs.map(p => (
                        <div key={p.id} className="bg-white p-4 rounded-md shadow border">
                        <h4 className="font-semibold text-textlight">{p.name}</h4>
                        <p className="text-sm text-neutral whitespace-pre-wrap">{p.description || "No description."}</p>
                        {/* TODO: Add Edit/Delete program functionality here */}
                        </div>
                    ))}
                    </div>
                ) : <p className="text-neutral">No programs created yet.</p>}
              </div>
            </div>
          )}

          {/* --- Manage Tasks (Admin) --- */}
          {currentPage === Page.ManageTasks && currentUser?.role === 'admin' && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">Manage Tasks</h2>
              <form onSubmit={handleCreateTask} className="mb-8 space-y-4 bg-gray-50 p-6 rounded-lg shadow-md">
                <h3 className="text-lg font-medium text-primary">Create New Task</h3>
                <FormInput label="Task Title" id="taskTitle" type="text" value={taskForm.title} onChange={e => setTaskForm({...taskForm, title: e.target.value})} required />
                <FormTextarea label="Task Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({...taskForm, description: e.target.value})} required />
                <FormTextarea label="Required Skills (comma-separated)" id="taskSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({...taskForm, requiredSkills: e.target.value})} required />
                <FormSelect label="Related Program (Optional)" id="taskProgram" value={taskForm.programId || ''} onChange={e => setTaskForm({...taskForm, programId: e.target.value || undefined })}>
                  <option value="">None</option>
                  {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </FormSelect>
                <FormInput label="Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline || ''} onChange={e => setTaskForm({...taskForm, deadline: e.target.value || undefined})} />
                <button type="submit" className="btn-primary">Create Task</button>
              </form>
              <div>
                <h3 className="text-lg font-medium text-primary mb-3">Existing Tasks ({tasks.length})</h3>
                {tasks.length > 0 ? (
                    <div className="space-y-3">
                    {tasks.map(t => (
                        <div key={t.id} className="bg-white p-4 rounded-md shadow border">
                        <div className="flex justify-between items-start">
                            <div>
                                <h4 className="font-semibold text-textlight">{t.title}</h4>
                                <p className="text-sm text-neutral whitespace-pre-wrap">{t.description}</p>
                                <p className="text-xs text-gray-500 mt-1">Skills: {t.requiredSkills}</p>
                                {t.programName && <p className="text-xs text-gray-500">Program: {t.programName}</p>}
                                {t.deadline && <p className="text-xs text-gray-500">Deadline: {new Date(t.deadline).toLocaleDateString()}</p>}
                            </div>
                            <button onClick={() => handleDeleteTask(t.id)} className="btn-danger p-1.5 text-xs" aria-label={`Delete task ${t.title}`}>
                                <TrashIcon className="w-4 h-4"/>
                            </button>
                        </div>
                        </div>
                    ))}
                    </div>
                ) : <p className="text-neutral">No tasks created yet.</p>}
              </div>
            </div>
          )}
          
          {/* --- Assign Work (Admin) --- */}
          {currentPage === Page.AssignWork && currentUser?.role === 'admin' && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">Assign Work</h2>
              <form onSubmit={handleCreateAssignment} className="space-y-6 bg-gray-50 p-6 rounded-lg shadow-md">
                <div>
                  <FormSelect label="Select Task to Assign" id="selectTask" value={selectedTaskForAssignment || ''} onChange={e => {setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); clearMessages();}}>
                    <option value="" disabled>-- Select a Task --</option>
                    {tasks.filter(task => !assignments.some(a => a.taskId === task.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user' || a.status === 'completed_admin_approved'))).map(t => ( // Filter out already assigned/completed tasks
                      <option key={t.id} value={t.id}>{t.title}</option>
                    ))}
                  </FormSelect>
                </div>

                {selectedTaskForAssignment && (
                  <>
                    <button type="button" onClick={handleGetAssignmentSuggestion} className="btn-info text-sm my-2" disabled={isLoadingSuggestion}>
                      {isLoadingSuggestion ? <LoadingSpinner/> : "Get AI Suggestion"}
                    </button>
                    {assignmentSuggestion && assignmentSuggestion.suggestedPersonName && (
                         <p className="text-sm text-green-700 bg-green-50 p-3 rounded-md">
                            AI Suggests: <strong>{assignmentSuggestion.suggestedPersonName}</strong>. 
                            Justification: <em>{assignmentSuggestion.justification}</em>
                        </p>
                    )}
                     {assignmentSuggestion && !assignmentSuggestion.suggestedPersonName && assignmentSuggestion.justification && (
                         <p className="text-sm text-amber-700 bg-amber-50 p-3 rounded-md">
                            AI: <em>{assignmentSuggestion.justification}</em>
                        </p>
                    )}


                    <div>
                      <FormSelect label="Assign to Person" id="assignedPerson" required>
                        <option value="" disabled>-- Select a Person --</option>
                        {users.filter(u => u.role === 'user' && !assignments.some(a => a.personId === u.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))).map(u => ( // Filter for users and those without active tasks
                          <option key={u.id} value={u.id} selected={assignmentSuggestion?.suggestedPersonName === u.displayName}>
                            {u.displayName} ({u.position}) - Interests: {u.userInterests?.substring(0,30) || 'N/A'}...
                          </option>
                        ))}
                      </FormSelect>
                       <p className="text-xs text-neutral mt-1">Only users without current active tasks are shown. If a user is not listed, they may already have a task.</p>
                    </div>
                    <FormInput label="Specific Deadline for this Assignment (Optional, overrides task default)" id="specificDeadline" type="date" value={assignmentForm.specificDeadline || ''} onChange={e => setAssignmentForm({ specificDeadline: e.target.value })} />
                    <button type="submit" className="btn-primary">Assign Task</button>
                  </>
                )}
              </form>
            </div>
          )}
          
          {/* --- View Assignments (Admin & User) --- */}
          {currentPage === Page.ViewAssignments && currentUser && (
            <div>
              <h2 className="text-2xl font-semibold text-textlight mb-6">{currentUser.role === 'admin' ? 'All Task Assignments' : 'My Task Assignments'}</h2>
              
              {/* Modal for Delay Reason */}
              {assignmentToSubmitDelayReason && currentUser && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[70]" aria-modal="true" role="dialog">
                    <div className="bg-surface p-6 rounded-lg shadow-xl w-full max-w-lg">
                        <h3 className="text-lg font-semibold text-textlight mb-2">Reason for Late Submission</h3>
                        <p className="text-sm text-neutral mb-4">Task: "{assignments.find(a=>a.taskId === assignmentToSubmitDelayReason)?.taskTitle || 'Selected Task'}"</p>
                        {error && <p className="text-danger text-sm mb-3">{error}</p>}
                        <FormTextarea
                            label="Please provide a brief reason for the delay:"
                            id="userDelayReason"
                            value={userSubmissionDelayReason}
                            onChange={(e) => setUserSubmissionDelayReason(e.target.value)}
                            required
                            rows={3}
                        />
                        <div className="mt-6 flex justify-end space-x-3">
                            <button onClick={() => setAssignmentToSubmitDelayReason(null)} className="btn-neutral">Cancel</button>
                            <button 
                                onClick={() => handleUserSubmitTask(assignmentToSubmitDelayReason, userSubmissionDelayReason)} 
                                className="btn-primary"
                                disabled={!userSubmissionDelayReason.trim()}
                            >
                                Submit with Reason
                            </button>
                        </div>
                    </div>
                </div>
              )}

              {assignments.length > 0 ? (
                <div className="space-y-4">
                  {assignments
                    .filter(a => currentUser.role === 'admin' || a.personId === currentUser.id)
                    .sort((a, b) => { // Sort by status, then deadline
                        const statusOrder: AssignmentStatus[] = ['pending_acceptance', 'accepted_by_user', 'submitted_late', 'submitted_on_time', 'declined_by_user', 'completed_admin_approved'];
                        const statusDiff = statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status);
                        if (statusDiff !== 0) return statusDiff;
                        return (new Date(a.deadline || 0)).getTime() - (new Date(b.deadline || 0)).getTime();
                    })
                    .map(a => {
                      const isUserAssignment = a.personId === currentUser.id;
                      const taskDetails = tasks.find(t => t.id === a.taskId);
                      let statusColor = 'text-neutral';
                      let bgColor = 'bg-gray-50';
                      switch(a.status) {
                        case 'pending_acceptance': statusColor = 'text-yellow-600'; bgColor = 'bg-yellow-50'; break;
                        case 'accepted_by_user': statusColor = 'text-blue-600'; bgColor = 'bg-blue-50'; break;
                        case 'submitted_on_time':
                        case 'submitted_late': statusColor = 'text-purple-600'; bgColor = 'bg-purple-50'; break;
                        case 'completed_admin_approved': statusColor = 'text-green-600'; bgColor = 'bg-green-50'; break;
                        case 'declined_by_user': statusColor = 'text-red-600'; bgColor = 'bg-red-50'; break;
                      }

                      return (
                        <div key={`${a.taskId}-${a.personId}`} className={`${bgColor} p-4 rounded-lg shadow-md border ${statusColor.replace('text-', 'border-')}`}>
                          <h3 className="font-semibold text-textlight text-lg">{a.taskTitle}</h3>
                          {currentUser.role === 'admin' && <p className="text-sm text-neutral">Assigned to: {a.personName}</p>}
                          <p className={`text-sm font-medium ${statusColor}`}>Status: {a.status.replace(/_/g, ' ')}</p>
                          {a.deadline && <p className="text-xs text-neutral">Deadline: {new Date(a.deadline).toLocaleDateString()}</p>}
                          {taskDetails && <p className="text-xs text-neutral mt-1">Task Description: {taskDetails.description}</p>}
                          {taskDetails && <p className="text-xs text-neutral">Required Skills: {taskDetails.requiredSkills}</p>}
                          {a.justification && currentUser.role === 'admin' && <p className="text-xs text-neutral italic mt-1">Justification: {a.justification}</p>}
                          {a.userSubmissionDate && <p className="text-xs text-neutral">Submitted: {new Date(a.userSubmissionDate).toLocaleString()}</p>}
                          {a.userDelayReason && <p className="text-xs text-red-500">Delay Reason: {a.userDelayReason}</p>}
                          
                          <div className="mt-3 space-x-2 space-y-2 sm:space-y-0">
                            {isUserAssignment && a.status === 'pending_acceptance' && (
                              <>
                                <button onClick={() => handleUserAcceptOrDeclineTask(a.taskId, 'accept')} className="btn-success px-3 py-1.5 text-sm">Accept Task</button>
                                <button onClick={() => handleUserAcceptOrDeclineTask(a.taskId, 'decline')} className="btn-danger px-3 py-1.5 text-sm">Decline Task</button>
                              </>
                            )}
                            {isUserAssignment && a.status === 'accepted_by_user' && (
                               <button 
                                onClick={() => {
                                    const deadlineDate = a.deadline ? new Date(a.deadline) : null;
                                    if (deadlineDate) deadlineDate.setHours(23, 59, 59, 999); // End of day for comparison
                                    if (deadlineDate && new Date() > deadlineDate) {
                                        setAssignmentToSubmitDelayReason(a.taskId); // Open modal for reason
                                        setUserSubmissionDelayReason(''); // Clear previous reason
                                        clearMessages();
                                    } else {
                                        handleUserSubmitTask(a.taskId); // Submit directly if on time
                                    }
                                }} 
                                className="btn-primary px-3 py-1.5 text-sm"
                                >
                                Mark as Completed / Submit
                                </button>
                            )}
                            {currentUser.role === 'admin' && (a.status === 'submitted_on_time' || a.status === 'submitted_late') && (
                              <button onClick={() => handleAdminApproveTaskCompletion(a.taskId)} className="btn-success px-3 py-1.5 text-sm">Approve Completion</button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                </div>
              ) : (
                <p className="text-neutral">{currentUser.role === 'admin' ? 'No tasks have been assigned yet.' : 'You have no tasks assigned to you currently.'}</p>
              )}
            </div>
          )}
          
          {/* --- View Tasks (User perspective for available tasks) --- */}
          {currentPage === Page.ViewTasks && currentUser && (
            <div>
                 <h2 className="text-2xl font-semibold text-textlight mb-6">{currentUser.role === 'admin' ? 'All Tasks Overview' : 'Available Tasks Directory'}</h2>
                {tasks.length > 0 ? (
                    <div className="space-y-4">
                        {tasks.map(task => {
                            const program = programs.find(p => p.id === task.programId);
                            const isAssignedToCurrentUser = assignments.some(a => a.taskId === task.id && a.personId === currentUser?.id && a.status !== 'declined_by_user' && a.status !== 'completed_admin_approved');
                            const isGenerallyAssigned = assignments.some(a => a.taskId === task.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'));
                            
                            let taskStatusDisplay = "Available";
                            let statusColor = "text-green-600";

                            if (isAssignedToCurrentUser) {
                                const currentUserAssignment = assignments.find(a => a.taskId === task.id && a.personId === currentUser?.id);
                                taskStatusDisplay = `Assigned to you (${currentUserAssignment?.status.replace(/_/g, ' ')})`;
                                statusColor = "text-blue-600";
                            } else if (isGenerallyAssigned) {
                                taskStatusDisplay = "Assigned to someone else";
                                statusColor = "text-orange-600";
                            }


                            return (
                                <div key={task.id} className={`bg-gray-50 p-4 rounded-lg shadow border ${isAssignedToCurrentUser ? 'border-blue-200' : (isGenerallyAssigned ? 'border-orange-200' : 'border-green-200') }`}>
                                    <h3 className="font-semibold text-textlight text-lg">{task.title}</h3>
                                    <p className="text-sm text-neutral whitespace-pre-wrap mt-1">{task.description}</p>
                                    <p className="text-xs text-gray-500 mt-2">Skills: {task.requiredSkills}</p>
                                    {program && <p className="text-xs text-gray-500">Program: {program.name}</p>}
                                    {task.deadline && <p className="text-xs text-gray-500">Deadline: {new Date(task.deadline).toLocaleDateString()}</p>}
                                    
                                    {currentUser.role === 'user' && (
                                         <p className={`text-sm font-medium mt-2 ${statusColor}`}>{taskStatusDisplay}</p>
                                    )}
                                    {currentUser.role === 'admin' && assignments.filter(a=>a.taskId === task.id).length > 0 && (
                                        <div className="mt-2 pt-2 border-t border-gray-200">
                                            <p className="text-xs font-semibold text-neutral">Assigned to:</p>
                                            <ul className="list-disc list-inside text-xs text-neutral">
                                                {assignments.filter(a=>a.taskId === task.id).map(assignee => (
                                                    <li key={assignee.personId}>{assignee.personName} ({assignee.status.replace(/_/g, ' ')})</li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}
                                    {currentUser.role === 'admin' && assignments.filter(a=>a.taskId === task.id).length === 0 && (
                                        <p className="text-xs text-green-600 mt-2">Status: Available for assignment</p>
                                    )}


                                    {/* Users cannot directly take tasks from here in current design; admins assign. */}
                                    {/* If users could 'request' a task, a button would go here. */}
                                </div>
                            );
                        })}
                    </div>
                ) : (
                    <p className="text-neutral">No tasks are currently listed or available.</p>
                )}
            </div>
          )}


        </main>
      </div>
      <footer className="text-center py-4 text-sm text-neutral border-t border-gray-200 mt-auto">
        <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. For demonstration purposes. Powered by AI.</p>
      </footer>
    </div>
  );
};
