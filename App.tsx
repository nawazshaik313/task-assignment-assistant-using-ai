
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import * as emailService from './src/utils/emailService';
import { validatePassword } from './src/utils/validation';
// import * as cloudDataService from './services/cloudDataService'; // No longer primary data source
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

  // Centralized API call helper
  const fetchData = useCallback(async <T,>(endpoint: string, options: RequestInit = {}, isLoginAttempt: boolean = false): Promise<T> => {
    clearMessages();
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          // Add Authorization header if tokens are used
          ...options.headers,
        },
        ...options,
      });

      if (!response.ok) {
        let errorData;
        try {
            errorData = await response.json();
        } catch (e) {
            // If response is not JSON, use text
            const textError = await response.text();
            errorData = { message: textError || `HTTP error ${response.status}` };
        }
        
        const errorMessage = errorData.message || errorData.error || `API Error: ${response.status} ${response.statusText}`;

        if (isLoginAttempt && (response.status === 401 || response.status === 400)) {
          throw new Error("Invalid email or password.");
        }
        console.error(`API Error for ${endpoint}:`, errorMessage, errorData);
        throw new Error(errorMessage);
      }

      if (response.status === 204 || response.headers.get("content-length") === "0") {
        return null as unknown as T; // For DELETE or other no-content responses
      }
      return response.json() as Promise<T>;
    } catch (err: any) {
      console.error(`Network or parsing error for ${endpoint}:`, err);
      setError(err.message || 'A network error occurred. Please try again.');
      throw err; // Re-throw to be caught by calling function if needed
    }
  }, [clearMessages]);


  // Load initial data from backend
  useEffect(() => {
    const loadAllData = async () => {
      setIsLoadingAppData(true);
      try {
        // Attempt to fetch current user first to see if a session exists
        try {
            const sessionUser = await fetchData<User>('/users/current', { method: 'GET' });
            if (sessionUser && sessionUser.id) {
                setCurrentUser(sessionUser);
            }
        } catch (e) {
            // No active session, or /users/current endpoint doesn't exist/failed
            console.info("No active session found or /users/current failed. User needs to log in.");
            setCurrentUser(null); // Ensure currentUser is null if fetch fails
        }
        // Fetch other data regardless of session, some might be public or needed for login context
        // If an endpoint requires auth and user is not logged in, fetchData will handle it
        // For now, let's assume these might be fetched after login or are public.
        // If they need auth, they should be fetched after currentUser is set.
        // For now, I'll fetch them, and if they fail due to auth, it's okay as they will be refetched/managed upon login.

        const [
          loadedUsers,
          loadedPendingUsers,
          loadedTasks,
          loadedPrograms,
          loadedAssignments,
          loadedAdminLogs,
        ] = await Promise.all([
          fetchData<User[]>('/users', { method: 'GET' }).catch(() => []),
          fetchData<PendingUser[]>('/pending-users', { method: 'GET' }).catch(() => []),
          fetchData<Task[]>('/tasks', { method: 'GET' }).catch(() => []),
          fetchData<Program[]>('/programs', { method: 'GET' }).catch(() => []),
          fetchData<Assignment[]>('/assignments', { method: 'GET' }).catch(() => []),
          fetchData<AdminLogEntry[]>('/admin-logs', { method: 'GET' }).catch(() => []),
        ]);

        setUsers(loadedUsers);
        setPendingUsers(loadedPendingUsers);
        setTasks(loadedTasks);
        setPrograms(loadedPrograms);
        setAssignments(loadedAssignments);
        setAdminLogs(loadedAdminLogs);
        
        console.log("Initial data fetched from backend.");

      } catch (err) {
        // This top-level catch might be redundant if fetchData handles errors by setting setError
        console.error("Critical error during initial data load:", err);
        setError("Failed to load initial application data. Please try refreshing.");
      } finally {
        setIsLoadingAppData(false);
      }
    };

    loadAllData();
  }, [fetchData]);


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
          // Fetch admin user details if needed, or assume valid if ID is present
          // For now, using local 'users' state for simplicity if already loaded
          const adminUser = users.find(u => u.id === refAdminIdFromHash && u.role === 'admin');
          setPreRegistrationForm(prev => ({
            ...initialPreRegistrationFormState, 
            referringAdminId: refAdminIdFromHash,
            referringAdminDisplayName: adminUser ? adminUser.displayName : 'Admin (Details from link)',
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

      if (newPage !== currentTopLevelPagePath) {
           navigateTo(newPage, targetParams);
      }
      _setCurrentPageInternal(newPage); 

      if (currentUser && currentUser.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${currentUser.id}`)) {
         setTimeout(() => {
            if (currentPage !== Page.Login && currentPage !== Page.PreRegistration) { 
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
  }, [currentUser, navigateTo, clearMessages, users, isLoadingAppData, _setCurrentPageInternal, currentPage]);


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


  const handleNewRegistration = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    const { name, email, password, confirmPassword, role } = newRegistrationForm;

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
      setError(passwordValidationResult.errors.join(' '));
      return;
    }

    // Client-side check (backend should also validate)
    if (users.some(u => u.email === email) || pendingUsers.some(pu => pu.email === email)) {
      setError("This email address is already registered or pending approval. Please use a different email or contact an administrator if you believe this is an error.");
      return;
    }
    
    // If no admin exists, the first registrant with role 'admin' (if UI allows)
    // or the backend handles first admin creation.
    // The UI logic for "first user becomes admin" is handled in the login page display.
    // Here, we just send what the form gathered.
    const registrationPayload = {
        displayName: name,
        email: email,
        password: password,
        role: users.some(u => u.role === 'admin') ? role : 'admin', // First user becomes admin if no admins exist.
        uniqueId: email, // Default uniqueId, backend might override or user updates later
        position: 'Default Position' // Default, user updates later
    };


    try {
      // Endpoint could be /users/register or /pending-users depending on backend flow
      // Assuming /pending-users for an approval flow
      const newPendingUser = await fetchData<PendingUser>('/pending-users', {
        method: 'POST',
        body: JSON.stringify(registrationPayload),
      });
      
      setPendingUsers(prev => [...prev, newPendingUser]);
      setSuccessMessage("Registration submitted successfully! Your account is pending administrator approval. You will be notified via email once it's active.");
      setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' }); 
      
      emailService.sendRegistrationPendingToUserEmail(newPendingUser.email, newPendingUser.displayName);
      const adminToNotify = getAdminToNotify();
      if (adminToNotify) {
        emailService.sendNewPendingRegistrationToAdminEmail(adminToNotify.email, adminToNotify.displayName, newPendingUser.displayName, newPendingUser.email);
      }
    } catch (err: any) {
       setError(err.message || "Failed to submit registration. Please check details or try again later.");
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
      setError(passwordValidationResult.errors.join(' '));
      return;
    }

    if (users.some(u => u.uniqueId === uniqueId || u.email === email) || pendingUsers.some(pu => pu.uniqueId === uniqueId || pu.email === email)) {
      setError("This System ID or Email is already registered or pending approval. Please choose a different one or contact an administrator.");
      return;
    }

    const pendingUserPayload = {
      uniqueId,
      displayName,
      email,
      password,
      role: 'user', // Pre-registration is always for 'user' role
      referringAdminId: referringAdminId || undefined,
      submissionDate: new Date().toISOString(), // Client-side, backend might override
    };

    try {
      const newPendingUser = await fetchData<PendingUser>('/pending-users', {
        method: 'POST',
        body: JSON.stringify(pendingUserPayload),
      });
      setPendingUsers(prev => [...prev, newPendingUser]);

      setSuccessMessage("Pre-registration submitted successfully! Your account is pending administrator approval. You will be notified via email.");
      setPreRegistrationForm(prev => ({ ...initialPreRegistrationFormState, referringAdminId: prev.referringAdminId, referringAdminDisplayName: prev.referringAdminDisplayName, isReferralLinkValid: prev.isReferralLinkValid }));
      
      const referringAdmin = users.find(u => u.id === referringAdminId);
      emailService.sendPreRegistrationSubmittedToUserEmail(newPendingUser.email, newPendingUser.displayName, referringAdmin?.displayName || 'the administrator');

      if (referringAdmin) {
        emailService.sendPreRegistrationNotificationToAdminEmail(referringAdmin.email, referringAdmin.displayName, newPendingUser.displayName, newPendingUser.uniqueId);
      } else {
          const generalAdmin = getAdminToNotify();
          if(generalAdmin) {
            emailService.sendPreRegistrationNotificationToAdminEmail(generalAdmin.email, generalAdmin.displayName, newPendingUser.displayName, newPendingUser.uniqueId);
          }
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
      }, true); // true indicates it's a login attempt for specific error handling

      setCurrentUser(loggedInUser);
      // Optionally, save to localStorage for persistence if backend doesn't use sessions robustly
      localStorage.setItem('currentUser', JSON.stringify(loggedInUser)); 

      // Fetch fresh data relevant to the logged-in user or admin
      setIsLoadingAppData(true); // Show loading while fetching context-specific data
      const [ updatedUsers, updatedPendingUsers, updatedTasks, updatedPrograms, updatedAssignments, updatedAdminLogs] = await Promise.all([
          fetchData<User[]>('/users', { method: 'GET' }).catch(() => users), // Keep old data on failure
          fetchData<PendingUser[]>('/pending-users', { method: 'GET' }).catch(() => pendingUsers),
          fetchData<Task[]>('/tasks', { method: 'GET' }).catch(() => tasks),
          fetchData<Program[]>('/programs', { method: 'GET' }).catch(() => programs),
          fetchData<Assignment[]>('/assignments', { method: 'GET' }).catch(() => assignments),
          fetchData<AdminLogEntry[]>('/admin-logs', { method: 'GET' }).catch(() => adminLogs),
      ]);
        setUsers(updatedUsers);
        setPendingUsers(updatedPendingUsers);
        setTasks(updatedTasks);
        setPrograms(updatedPrograms);
        setAssignments(updatedAssignments);
        setAdminLogs(updatedAdminLogs);
      setIsLoadingAppData(false);


      setSuccessMessage(`Welcome back, ${loggedInUser.displayName}!`);
      setNewLoginForm({ email: '', password: '' }); 

      const targetPage = loggedInUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
      navigateTo(targetPage);
      
      if (loggedInUser.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${loggedInUser.id}`)) {
         setShowUserTour(true);
      }

    } catch (err: any) {
      // setError is called by fetchData for API errors, but direct errors like "Invalid email or password" are set here
      setError(err.message || "Login failed. Please check your credentials.");
    }
  };

  useEffect(() => { // Restore currentUser from localStorage on mount if API fails or for quicker UI response
    const storedUser = localStorage.getItem('currentUser');
    if (storedUser && !currentUser) { // Only if API hasn't already set it
      try {
        const parsedUser = JSON.parse(storedUser);
        setCurrentUser(parsedUser);
      } catch (e) {
        localStorage.removeItem('currentUser');
      }
    }
  }, [currentUser]); // Added currentUser to dependency array

  const handleLogout = async () => {
    clearMessages();
    try {
      await fetchData<void>('/users/logout', { method: 'POST' });
      setSuccessMessage("You have been logged out successfully.");
    } catch (err: any) {
      // Even if logout API fails, log out on client
      console.warn("Logout API call failed or was not configured, logging out client-side:", err.message);
      setInfoMessage("Logged out from this device. Server session might still be active if API failed.");
    } finally {
      setCurrentUser(null);
      localStorage.removeItem('currentUser'); // Clear stored user
      navigateTo(Page.Login);
    }
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
    
    // Client-side check if uniqueId is taken by another user. Backend should also validate.
    if (users.some(u => u.uniqueId === uniqueId && u.id !== currentUser.id)) {
        setError("This System ID is already taken. Please choose another.");
        return;
    }
    
    let passwordToUpdate = undefined; // Only send password if it's being changed
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
        passwordToUpdate = password;
    }

    const updatedProfileData: Partial<User> = {
      uniqueId,
      displayName,
      position,
      userInterests: userInterests || '',
      phone: phone || '',
      notificationPreference: notificationPreference || 'none',
      ...(passwordToUpdate && { password: passwordToUpdate }), // Add password only if it's being updated
    };
    
    try {
      const updatedUser = await fetchData<User>(`/users/${currentUser.id}`, {
        method: 'PUT',
        body: JSON.stringify(updatedProfileData),
      });
      
      setUsers(prevUsers => prevUsers.map(u => u.id === currentUser.id ? updatedUser : u));
      setCurrentUser(updatedUser); 
      localStorage.setItem('currentUser', JSON.stringify(updatedUser));

      setSuccessMessage("Profile updated successfully!");
      setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' })); 
      addAdminLogEntry(`User profile updated for ${updatedUser.displayName} (ID: ${updatedUser.uniqueId}).`);
    } catch (err: any) {
      setError(err.message || "Failed to update profile.");
    }
  };
  
  const handleAdminUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!editingUserId) return;

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
    
    let passwordToUpdate = undefined;
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
        passwordToUpdate = password;
    }

    const userUpdatePayload: Partial<User> = {
      email,
      uniqueId,
      displayName,
      position,
      userInterests: userInterests || '',
      phone: phone || '',
      notificationPreference: notificationPreference || 'none',
      role,
      ...(passwordToUpdate && { password: passwordToUpdate }),
    };

    try {
      const updatedUser = await fetchData<User>(`/users/${editingUserId}`, {
        method: 'PUT',
        body: JSON.stringify(userUpdatePayload),
      });
      
      setUsers(prevUsers => prevUsers.map(u => u.id === editingUserId ? updatedUser : u));
      
      if(currentUser && currentUser.id === editingUserId) { 
          setCurrentUser(updatedUser);
          localStorage.setItem('currentUser', JSON.stringify(updatedUser));
      }

      setSuccessMessage(`User ${updatedUser.displayName} updated successfully!`);
      setEditingUserId(null);
      setUserForm(initialUserFormData); 
      addAdminLogEntry(`Admin updated user profile for ${updatedUser.displayName} (ID: ${updatedUser.uniqueId}). Role set to ${role}.`);
      navigateTo(Page.UserManagement);
    } catch (err:any) {
      setError(err.message || "Failed to update user.");
    }
  };


  const handleCreateUserByAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    const { email, uniqueId, displayName, position, userInterests, phone, notificationPreference, role, password, confirmPassword } = userForm;

    if (!email.trim() || !uniqueId.trim() || !displayName.trim() || !position.trim() || !password.trim() || !confirmPassword.trim()) {
        setError("Email, System ID, Display Name, Position, Password, and Confirm Password are required.");
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
    if (users.some(u => u.email === email || u.uniqueId === uniqueId) || pendingUsers.some(pu => pu.email === email || pu.uniqueId === uniqueId)) {
        setError("This Email or System ID is already in use or pending approval. Please choose a different one.");
        return;
    }

    const newUserPayload: Omit<User, 'id'> = { // Backend will assign ID
      email,
      uniqueId,
      password,
      role,
      displayName,
      position,
      userInterests: userInterests || '',
      phone: phone || '',
      notificationPreference: notificationPreference || 'none',
    };

    try {
      const createdUser = await fetchData<User>(`/users`, {
        method: 'POST',
        body: JSON.stringify(newUserPayload),
      });
      setUsers(prevUsers => [...prevUsers, createdUser]);
      setSuccessMessage(`User ${displayName} created successfully!`);
      setUserForm(initialUserFormData); 
      emailService.sendWelcomeRegistrationEmail(createdUser.email, createdUser.displayName, createdUser.role);
      addAdminLogEntry(`Admin created new user: ${createdUser.displayName} (ID: ${createdUser.uniqueId}), Role: ${createdUser.role}.`);
      navigateTo(Page.UserManagement);
    } catch (err:any) {
      setError(err.message || "Failed to create user.");
    }
  };
  
  const handleApprovePendingUser = async () => {
    if (!approvingPendingUser || !currentUser || currentUser.role !== 'admin') {
      setError("Approval failed: Invalid operation or permissions.");
      return;
    }
    clearMessages();

    const { id: pendingId, uniqueId, displayName, email, password, role, referringAdminId } = approvingPendingUser;

    // Data from the form, allowing admin to override if necessary
    const finalUserData = {
        email: userForm.email,
        uniqueId: userForm.uniqueId,
        displayName: userForm.displayName,
        position: userForm.position,
        userInterests: userForm.userInterests,
        phone: userForm.phone,
        notificationPreference: userForm.notificationPreference,
        role: userForm.role,
        password: password, // Use the password from the pending user submission
        referringAdminId: referringAdminId || currentUser.id,
    };


    try {
      // This might be a POST to /users, or a specific /pending-users/:id/approve endpoint
      // Assuming POST to /users for creating an active user from pending details
      const newUser = await fetchData<User>('/users/approve-pending', { // Or just /users if backend handles this as creation
        method: 'POST',
        body: JSON.stringify({ ...finalUserData, pendingId: pendingId }), // Send pendingId for backend to locate and delete
      });
      
      setUsers(prevUsers => [...prevUsers, newUser]);
      setPendingUsers(prevPending => prevPending.filter(pu => pu.id !== pendingId));
      
      setApprovingPendingUser(null); 
      setUserForm(initialUserFormData);
      setSuccessMessage(`User ${newUser.displayName} approved and account activated!`);
      
      emailService.sendAccountActivatedByAdminEmail(newUser.email, newUser.displayName, currentUser.displayName);
      addAdminLogEntry(`Admin ${currentUser.displayName} approved pending user: ${newUser.displayName} (ID: ${newUser.uniqueId}).`);

    } catch (err:any) {
      setError(err.message || "Failed to approve user.");
    }
  };

  const handleRejectPendingUser = async (pendingUserId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    clearMessages();
    try {
      const userToReject = pendingUsers.find(pu => pu.id === pendingUserId);
      await fetchData<void>(`/pending-users/${pendingUserId}`, { method: 'DELETE' });
      
      setPendingUsers(prevPending => prevPending.filter(pu => pu.id !== pendingUserId));
      setSuccessMessage(`Pending registration for ${userToReject?.displayName || 'user'} rejected.`);
      addAdminLogEntry(`Admin ${currentUser.displayName} rejected pending registration for ${userToReject?.displayName || 'user (ID: ' + pendingUserId + ')'}.`);
    } catch (err:any) {
        setError(err.message || "Failed to reject pending user registration.");
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    if (currentUser.id === userId) {
        setError("Admins cannot delete their own accounts through this action.");
        return;
    }
    clearMessages();
    try {
      const userToDelete = users.find(u => u.id === userId);
      await fetchData<void>(`/users/${userId}`, { method: 'DELETE' });
      
      setUsers(prevUsers => prevUsers.filter(u => u.id !== userId));
      // Also remove any assignments for this user locally, backend might do this with cascading delete
      setAssignments(prevAssignments => prevAssignments.filter(a => a.personId !== userId));
      
      setSuccessMessage(`User ${userToDelete?.displayName || 'user'} and their assignments deleted successfully.`);
      addAdminLogEntry(`Admin ${currentUser.displayName} deleted user: ${userToDelete?.displayName || 'user (ID: ' + userId + ')'}.`);
    } catch (err:any) {
      setError(err.message || "Failed to delete user.");
    }
  };

  const handleGeneratePreRegistrationLink = () => {
    if (!currentUser || currentUser.role !== 'admin') {
      setError("Only admins can generate pre-registration links.");
      return;
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
    e.preventDefault();
    clearMessages();
    if (!programForm.name.trim() || !programForm.description.trim()) {
      setError("Program name and description are required.");
      return;
    }
    try {
      const newProgram = await fetchData<Program>('/programs', {
        method: 'POST',
        body: JSON.stringify(programForm),
      });
      setPrograms(prev => [...prev, newProgram]);
      setSuccessMessage("Program created successfully!");
      setProgramForm({ name: '', description: '' }); 
      if(currentUser) addAdminLogEntry(`Admin ${currentUser.displayName} created program: ${newProgram.name}.`);
    } catch (err:any) {
      setError(err.message || "Failed to create program.");
    }
  };
  
  const handleDeleteProgram = async (programId: string) => {
    clearMessages();
    try {
      const programToDelete = programs.find(p => p.id === programId);
      await fetchData<void>(`/programs/${programId}`, { method: 'DELETE' });
      
      setPrograms(prev => prev.filter(p => p.id !== programId));
      // Tasks associated with this program might need their programId cleared on backend
      // For client-side, we can update tasks if backend doesn't handle unlinking.
      setTasks(prevTasks => prevTasks.map(t => t.programId === programId ? { ...t, programId: undefined, programName: undefined } : t));
      
      setSuccessMessage(`Program "${programToDelete?.name}" deleted and tasks unlinked.`);
      if(currentUser) addAdminLogEntry(`Admin ${currentUser.displayName} deleted program: ${programToDelete?.name}.`);
    } catch (err:any) {
      setError(err.message || "Failed to delete program.");
    }
  };


  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!taskForm.title.trim() || !taskForm.description.trim() || !taskForm.requiredSkills.trim()) {
      setError("Task title, description, and required skills are required.");
      return;
    }
    const associatedProgram = programs.find(p => p.id === taskForm.programId);
    const taskPayload = {
      ...taskForm,
      programName: associatedProgram?.name, // May not be needed if backend resolves it
      deadline: taskForm.deadline ? new Date(taskForm.deadline).toISOString().split('T')[0] : undefined,
    };

    try {
      const newTask = await fetchData<Task>('/tasks', {
        method: 'POST',
        body: JSON.stringify(taskPayload),
      });
      setTasks(prev => [...prev, newTask]);
      setSuccessMessage("Task created successfully!");
      setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' }); 
      if(currentUser) addAdminLogEntry(`Admin ${currentUser.displayName} created task: ${newTask.title}.`);
    } catch (err:any) {
      setError(err.message || "Failed to create task.");
    }
  };

  const handleDeleteTask = async (taskId: string) => {
    clearMessages();
    try {
      const taskToDelete = tasks.find(t => t.id === taskId);
      await fetchData<void>(`/tasks/${taskId}`, { method: 'DELETE' });

      setTasks(prev => prev.filter(t => t.id !== taskId));
      // Also delete any assignments associated with this task locally, backend might cascade
      setAssignments(prevAssignments => prevAssignments.filter(a => a.taskId !== taskId));
      
      setSuccessMessage(`Task "${taskToDelete?.title}" and its assignments deleted.`);
      if(currentUser) addAdminLogEntry(`Admin ${currentUser.displayName} deleted task: ${taskToDelete?.title}.`);
    } catch (err:any) {
      setError(err.message || "Failed to delete task.");
    }
  };
  
  const handleGetAssignmentSuggestion = async () => {
    if (!selectedTaskForAssignment) {
      setError("Please select a task first.");
      return;
    }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    if (!task) {
      setError("Selected task not found.");
      return;
    }
    
    const usersEligibleForThisTask = users.filter(u => u.role === 'user' && !assignments.some(a => a.taskId === task.id && a.personId === u.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user')));

    setIsLoadingSuggestion(true);
    setError(null); // Clear previous errors specifically for suggestion
    setAssignmentSuggestion(null);
    try {
      // getAssignmentSuggestion is a call to Gemini, not our backend. Stays as is.
      const suggestion = await getAssignmentSuggestion(task, usersEligibleForThisTask, programs, assignments);
      setAssignmentSuggestion(suggestion);
      if(suggestion && suggestion.suggestedPersonName){
        setInfoMessage(`AI Suggestion: ${suggestion.suggestedPersonName}. Justification: ${suggestion.justification}`);
      } else if (suggestion && suggestion.justification) {
        setInfoMessage(`AI: ${suggestion.justification}`);
      } else {
        setInfoMessage("AI could not provide a suggestion or no suitable person was found.");
      }
      if(currentUser) addAdminLogEntry(`Admin ${currentUser.displayName} requested AI assignment suggestion for task: ${task.title}.`);
    } catch (err: any) {
      console.error("Error getting AI suggestion:", err);
      setError(`AI suggestion failed: ${err.message || "Unknown error"}`);
    } finally {
      setIsLoadingSuggestion(false);
    }
  };

  const handleAssignTask = async (e: React.FormEvent, suggestedPersonDisplayName?: string | null) => {
    e.preventDefault();
    clearMessages();
    const personIdToAssign = (e.target as HTMLFormElement).assignPerson.value;
    const specificDeadline = (e.target as HTMLFormElement).specificDeadline?.value;

    if (!selectedTaskForAssignment || !personIdToAssign) {
      setError("Task and person must be selected.");
      return;
    }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    const person = users.find(u => u.id === personIdToAssign);

    if (!task || !person) {
      setError("Selected task or person not found.");
      return;
    }

    if (assignments.some(a => a.taskId === task.id && a.personId === person.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))) {
      setError(`${person.displayName} is already assigned this task or it's pending their acceptance.`);
      return;
    }
    
    const justification = suggestedPersonDisplayName === person.displayName && assignmentSuggestion?.justification 
        ? assignmentSuggestion.justification 
        : 'Manually assigned by admin.';

    const assignmentPayload = {
      taskId: task.id,
      personId: person.id,
      taskTitle: task.title, // Denormalized, backend might handle this
      personName: person.displayName, // Denormalized
      justification,
      status: 'pending_acceptance' as AssignmentStatus,
      deadline: specificDeadline || task.deadline,
    };

    try {
      // Backend should return the created assignment, including its own ID if applicable
      const newAssignment = await fetchData<Assignment>('/assignments', {
        method: 'POST',
        body: JSON.stringify(assignmentPayload),
      });
      setAssignments(prev => [...prev, newAssignment]); // Use returned assignment
      setSuccessMessage(`Task "${task.title}" assigned to ${person.displayName}.`);
      setSelectedTaskForAssignment(null);
      setAssignmentSuggestion(null);
      setAssignmentForm({ specificDeadline: '' });
      
      if (person.notificationPreference === 'email' && person.email) {
        emailService.sendTaskProposalEmail(person.email, person.displayName, task.title, currentUser?.displayName || "Admin", newAssignment.deadline);
      }
      if(currentUser) addAdminLogEntry(`Admin ${currentUser.displayName} assigned task "${task.title}" to ${person.displayName}. Justification: ${justification}`);

    } catch (err:any) {
      setError(err.message || "Failed to assign task.");
    }
  };

  const updateAssignmentStatus = async (taskId: string, personId: string, newStatus: AssignmentStatus, additionalData: Record<string, any> = {}) => {
    if (!currentUser && newStatus !== 'pending_acceptance') return; // currentUser check mostly for user actions
    clearMessages();

    const assignmentToUpdate = assignments.find(a => a.taskId === taskId && a.personId === (personId || currentUser?.id));
    if (!assignmentToUpdate) {
        setError("Assignment not found.");
        return;
    }
    // Assuming assignments get an 'id' from the backend. If not, endpoint must identify by taskId/personId.
    // Let's assume for now that assignments returned from backend *do* have an 'id'.
    // If your Assignment type doesn't have an `id` from the backend, this needs a different endpoint.
    // Let's try PATCH /assignments/tasks/:taskId/users/:personId
    const endpoint = `/assignments/tasks/${taskId}/users/${personId || currentUser!.id}`;
    const payload = { status: newStatus, ...additionalData };


    try {
      const updatedAssignment = await fetchData<Assignment>(endpoint, {
        method: 'PATCH', // Or PUT if replacing the whole resource
        body: JSON.stringify(payload),
      });
      setAssignments(prev => prev.map(a => (a.taskId === taskId && a.personId === (personId || currentUser?.id)) ? updatedAssignment : a));
      return updatedAssignment;
    } catch (err:any) {
      setError(err.message || `Failed to update task status to ${newStatus}.`);
      throw err; // Re-throw for calling function to handle
    }
  };


  const handleUserAcceptTask = async (taskId: string) => {
    if (!currentUser) return;
    try {
        const updatedAssignment = await updateAssignmentStatus(taskId, currentUser.id, 'accepted_by_user');
        if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" accepted.`);
            const adminToNotify = getAdminToNotify(users.find(u => u.id === currentUser.referringAdminId)?.id);
            if (adminToNotify && adminToNotify.notificationPreference === 'email' && adminToNotify.email) {
                emailService.sendTaskStatusUpdateToAdminEmail(adminToNotify.email, adminToNotify.displayName, currentUser.displayName, updatedAssignment.taskTitle, "accepted");
            }
        }
    } catch (e) { /* error already set by updateAssignmentStatus */ }
  };

  const handleUserDeclineTask = async (taskId: string) => {
    if (!currentUser) return;
     try {
        const updatedAssignment = await updateAssignmentStatus(taskId, currentUser.id, 'declined_by_user');
         if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" declined.`);
            const adminToNotify = getAdminToNotify(users.find(u => u.id === currentUser.referringAdminId)?.id);
            if (adminToNotify && adminToNotify.notificationPreference === 'email' && adminToNotify.email) {
                emailService.sendTaskStatusUpdateToAdminEmail(adminToNotify.email, adminToNotify.displayName, currentUser.displayName, updatedAssignment.taskTitle, "declined");
            }
        }
    } catch (e) { /* error already set by updateAssignmentStatus */ }
  };

  const handleUserSubmitTask = async (taskId: string, delayReason?: string) => {
    if (!currentUser) return;
    const assignment = assignments.find(a => a.taskId === taskId && a.personId === currentUser.id && a.status === 'accepted_by_user');
    if (!assignment) {
      setError("Task not found, not accepted, or already submitted.");
      return;
    }
    
    const submissionDate = new Date();
    let newStatus: AssignmentStatus = 'submitted_on_time';
    if (assignment.deadline && submissionDate > new Date(assignment.deadline)) {
      newStatus = 'submitted_late';
      if (!delayReason && assignmentToSubmitDelayReason === taskId) {
        setError("A reason is required for late submission.");
        return; 
      }
    }
    
    const additionalData: any = { userSubmissionDate: submissionDate.toISOString() };
    if (newStatus === 'submitted_late') {
      additionalData.userDelayReason = delayReason || userSubmissionDelayReason;
    }

    try {
        const updatedAssignment = await updateAssignmentStatus(taskId, currentUser.id, newStatus, additionalData);
        if (updatedAssignment) {
            setSuccessMessage(`Task "${updatedAssignment.taskTitle}" submitted successfully.`);
            setUserSubmissionDelayReason(''); 
            setAssignmentToSubmitDelayReason(null); 

            const adminToNotify = getAdminToNotify(users.find(u => u.id === currentUser.referringAdminId)?.id);
            if (adminToNotify && adminToNotify.notificationPreference === 'email' && adminToNotify.email) {
                emailService.sendTaskStatusUpdateToAdminEmail(adminToNotify.email, adminToNotify.displayName, currentUser.displayName, updatedAssignment.taskTitle, `submitted (${newStatus.replace(/_/g, ' ')})`);
            }
        }
    } catch (e) { /* error already set by updateAssignmentStatus */ }
  };

  const handleAdminApproveTaskCompletion = async (taskId: string, personId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
     try {
        const updatedAssignment = await updateAssignmentStatus(taskId, personId, 'completed_admin_approved');
        if (updatedAssignment) {
            const assignedUser = users.find(u => u.id === personId);
            setSuccessMessage(`Completion of task "${updatedAssignment.taskTitle}" by ${assignedUser?.displayName || 'user'} approved.`);
            
            if (assignedUser && assignedUser.notificationPreference === 'email' && assignedUser.email) {
                emailService.sendTaskCompletionApprovedToUserEmail(assignedUser.email, assignedUser.displayName, updatedAssignment.taskTitle, currentUser.displayName);
            }
            addAdminLogEntry(`Admin ${currentUser.displayName} approved task completion for "${updatedAssignment.taskTitle}" by ${assignedUser?.displayName}.`);
        }
    } catch (e) { /* error already set by updateAssignmentStatus */ }
  };

  const addAdminLogEntry = async (logText: string, imagePreviewUrl?: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    const logPayload = {
      adminId: currentUser.id, // Backend might infer from session
      adminDisplayName: currentUser.displayName, // Denormalized
      timestamp: new Date().toISOString(), // Backend might set this
      logText,
      imagePreviewUrl
    };
    try {
        const newLog = await fetchData<AdminLogEntry>('/admin-logs', {
            method: 'POST',
            body: JSON.stringify(logPayload),
        });
        setAdminLogs(prevLogs => [newLog, ...prevLogs]); // Prepend new log
    } catch (error) {
        console.error("Failed to save admin log via API:", error);
        // setError("Failed to record admin log entry."); // Potentially too noisy for admin
    }
  };

  const handleAdminLogSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminLogText.trim() && !adminLogImageFile) {
        setError("Log text or an image is required to submit an admin log.");
        return;
    }
    setIsSubmittingLog(true);
    clearMessages();

    let imagePreviewUrl: string | undefined = undefined;
    if (adminLogImageFile) {
        // For simplicity, continue using base64 for preview.
        // A real backend might need FormData for actual file upload.
        try {
            imagePreviewUrl = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = () => resolve(reader.result as string);
                reader.onerror = reject;
                reader.readAsDataURL(adminLogImageFile);
            });
        } catch (error) {
            console.error("Error converting image to data URL:", error);
            setError("Failed to process image file. Please try again without an image or use a different image.");
            setIsSubmittingLog(false);
            return;
        }
    }

    try {
        await addAdminLogEntry(adminLogText || `Image log entry by ${currentUser?.displayName}`, imagePreviewUrl);
        setSuccessMessage("Admin log entry added.");
        setAdminLogText('');
        setAdminLogImageFile(null);
        const fileInput = document.getElementById('adminLogImage') as HTMLInputElement;
        if (fileInput) fileInput.value = ''; 
    } catch (err: any) {
        // Error handled by addAdminLogEntry or fetchData
    } finally {
        setIsSubmittingLog(false);
    }
  };


  const handleForgotPassword = async () => {
    clearMessages();
    const emailToReset = newLoginForm.email;
    if (!emailToReset || !/\S+@\S+\.\S+/.test(emailToReset)) {
      setError("Please enter a valid email address to reset password.");
      return;
    }

    try {
      // Backend endpoint for initiating password reset
      await fetchData<void>('/users/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ email: emailToReset }),
      });
      setInfoMessage(`If an account exists for ${emailToReset}, a password reset link has been sent.`);
      // No direct admin log here, backend should log this action.
    } catch (err: any) {
      // Generic message to prevent user enumeration, even on error
      setInfoMessage(`If an account exists for ${emailToReset}, a password reset link has been sent.`);
      console.error("Forgot password API call failed:", err);
    }
  };
  
  const handleCompleteUserTour = (completed: boolean) => {
    setShowUserTour(false);
    if (currentUser) {
        localStorage.setItem(`hasCompletedUserTour_${currentUser.id}`, 'true');
        if (completed) {
            setSuccessMessage("Great! You've completed the tour. Feel free to explore.");
        } else {
            setInfoMessage("Tour skipped. You can always find help or ask your admin if you have questions.");
        }
    }
  };


  // UI Component Rendering Logic
  if (isLoadingAppData && !currentUser) { // Show full page loader only if no user and still loading initial data
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-bground p-4">
        <LoadingSpinner />
        <p className="mt-4 text-textlight">Loading application data...</p>
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
                <AuthFormInput
                  type="email"
                  id="loginEmail"
                  aria-label="Email for login"
                  placeholder="you@example.com"
                  value={newLoginForm.email}
                  onChange={(e) => setNewLoginForm({ ...newLoginForm, email: e.target.value })}
                  required
                  autoComplete="email"
                />
              </div>
              <div>
                <label htmlFor="loginPassword" className="block text-sm font-medium text-textlight">Password</label>
                <AuthFormInput
                  type="password"
                  id="loginPassword"
                  aria-label="Password for login"
                  placeholder="Enter your password"
                  value={newLoginForm.password}
                  onChange={(e) => setNewLoginForm({ ...newLoginForm, password: e.target.value })}
                  required
                  autoComplete="current-password"
                />
              </div>
              <button 
                type="submit" 
                className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
              >
                Sign In
              </button>
              <div className="text-sm text-center">
                <button
                  type="button"
                  onClick={handleForgotPassword}
                  className="font-medium text-authLink hover:underline"
                >
                  Forgot password?
                </button>
              </div>
            </form>
          ) : (
            <form onSubmit={handleNewRegistration} className="space-y-5">
              <h3 className="text-xl font-semibold text-textlight mb-4">Register New Account</h3>
              <div>
                <label htmlFor="regName" className="block text-sm font-medium text-textlight">Full Name</label>
                <AuthFormInput
                  type="text"
                  id="regName"
                  aria-label="Full name for registration"
                  placeholder="Your Full Name"
                  value={newRegistrationForm.name}
                  onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, name: e.target.value })}
                  required
                  autoComplete="name"
                />
              </div>
              <div>
                <label htmlFor="regEmail" className="block text-sm font-medium text-textlight">Email Address</label>
                <AuthFormInput
                  type="email"
                  id="regEmail"
                  aria-label="Email for registration"
                  placeholder="you@example.com"
                  value={newRegistrationForm.email}
                  onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, email: e.target.value })}
                  required
                  autoComplete="email"
                />
              </div>
              <div>
                <label htmlFor="regPassword" className="block text-sm font-medium text-textlight">Password</label>
                <AuthFormInput
                  type="password"
                  id="regPassword"
                  aria-label="Password for registration"
                  placeholder="Create a password"
                  value={newRegistrationForm.password}
                  onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, password: e.target.value })}
                  required
                  autoComplete="new-password"
                  aria-describedby="passwordHelpReg"
                />
                <p id="passwordHelpReg" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
              </div>
              <div>
                <label htmlFor="regConfirmPassword" className="block text-sm font-medium text-textlight">Confirm Password</label>
                <AuthFormInput
                  type="password"
                  id="regConfirmPassword"
                  aria-label="Confirm password for registration"
                  placeholder="Confirm your password"
                  value={newRegistrationForm.confirmPassword}
                  onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, confirmPassword: e.target.value })}
                  required
                  autoComplete="new-password"
                />
              </div>
              {users.some(u => u.role === 'admin') && ( 
                <div>
                  <label htmlFor="regRole" className="block text-sm font-medium text-textlight">Role</label>
                  <AuthFormSelect
                    id="regRole"
                    aria-label="Role for registration"
                    value={newRegistrationForm.role}
                    onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, role: e.target.value as Role })}
                  >
                    <option value="user">User</option>
                  </AuthFormSelect>
                  <p className="mt-1 text-xs text-neutral">General registration is for 'User' role. Admins are typically pre-configured or added by existing admins.</p>
                </div>
              )}
              <button 
                type="submit" 
                className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
              >
                Register
              </button>
            </form>
          )}
          <p className="text-center text-sm text-textlight mt-6">
            {authView === 'login' ? "Don't have an account?" : "Already have an account?"}{' '}
            <button
              type="button"
              onClick={() => { clearMessages(); setAuthView(authView === 'login' ? 'register' : 'login'); }}
              className="font-medium text-authLink hover:underline"
            >
              {authView === 'login' ? 'Register here' : 'Sign in here'}
            </button>
          </p>
           { !users.some(u => u.role === 'admin') && authView === 'login' && !isLoadingAppData && (
            <div className="mt-6 p-4 bg-yellow-50 border border-yellow-300 rounded-md">
              <p className="text-sm text-yellow-700">
                <strong className="font-bold">First-time Setup:</strong> No admin accounts found. The first registered user will become an administrator.
                Please <button type="button" onClick={() => { clearMessages(); setAuthView('register'); setNewRegistrationForm(f => ({...f, role: 'admin'})); }} className="font-medium text-authLink hover:underline">register as Admin</button> to initialize the system.
              </p>
            </div>
          )}
        </div>
        <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by SHAIK MOHAMMED NAWAZ.</p>
        </footer>
      </div>
    );
  }
  
  const NavLink: React.FC<{ page: Page; children: React.ReactNode; icon?: React.ReactNode; current: Page, params?: Record<string, string> }> = ({ page, children, icon, current, params }) => (
    <button
      onClick={() => navigateTo(page, params)}
      className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors duration-150 ease-in-out
                  ${current === page ? 'bg-primary text-white shadow-md' : 'text-textlight hover:bg-bground hover:text-primary'}`}
      aria-current={current === page ? 'page' : undefined}
    >
      {icon && <span className="flex-shrink-0 w-5 h-5">{icon}</span>}
      <span>{children}</span>
    </button>
  );

  return (
    <div className="flex h-screen bg-bground main-app-scope">
       {isLoadingAppData && <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-50 flex items-center justify-center z-50"><LoadingSpinner /><p className="text-white ml-2">Loading data...</p></div>}
       {showUserTour && currentUser && <UserTour user={currentUser} onClose={handleCompleteUserTour} />}
      <aside className="w-64 bg-surface text-textlight flex flex-col shadow-lg overflow-y-auto">
        <div className="p-4 border-b border-gray-200">
          <h1 className="text-2xl font-semibold text-primary flex items-center">
            <BriefcaseIcon className="w-7 h-7 mr-2 text-secondary"/> TAA
          </h1>
           <p className="text-xs text-neutral mt-1">Task Assignment Assistant</p>
        </div>
        <nav className="flex-grow p-3 space-y-1.5">
          {currentUser.role === 'admin' && (
            <>
              <NavLink page={Page.Dashboard} current={currentPage} icon={<LightBulbIcon />}>Dashboard</NavLink>
              <NavLink page={Page.UserManagement} current={currentPage} icon={<UsersIcon />}>User Management</NavLink>
              <NavLink page={Page.ManagePrograms} current={currentPage} icon={<ClipboardListIcon />}>Manage Programs</NavLink>
              <NavLink page={Page.ManageTasks} current={currentPage} icon={<CheckCircleIcon />}>Manage Tasks</NavLink>
              <NavLink page={Page.AssignWork} current={currentPage} icon={<PlusCircleIcon />}>Assign Work</NavLink>
            </>
          )}
          <NavLink page={Page.ViewAssignments} current={currentPage} icon={<ClipboardListIcon />}>My Assignments</NavLink>
          <NavLink page={Page.ViewTasks} current={currentPage} icon={<CheckCircleIcon />}>Available Tasks</NavLink>
          <NavLink page={Page.UserProfile} current={currentPage} icon={<UserCircleIcon />}>My Profile</NavLink>
        </nav>
        <div className="p-4 mt-auto border-t border-gray-200">
            <div className="flex items-center mb-3">
                <UserCircleIcon className="w-8 h-8 mr-2 text-neutral" />
                <div>
                    <p className="text-sm font-medium text-textlight">{currentUser.displayName}</p>
                    <p className="text-xs text-neutral capitalize">{currentUser.role} / {currentUser.position.substring(0,20)}{currentUser.position.length > 20 ? '...' : ''}</p>
                </div>
            </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-danger hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger transition-colors"
            aria-label="Logout"
          >
            <LogoutIcon className="w-5 h-5 mr-2" />
            Logout
          </button>
        </div>
      </aside>

      <main className="flex-1 p-6 overflow-y-auto">
        <UIMessages />
        
        {currentPage === Page.Dashboard && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-semibold text-primary mb-6">Admin Dashboard</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="bg-surface p-5 rounded-lg shadow-md">
                    <h3 className="text-xl font-medium text-secondary mb-2">Users</h3>
                    <p className="text-3xl font-bold text-textlight">{users.length}</p>
                    <p className="text-sm text-neutral">Total active users</p>
                </div>
                <div className="bg-surface p-5 rounded-lg shadow-md">
                    <h3 className="text-xl font-medium text-secondary mb-2">Pending Approvals</h3>
                    <p className="text-3xl font-bold text-textlight">{pendingUsers.length}</p>
                    <p className="text-sm text-neutral">Users awaiting approval</p>
                </div>
                <div className="bg-surface p-5 rounded-lg shadow-md">
                    <h3 className="text-xl font-medium text-secondary mb-2">Tasks</h3>
                    <p className="text-3xl font-bold text-textlight">{tasks.length}</p>
                    <p className="text-sm text-neutral">Total defined tasks</p>
                </div>
                <div className="bg-surface p-5 rounded-lg shadow-md">
                    <h3 className="text-xl font-medium text-secondary mb-2">Programs</h3>
                    <p className="text-3xl font-bold text-textlight">{programs.length}</p>
                    <p className="text-sm text-neutral">Total programs</p>
                </div>
                 <div className="bg-surface p-5 rounded-lg shadow-md">
                    <h3 className="text-xl font-medium text-secondary mb-2">Active Assignments</h3>
                    <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'accepted_by_user' || a.status === 'pending_acceptance').length}</p>
                    <p className="text-sm text-neutral">Tasks currently assigned</p>
                </div>
                 <div className="bg-surface p-5 rounded-lg shadow-md">
                    <h3 className="text-xl font-medium text-secondary mb-2">Completed Tasks</h3>
                    <p className="text-3xl font-bold text-textlight">{assignments.filter(a => a.status === 'completed_admin_approved').length}</p>
                    <p className="text-sm text-neutral">Successfully finished tasks</p>
                </div>
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-primary mb-4">Admin Log Entry</h3>
              <form onSubmit={handleAdminLogSubmit} className="space-y-4">
                <FormTextarea
                  label="Log Message"
                  id="adminLogText"
                  value={adminLogText}
                  onChange={(e) => setAdminLogText(e.target.value)}
                  placeholder="Enter log details (e.g., manual system change, important observation)"
                />
                <div>
                    <label htmlFor="adminLogImage" className="block text-sm font-medium text-textlight">Attach Image (Optional)</label>
                    <input 
                        type="file" 
                        id="adminLogImage"
                        aria-label="Attach image to admin log" 
                        accept="image/*"
                        onChange={(e) => setAdminLogImageFile(e.target.files ? e.target.files[0] : null)}
                        className="mt-1 block w-full text-sm text-neutral file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-primary file:text-white hover:file:bg-blue-600"
                    />
                </div>
                <button type="submit" className="btn-primary" disabled={isSubmittingLog}>
                  {isSubmittingLog ? <LoadingSpinner/> : 'Add Log Entry'}
                </button>
              </form>
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-primary mb-4">Recent Admin Logs</h3>
                {adminLogs.length === 0 ? (
                    <p className="text-neutral">No admin logs recorded yet.</p>
                ) : (
                    <ul className="space-y-3 max-h-96 overflow-y-auto">
                    {adminLogs.slice(0, 10).map(log => (
                        <li key={log.id} className="p-3 bg-bground rounded-md shadow-sm">
                        <p className="text-sm text-textlight"><strong className="font-medium">{log.adminDisplayName}</strong>: {log.logText}</p>
                        <p className="text-xs text-neutral mt-1">{new Date(log.timestamp).toLocaleString()}</p>
                        {log.imagePreviewUrl && (
                            <div className="mt-2">
                                <img src={log.imagePreviewUrl} alt="Log attachment preview" className="max-h-40 max-w-xs rounded border border-neutral"/>
                            </div>
                        )}
                        </li>
                    ))}
                    </ul>
                )}
            </div>
          </div>
        )}

        {currentPage === Page.UserProfile && (
          <div className="max-w-2xl mx-auto bg-surface p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Profile</h2>
            <form onSubmit={handleUpdateProfile} className="space-y-4">
              <FormInput label="Email (Cannot be changed)" id="profileEmail" type="email" value={userForm.email} readOnly disabled 
                description="Your login email address. This cannot be changed here."
              />
              <FormInput label="System ID / Username" id="profileUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required 
                description="Your unique identifier within the system."
              />
              <FormInput label="Display Name" id="profileDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
              <FormInput label="Position / Role Title" id="profilePosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required 
                 description="Your job title or primary role (e.g., 'Software Developer', 'Event Coordinator')."
              />
              <FormTextarea label="My Skills & Interests" id="profileUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} 
                placeholder="List skills or interests relevant to tasks (e.g., 'Python, data analysis, public speaking, graphic design')"
              />
              <FormInput label="Phone (Optional)" id="profilePhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
              <FormSelect label="Notification Preference" id="profileNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                <option value="email">Email</option>
                <option value="phone">Phone (Not Implemented)</option>
                <option value="none">None</option>
              </FormSelect>
               <div className="pt-4 border-t border-gray-200">
                <h3 className="text-lg font-medium text-textlight mb-2">Change Password (Optional)</h3>
                <FormInput label="New Password" id="profileNewPassword" type="password" value={userForm.password} onChange={e => setUserForm({...userForm, password: e.target.value})} 
                    description={passwordRequirementsText} autoComplete="new-password"
                />
                <FormInput label="Confirm New Password" id="profileConfirmPassword" type="password" value={userForm.confirmPassword} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} 
                    autoComplete="new-password"
                />
              </div>
              <button type="submit" className="btn-primary">Update Profile</button>
            </form>
          </div>
        )}

        {currentPage === Page.UserManagement && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-1">User Management</h2>
            <p className="text-sm text-neutral mb-6">Manage user accounts, approve registrations, and view user details.</p>

            {editingUserId || approvingPendingUser || userForm.email ? ( 
                 <div className="bg-surface p-6 rounded-lg shadow-md mb-6">
                    <h3 className="text-xl font-semibold text-primary mb-4">
                        {editingUserId ? 'Edit User' : (approvingPendingUser ? 'Approve Pending User' : 'Add New User')}
                    </h3>
                    {approvingPendingUser && (
                        <div className="mb-4 p-3 bg-blue-50 border border-blue-300 rounded-md">
                            <p className="text-sm text-blue-700">
                                <strong>Approving:</strong> {approvingPendingUser.displayName} ({approvingPendingUser.email})<br/>
                                <strong>Desired System ID:</strong> {approvingPendingUser.uniqueId}<br/>
                                <strong>Role:</strong> {approvingPendingUser.role} (from registration)<br/>
                                You can adjust details below before final approval. Password will be what user initially set.
                            </p>
                        </div>
                    )}
                    <form onSubmit={editingUserId ? handleAdminUpdateUser : (approvingPendingUser ? (e) => { e.preventDefault(); handleApprovePendingUser(); } : handleCreateUserByAdmin)} className="space-y-4">
                        <FormInput label="Email" id="userFormEmail" type="email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required 
                            disabled={!!approvingPendingUser}
                        />
                        <FormInput label="System ID / Username" id="userFormUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required 
                             disabled={!!approvingPendingUser && !!approvingPendingUser.uniqueId}
                        />
                        <FormInput label="Display Name" id="userFormDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
                        <FormInput label="Position / Role Title" id="userFormPosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                        <FormTextarea label="User Skills & Interests" id="userFormUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} placeholder="e.g., 'Web development, event planning'"/>
                        <FormInput label="Phone (Optional)" id="userFormPhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                        <FormSelect label="Notification Preference" id="userFormNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                            <option value="email">Email</option>
                            <option value="phone">Phone (Not Implemented)</option>
                            <option value="none">None</option>
                        </FormSelect>
                        <FormSelect label="Role" id="userFormRole" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value as Role})}>
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </FormSelect>
                         {!approvingPendingUser && ( 
                            <div className="pt-4 border-t border-gray-200">
                                <h3 className="text-lg font-medium text-textlight mb-2">{editingUserId ? 'Reset Password (Optional)' : 'Set Password'}</h3>
                                <FormInput label="Password" id="userFormPassword" type="password" value={userForm.password} 
                                    onChange={e => setUserForm({...userForm, password: e.target.value})} 
                                    required={!editingUserId}  
                                    description={passwordRequirementsText} autoComplete="new-password"
                                />
                                <FormInput label="Confirm Password" id="userFormConfirmPassword" type="password" value={userForm.confirmPassword} 
                                    onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} 
                                    required={!editingUserId || !!userForm.password} 
                                    autoComplete="new-password"
                                />
                            </div>
                        )}
                        <div className="flex space-x-3">
                           <button type="submit" className="btn-primary">
                                {editingUserId ? 'Save Changes' : (approvingPendingUser ? 'Approve & Create User' : 'Create User')}
                           </button>
                           <button type="button" className="btn-neutral" onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); clearMessages(); }}>Cancel</button>
                        </div>
                    </form>
                </div>
            ) : (
                 <button onClick={() => { setUserForm(initialUserFormData); clearMessages(); }} className="btn-success mb-6 inline-flex items-center">
                    <PlusCircleIcon className="w-5 h-5 mr-2"/> Add New User Manually
                </button>
            )}

            {pendingUsers.length > 0 && (
                <div className="bg-surface p-6 rounded-lg shadow-md">
                    <h3 className="text-xl font-semibold text-amber-600 mb-4">Pending User Registrations ({pendingUsers.length})</h3>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Display Name</th>
                                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Email</th>
                                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Desired System ID</th>
                                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Date Submitted</th>
                                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Referred By</th>
                                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                            {pendingUsers.map(pu => {
                                const referringAdmin = pu.referringAdminId ? users.find(u => u.id === pu.referringAdminId) : null;
                                return (
                                <tr key={pu.id} className="hover:bg-gray-50">
                                    <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{pu.displayName}</td>
                                    <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{pu.email}</td>
                                    <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{pu.uniqueId}</td>
                                    <td className="px-4 py-3 whitespace-nowrap text-sm text-neutral">{new Date(pu.submissionDate).toLocaleDateString()}</td>
                                    <td className="px-4 py-3 whitespace-nowrap text-sm text-neutral">{referringAdmin ? referringAdmin.displayName : (pu.referringAdminId ? 'Admin (details pending)' : 'General Registration')}</td>
                                    <td className="px-4 py-3 whitespace-nowrap text-sm space-x-2">
                                    <button onClick={() => { 
                                        setApprovingPendingUser(pu);
                                        setUserForm({ // Pre-fill form with pending user's data
                                            email: pu.email,
                                            uniqueId: pu.uniqueId,
                                            displayName: pu.displayName,
                                            position: 'Pending Profile Setup', 
                                            userInterests: '',
                                            phone: '',
                                            notificationPreference: 'email',
                                            role: pu.role, // Use role from pending user
                                            password: '', // Password not shown/changed here by admin
                                            confirmPassword: '',
                                            referringAdminId: pu.referringAdminId || ''
                                        });
                                        setEditingUserId(null); 
                                        clearMessages();
                                        window.scrollTo(0,0); 
                                    }} className="btn-success text-xs px-2 py-1">Approve</button>
                                    <button onClick={() => { if(window.confirm(`Are you sure you want to reject registration for ${pu.displayName}?`)) handleRejectPendingUser(pu.id);}} className="btn-danger text-xs px-2 py-1">Reject</button>
                                    </td>
                                </tr>
                                );
                            })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
             {pendingUsers.length === 0 && !editingUserId && !approvingPendingUser && !userForm.email && (
                <p className="text-neutral p-4 bg-surface rounded-lg shadow-sm">No pending user registrations at this time.</p>
            )}

            <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-primary mb-4">Generate Pre-registration Link</h3>
                <p className="text-sm text-neutral mb-3">Create a unique link to send to new users. They can use this link to pre-register, and their account will then appear above for your approval.</p>
                <button onClick={handleGeneratePreRegistrationLink} className="btn-secondary inline-flex items-center">
                    <KeyIcon className="w-5 h-5 mr-2"/> Generate Link
                </button>
                {generatedLink && (
                <div className="mt-4 p-3 bg-blue-50 border border-blue-300 rounded-md">
                    <p className="text-sm text-blue-700 font-medium">Share this link:</p>
                    <input type="text" readOnly value={generatedLink} className="w-full p-2 mt-1 border border-blue-300 rounded bg-white text-sm" aria-label="Generated pre-registration link"/>
                    <button onClick={() => copyToClipboard(generatedLink)} className="btn-info text-xs px-2 py-1 mt-2">Copy Link</button>
                </div>
                )}
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-primary mb-4">Active Users ({users.length})</h3>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                        <tr>
                            <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Display Name</th>
                            <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Email</th>
                            <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">System ID</th>
                            <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Role</th>
                            <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Position</th>
                            <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                        </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                        {users.map(user => (
                            <tr key={user.id} className="hover:bg-gray-50">
                            <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{user.displayName}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{user.email}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{user.uniqueId}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-sm text-neutral capitalize">{user.role}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-sm text-neutral">{user.position}</td>
                            <td className="px-4 py-3 whitespace-nowrap text-sm space-x-2">
                                <button onClick={() => {
                                    setEditingUserId(user.id);
                                    setUserForm({
                                        email: user.email,
                                        uniqueId: user.uniqueId,
                                        displayName: user.displayName,
                                        position: user.position,
                                        userInterests: user.userInterests || '',
                                        phone: user.phone || '',
                                        notificationPreference: user.notificationPreference || 'none',
                                        role: user.role,
                                        password: '', 
                                        confirmPassword: '',
                                        referringAdminId: user.referringAdminId || ''
                                    });
                                    setApprovingPendingUser(null); 
                                    clearMessages();
                                    window.scrollTo(0,0); 
                                }} className="btn-info text-xs px-2 py-1">Edit</button>
                                {currentUser.id !== user.id && ( 
                                <button onClick={() => {if(window.confirm(`Are you sure you want to delete user ${user.displayName}? This action cannot be undone.`)) handleDeleteUser(user.id);}} className="btn-danger text-xs px-2 py-1">Delete</button>
                                )}
                            </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            </div>
          </div>
        )}

        {currentPage === Page.ManagePrograms && currentUser.role === 'admin' && (
            <div className="space-y-6">
                <h2 className="text-2xl font-semibold text-primary mb-6">Manage Programs</h2>
                <div className="bg-surface p-6 rounded-lg shadow-md">
                    <h3 className="text-xl font-semibold text-secondary mb-4">Create New Program</h3>
                    <form onSubmit={handleCreateProgram} className="space-y-4">
                        <FormInput label="Program Name" id="programName" type="text" value={programForm.name} onChange={e => setProgramForm({ ...programForm, name: e.target.value })} required />
                        <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({ ...programForm, description: e.target.value })} required />
                        <button type="submit" className="btn-primary">Create Program</button>
                    </form>
                </div>

                <div className="bg-surface p-6 rounded-lg shadow-md">
                    <h3 className="text-xl font-semibold text-primary mb-4">Existing Programs ({programs.length})</h3>
                    {programs.length > 0 ? (
                        <ul className="space-y-3">
                        {programs.map(program => (
                            <li key={program.id} className="p-4 bg-bground rounded-md shadow-sm">
                            <div className="flex justify-between items-start">
                                <div>
                                <h4 className="font-semibold text-textlight">{program.name}</h4>
                                <p className="text-sm text-neutral">{program.description}</p>
                                </div>
                                <button onClick={() => {if(window.confirm(`Are you sure you want to delete program "${program.name}"? Associated tasks will be unlinked.`)) handleDeleteProgram(program.id)}} className="btn-danger text-xs p-1.5 ml-4 self-start">
                                    <TrashIcon className="w-4 h-4"/>
                                </button>
                            </div>
                            </li>
                        ))}
                        </ul>
                    ) : (
                        <p className="text-neutral">No programs created yet.</p>
                    )}
                </div>
            </div>
        )}
        
        {currentPage === Page.ManageTasks && currentUser.role === 'admin' && (
            <div className="space-y-6">
                <h2 className="text-2xl font-semibold text-primary mb-6">Manage Tasks</h2>
                 <div className="bg-surface p-6 rounded-lg shadow-md">
                    <h3 className="text-xl font-semibold text-secondary mb-4">Create New Task</h3>
                    <form onSubmit={handleCreateTask} className="space-y-4">
                        <FormInput label="Task Title" id="taskTitle" type="text" value={taskForm.title} onChange={e => setTaskForm({ ...taskForm, title: e.target.value })} required />
                        <FormTextarea label="Task Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({ ...taskForm, description: e.target.value })} required />
                        <FormTextarea label="Required Skills (comma-separated)" id="taskSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({ ...taskForm, requiredSkills: e.target.value })} required 
                            placeholder="e.g., JavaScript, Project Management, Communication"
                        />
                        <FormSelect label="Related Program (Optional)" id="taskProgram" value={taskForm.programId} onChange={e => setTaskForm({ ...taskForm, programId: e.target.value })}>
                            <option value="">None</option>
                            {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                        </FormSelect>
                        <FormInput label="General Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline} onChange={e => setTaskForm({ ...taskForm, deadline: e.target.value })} 
                            min={new Date().toISOString().split("T")[0]} 
                        />
                        <button type="submit" className="btn-primary">Create Task</button>
                    </form>
                </div>

                <div className="bg-surface p-6 rounded-lg shadow-md">
                    <h3 className="text-xl font-semibold text-primary mb-4">Existing Tasks ({tasks.length})</h3>
                     {tasks.length > 0 ? (
                        <ul className="space-y-3">
                        {tasks.map(task => (
                            <li key={task.id} className="p-4 bg-bground rounded-md shadow-sm">
                            <div className="flex justify-between items-start">
                                <div>
                                <h4 className="font-semibold text-textlight">{task.title}</h4>
                                <p className="text-sm text-neutral mt-1">{task.description}</p>
                                <p className="text-sm text-neutral mt-1"><strong>Skills:</strong> {task.requiredSkills}</p>
                                {task.programName && <p className="text-sm text-neutral mt-1"><strong>Program:</strong> {task.programName}</p>}
                                {task.deadline && <p className="text-sm text-neutral mt-1"><strong>Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>}
                                </div>
                                <button onClick={() => {if(window.confirm(`Are you sure you want to delete task "${task.title}"? All its assignments will also be deleted.`)) handleDeleteTask(task.id)}} className="btn-danger text-xs p-1.5 ml-4 self-start">
                                     <TrashIcon className="w-4 h-4"/>
                                </button>
                            </div>
                            </li>
                        ))}
                        </ul>
                    ) : (
                        <p className="text-neutral">No tasks created yet.</p>
                    )}
                </div>
            </div>
        )}

        {currentPage === Page.AssignWork && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Assign Work</h2>
            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-secondary mb-4">Assign Task to User</h3>
              <form onSubmit={(e) => handleAssignTask(e, assignmentSuggestion?.suggestedPersonName)} className="space-y-4">
                <FormSelect label="Select Task" id="assignTask" value={selectedTaskForAssignment || ''} onChange={e => {setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); clearMessages();}} required>
                  <option value="" disabled>-- Select a Task --</option>
                  {tasks.filter(task => !assignments.some(a => a.taskId === task.id && (a.status === 'accepted_by_user' || a.status === 'pending_acceptance' || a.status === 'completed_admin_approved'))).map(task => (
                    <option key={task.id} value={task.id}>{task.title}</option>
                  ))}
                  {tasks.filter(task => assignments.some(a => a.taskId === task.id && (a.status === 'accepted_by_user' || a.status === 'pending_acceptance' || a.status === 'completed_admin_approved'))).length > 0 && (
                    <optgroup label="Tasks Already Assigned or Completed">
                        {tasks.filter(task => assignments.some(a => a.taskId === task.id && (a.status === 'accepted_by_user' || a.status === 'pending_acceptance' || a.status === 'completed_admin_approved')))
                            .map(task => <option key={task.id} value={task.id} disabled>{task.title} (Assigned/Completed)</option>)}
                    </optgroup>
                  )}
                </FormSelect>
                
                {selectedTaskForAssignment && (
                  <button type="button" onClick={handleGetAssignmentSuggestion} disabled={isLoadingSuggestion} className="btn-info inline-flex items-center">
                    {isLoadingSuggestion ? <LoadingSpinner /> : <><LightBulbIcon className="w-5 h-5 mr-2"/> Get AI Suggestion</>}
                  </button>
                )}

                {assignmentSuggestion && assignmentSuggestion.suggestedPersonName && (
                    <div className="p-3 bg-blue-50 border border-blue-200 rounded-md">
                        <p className="text-sm text-blue-700">
                            <strong>AI Suggestion:</strong> Assign to <strong>{assignmentSuggestion.suggestedPersonName}</strong>.
                        </p>
                        <p className="text-xs text-neutral mt-1"><em>Justification: {assignmentSuggestion.justification}</em></p>
                    </div>
                )}
                {assignmentSuggestion && !assignmentSuggestion.suggestedPersonName && assignmentSuggestion.justification && (
                     <div className="p-3 bg-yellow-50 border border-yellow-300 rounded-md">
                        <p className="text-sm text-yellow-700">
                            <strong>AI Note:</strong> {assignmentSuggestion.justification}
                        </p>
                    </div>
                )}

                <FormSelect label="Select Person" id="assignPerson" required
                    defaultValue={users.find(u => u.displayName === assignmentSuggestion?.suggestedPersonName)?.id || ""}
                >
                  <option value="" disabled>-- Select a Person --</option>
                  {users.filter(u => u.role === 'user').map(user => (
                    <option key={user.id} value={user.id} 
                        disabled={assignments.some(a => a.taskId === selectedTaskForAssignment && a.personId === user.id && (a.status === 'accepted_by_user' || a.status === 'pending_acceptance'))}
                    >
                        {user.displayName} ({user.position})
                        {assignments.some(a => a.taskId === selectedTaskForAssignment && a.personId === user.id && (a.status === 'accepted_by_user' || a.status === 'pending_acceptance')) ? ' - Already assigned this task' : ''}
                    </option>
                  ))}
                </FormSelect>

                 <FormInput 
                    label="Specific Deadline for this Assignment (Optional)" 
                    id="specificDeadline" 
                    type="date" 
                    value={assignmentForm.specificDeadline} 
                    onChange={e => setAssignmentForm({...assignmentForm, specificDeadline: e.target.value})}
                    min={new Date().toISOString().split("T")[0]}
                    description="Overrides the task's general deadline for this specific assignment. If blank, general deadline applies."
                />
                <button type="submit" className="btn-primary">Assign Task</button>
              </form>
            </div>
            
            <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-primary mb-4">Current Assignments Overview</h3>
                {assignments.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Task</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Assigned To</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Deadline</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Submitted On</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {assignments.sort((a,b) => (a.taskTitle.localeCompare(b.taskTitle) || a.personName.localeCompare(b.personName))).map(assignment => (
                                    <tr key={`${assignment.taskId}-${assignment.personId}`} /* Assuming taskId+personId is unique for an assignment instance. If assignments have their own IDs from backend, use that. */ className="hover:bg-gray-50">
                                        <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{assignment.taskTitle}</td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{assignment.personName}</td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm">
                                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                assignment.status === 'completed_admin_approved' ? 'bg-green-100 text-green-800' :
                                                assignment.status === 'accepted_by_user' ? 'bg-blue-100 text-blue-800' :
                                                assignment.status === 'pending_acceptance' ? 'bg-yellow-100 text-yellow-800' :
                                                assignment.status === 'declined_by_user' ? 'bg-red-100 text-red-800' :
                                                assignment.status === 'submitted_late' ? 'bg-orange-100 text-orange-800' :
                                                assignment.status === 'submitted_on_time' ? 'bg-teal-100 text-teal-800' :
                                                'bg-gray-100 text-gray-800'
                                            }`}>
                                                {assignment.status.replace(/_/g, ' ')}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm text-neutral">{assignment.deadline ? new Date(assignment.deadline).toLocaleDateString() : 'N/A'}</td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm text-neutral">
                                            {assignment.userSubmissionDate ? new Date(assignment.userSubmissionDate).toLocaleString() : 'N/A'}
                                            {assignment.userDelayReason && <p className="text-xs text-orange-600 italic">Reason: {assignment.userDelayReason}</p>}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-sm">
                                            {(assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') && (
                                                <button onClick={() => handleAdminApproveTaskCompletion(assignment.taskId, assignment.personId)} className="btn-success text-xs px-2 py-1">Approve Completion</button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="text-neutral">No tasks assigned yet.</p>
                )}
            </div>

          </div>
        )}

        {currentPage === Page.ViewAssignments && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Assignments</h2>
            {assignments.filter(a => a.personId === currentUser.id).length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {assignments.filter(a => a.personId === currentUser.id)
                  .sort((a,b) => { 
                      const statusOrder: AssignmentStatus[] = ['pending_acceptance', 'accepted_by_user', 'submitted_on_time', 'submitted_late', 'declined_by_user', 'completed_admin_approved'];
                      const aStatusIndex = statusOrder.indexOf(a.status);
                      const bStatusIndex = statusOrder.indexOf(b.status);
                      if (aStatusIndex !== bStatusIndex) return aStatusIndex - bStatusIndex;
                      if (a.deadline && b.deadline) return new Date(a.deadline).getTime() - new Date(b.deadline).getTime();
                      return 0;
                  })
                  .map(assignment => {
                    const taskDetails = tasks.find(t => t.id === assignment.taskId);
                    const isLateSubmission = assignment.deadline && new Date() > new Date(assignment.deadline) && assignment.status === 'accepted_by_user';
                    return (
                    <div key={`${assignment.taskId}-${assignment.personId}`} /* Use backend provided assignment.id if available */ className="bg-surface p-5 rounded-lg shadow-md flex flex-col justify-between">
                      <div>
                        <h3 className="text-lg font-semibold text-secondary mb-2">{assignment.taskTitle}</h3>
                        {taskDetails && <p className="text-sm text-neutral mb-1">{taskDetails.description}</p>}
                        {taskDetails && <p className="text-sm text-neutral mb-1"><strong>Skills:</strong> {taskDetails.requiredSkills}</p>}
                        {taskDetails?.programName && <p className="text-sm text-neutral mb-1"><strong>Program:</strong> {taskDetails.programName}</p>}
                        <p className="text-sm font-medium mb-1">Status: 
                            <span className={`ml-1 px-2 py-0.5 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                assignment.status === 'completed_admin_approved' ? 'bg-green-100 text-green-800' :
                                assignment.status === 'accepted_by_user' ? 'bg-blue-100 text-blue-800' :
                                assignment.status === 'pending_acceptance' ? 'bg-yellow-100 text-yellow-800' :
                                assignment.status === 'declined_by_user' ? 'bg-red-100 text-red-800' :
                                assignment.status === 'submitted_late' ? 'bg-orange-100 text-orange-800' :
                                assignment.status === 'submitted_on_time' ? 'bg-teal-100 text-teal-800' :
                                'bg-gray-100 text-gray-800'
                            }`}>
                                {assignment.status.replace(/_/g, ' ')}
                            </span>
                        </p>
                        {assignment.deadline && <p className="text-sm text-neutral mb-3"><strong>Deadline:</strong> {new Date(assignment.deadline).toLocaleDateString()}</p>}
                        {assignment.justification && !assignment.justification.startsWith("Manually assigned") && <p className="text-xs italic text-neutral mb-2">AI Suggestion Reason: {assignment.justification}</p>}
                         {assignment.userSubmissionDate && <p className="text-xs text-neutral">Submitted: {new Date(assignment.userSubmissionDate).toLocaleString()}</p>}
                         {assignment.userDelayReason && <p className="text-xs text-orange-500 italic">Reason for delay: {assignment.userDelayReason}</p>}
                      </div>
                      <div className="mt-4 pt-4 border-t border-gray-200 space-y-2 flex flex-col items-start">
                        {assignment.status === 'pending_acceptance' && (
                          <>
                            <button onClick={() => handleUserAcceptTask(assignment.taskId)} className="btn-success w-full">Accept Task</button>
                            <button onClick={() => handleUserDeclineTask(assignment.taskId)} className="btn-danger w-full">Decline Task</button>
                          </>
                        )}
                        {assignment.status === 'accepted_by_user' && (
                          <>
                            <button 
                                onClick={() => {
                                    if (isLateSubmission) {
                                        setAssignmentToSubmitDelayReason(assignment.taskId); 
                                    } else {
                                        handleUserSubmitTask(assignment.taskId);
                                    }
                                }} 
                                className="btn-primary w-full"
                            >
                                Mark as Completed / Submit
                            </button>
                            {isLateSubmission && <p className="text-xs text-warning mt-1">This task is past its deadline. You'll be asked for a reason upon submission.</p>}
                          </>
                        )}
                        {(assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') && (
                          <p className="text-sm text-info">Awaiting admin approval.</p>
                        )}
                        {assignment.status === 'completed_admin_approved' && (
                          <p className="text-sm text-success font-semibold flex items-center"><CheckCircleIcon className="w-5 h-5 mr-1 text-success"/> Task Completed & Approved!</p>
                        )}
                         {assignment.status === 'declined_by_user' && (
                          <p className="text-sm text-danger">You declined this task.</p>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-neutral text-center py-10 bg-surface rounded-lg shadow">You have no assignments at the moment. Check the "Available Tasks" page or wait for an admin to assign work to you.</p>
            )}
          </div>
        )}

        {assignmentToSubmitDelayReason && currentUser && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                <div className="bg-surface p-6 rounded-lg shadow-xl w-full max-w-md">
                    <h3 className="text-lg font-semibold text-warning mb-3">Late Submission</h3>
                    <p className="text-sm text-textlight mb-4">This task is being submitted after its deadline. Please provide a brief reason for the delay.</p>
                    <FormTextarea 
                        label="Reason for Delay"
                        id="userDelayReason"
                        value={userSubmissionDelayReason}
                        onChange={(e) => setUserSubmissionDelayReason(e.target.value)}
                        required
                        placeholder="e.g., Unexpected technical difficulties, Prioritized other urgent tasks"
                    />
                    <div className="mt-5 flex justify-end space-x-3">
                        <button 
                            type="button" 
                            onClick={() => { setAssignmentToSubmitDelayReason(null); setUserSubmissionDelayReason(''); clearMessages(); }} 
                            className="btn-neutral"
                        >
                            Cancel
                        </button>
                        <button 
                            type="button" 
                            onClick={() => {
                                if (!userSubmissionDelayReason.trim()) {
                                    setError("A reason for the delay is required.");
                                    return;
                                }
                                handleUserSubmitTask(assignmentToSubmitDelayReason, userSubmissionDelayReason);
                            }} 
                            className="btn-primary"
                        >
                            Submit with Reason
                        </button>
                    </div>
                </div>
            </div>
        )}


        {currentPage === Page.ViewTasks && ( 
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Available Tasks ({tasks.length})</h2>
            {tasks.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {tasks.map(task => {
                  const assignmentForThisTask = assignments.find(a => a.taskId === task.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user' || a.status === 'completed_admin_approved'));
                  const isAssignedToCurrentUser = assignmentForThisTask?.personId === currentUser?.id;
                  return (
                    <div key={task.id} className={`bg-surface p-5 rounded-lg shadow-md ${assignmentForThisTask && !isAssignedToCurrentUser ? 'opacity-60' : ''}`}>
                      <h3 className="text-lg font-semibold text-secondary mb-2">{task.title}</h3>
                      <p className="text-sm text-neutral mb-1 h-20 overflow-y-auto">{task.description}</p>
                      <p className="text-sm text-neutral mb-1"><strong>Skills:</strong> {task.requiredSkills}</p>
                      {task.programName && <p className="text-sm text-neutral mb-1"><strong>Program:</strong> {task.programName}</p>}
                      {task.deadline && <p className="text-sm text-neutral mb-3"><strong>Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>}
                       {assignmentForThisTask ? (
                            isAssignedToCurrentUser ? (
                                <p className="text-sm text-blue-600 font-semibold">This task is assigned to you. (Status: {assignmentForThisTask.status.replace(/_/g, ' ')})</p>
                            ) : (
                                <p className="text-sm text-gray-500 font-semibold">Assigned to: {assignmentForThisTask.personName} (Status: {assignmentForThisTask.status.replace(/_/g, ' ')})</p>
                            )
                        ) : (
                           currentUser.role === 'admin' && (
                             <button onClick={() => navigateTo(Page.AssignWork, { taskId: task.id })} className="btn-primary text-sm mt-2">Assign This Task</button>
                           )
                        )}
                         {currentUser.role === 'user' && !assignmentForThisTask && (
                            <p className="text-sm text-neutral italic mt-2">This task is not yet assigned. An admin can assign it if suitable.</p>
                        )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-neutral text-center py-10 bg-surface rounded-lg shadow">No tasks have been created in the system yet.</p>
            )}
          </div>
        )}
      </main>
    </div>
  );
};
