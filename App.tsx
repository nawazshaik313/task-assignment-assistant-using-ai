
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
      return defaultReturnVal !== null ? defaultReturnVal : ({} as T); // Return empty object or default for 204
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
return defaultReturnVal !== null ? defaultReturnVal : ({} as T);
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

  const newPendingUserData = {
    displayName: name,
    email,
    password,
    role: actualRoleToRegister,
    uniqueId: email,
    submissionDate: new Date().toISOString(),
  };

  try {
    const response = await fetchData<{ success: boolean; user: PendingUser }>('/pending-users', {
      method: 'POST',
      body: JSON.stringify(newPendingUserData),
    });

    const createdPendingUser = response?.user;
    const normalizedId = createdPendingUser?._id || createdPendingUser?.id;

    if (createdPendingUser && normalizedId) {
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
      setError("Failed to submit registration. The server did not confirm creation or returned unexpected data.");
    }
  } catch (err: any) {
    setError(err.message || "Failed to submit registration. Please try again later.");
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
    role: 'user',
    referringAdminId: referringAdminId || undefined,
    submissionDate: new Date().toISOString(),
  };

  try {
    const response = await fetchData<{ success: boolean; user: PendingUser }>('/pending-users', {
      method: 'POST',
      body: JSON.stringify(newPendingUserData),
    });

    const createdPendingUser = response?.user;
    const normalizedId = createdPendingUser?._id || createdPendingUser?.id;

    if (createdPendingUser && normalizedId) {
      createdPendingUser.id = normalizedId;

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
    setNewRegistrationForm(prev => ({ ...prev, role: 'user' })); // Reset for next potential registration
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
            setError("New passwords do not match.");
            return;
        }
        const passwordValidationResult = validatePassword(password);
        if (!passwordValidationResult.isValid) {
            setError(passwordValidationResult.errors.join(" "));
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
        if(currentUser && currentUser.id === editingUserId) { 
            setCurrentUser(updatedUserFromServer);
        }
        setSuccessMessage(`User ${updatedUserFromServer.displayName} updated successfully!`);
        setEditingUserId(null);
        setUserForm(initialUserFormData); 
        await addAdminLogEntry(`Admin updated user profile for ${updatedUserFromServer.displayName} (ID: ${updatedUserFromServer.uniqueId}). Role set to ${role}.`);
        navigateTo(Page.UserManagement);
      } else {
        setError("Failed to update user. Server did not confirm update or returned unexpected data.");
      }
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

    const newUserData: Omit<User, 'id'> = { 
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
      const createdUser = await fetchData<User>('/users', {
        method: 'POST',
        body: JSON.stringify(newUserData),
      });

      if (createdUser && createdUser.id) {
        setUsers(prev => [...prev, createdUser]);
        setSuccessMessage(`User ${createdUser.displayName} created successfully!`);
        setUserForm(initialUserFormData); 
        emailService.sendWelcomeRegistrationEmail(createdUser.email, createdUser.displayName, createdUser.role);
        await addAdminLogEntry(`Admin created new user: ${createdUser.displayName} (ID: ${createdUser.uniqueId}), Role: ${createdUser.role}.`);
        navigateTo(Page.UserManagement);
      } else {
        setError("Failed to create user. Server did not confirm creation or returned unexpected data.");
      }
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

    const { id: pendingId, uniqueId: pendingUniqueId, displayName: pendingDisplayName, email: pendingEmail, password: pendingPassword, role: pendingRole, referringAdminId } = approvingPendingUser;

    const finalUserDataForCreation: Omit<User, 'id'> = {
        email: userForm.email || pendingEmail,
        uniqueId: userForm.uniqueId || pendingUniqueId,
        displayName: userForm.displayName || pendingDisplayName,
        position: userForm.position || 'Default Position',
        userInterests: userForm.userInterests || '',
        phone: userForm.phone || '',
        notificationPreference: userForm.notificationPreference || 'email',
        role: userForm.role || pendingRole,
        password: pendingPassword, // Password from pending user
        referringAdminId: referringAdminId || currentUser.id,
    };

    try {
      const createdUser = await fetchData<User>('/users', { // Create the user first
        method: 'POST',
        body: JSON.stringify(finalUserDataForCreation),
      });

      if (createdUser && createdUser.id) {
        setUsers(prev => [...prev, createdUser]); // Add to active users

        // Then delete the pending user
        await fetchData(`/pending-users/${pendingId}`, { method: 'DELETE' });
        setPendingUsers(prev => prev.filter(pu => pu.id !== pendingId));
        
        setApprovingPendingUser(null); 
        setUserForm(initialUserFormData);
        setSuccessMessage(`User ${createdUser.displayName} approved and account activated!`);
        
        emailService.sendAccountActivatedByAdminEmail(createdUser.email, createdUser.displayName, currentUser.displayName);
        await addAdminLogEntry(`Admin ${currentUser.displayName} approved pending user: ${createdUser.displayName} (ID: ${createdUser.uniqueId}).`);
      } else {
        setError("Failed to create user from pending registration. Server did not confirm user creation or returned unexpected data.");
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
      await fetchData(`/pending-users/${pendingUserId}`, { method: 'DELETE' });
      setPendingUsers(prev => prev.filter(pu => pu.id !== pendingUserId));
      
      setSuccessMessage(`Pending registration for ${userToReject?.displayName || 'user'} rejected.`);
      await addAdminLogEntry(`Admin ${currentUser.displayName} rejected pending registration for ${userToReject?.displayName || 'user (ID: ' + pendingUserId + ')'}.`);
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
      await fetchData(`/users/${userId}`, { method: 'DELETE' });
      setUsers(prev => prev.filter(u => u.id !== userId));
      // Optionally, fetch assignments again or rely on backend to cascade delete/unlink
      const updatedAssignments = await fetchData<Assignment[]>('/assignments', {}, []);
      setAssignments(updatedAssignments || []);
      
      setSuccessMessage(`User ${userToDelete?.displayName || 'user'} and their assignments (if any linked on backend) handled.`);
      await addAdminLogEntry(`Admin ${currentUser.displayName} deleted user: ${userToDelete?.displayName || 'user (ID: ' + userId + ')'}.`);
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
    const newProgramData: Omit<Program, 'id'> = { ...programForm };
    try {
      const createdProgram = await fetchData<Program>('/programs', {
        method: 'POST',
        body: JSON.stringify(newProgramData),
      });
      if (createdProgram && createdProgram.id) {
        setPrograms(prev => [...prev, createdProgram]);
        setSuccessMessage("Program created successfully!");
        setProgramForm({ name: '', description: '' }); 
        if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} created program: ${createdProgram.name}.`);
      } else {
        setError("Failed to create program. Server did not confirm creation or returned unexpected data.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to create program.");
    }
  };
  
  const handleDeleteProgram = async (programId: string) => {
    clearMessages();
    try {
      const programToDelete = programs.find(p => p.id === programId);
      await fetchData(`/programs/${programId}`, { method: 'DELETE' });
      setPrograms(prev => prev.filter(p => p.id !== programId));
      // Tasks might need to be re-fetched or updated if backend unlinks them
      const updatedTasks = await fetchData<Task[]>('/tasks', {}, []);
      setTasks(updatedTasks || []);
      
      setSuccessMessage(`Program "${programToDelete?.name}" deleted.`);
      if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} deleted program: ${programToDelete?.name}.`);
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
    const newTaskData: Omit<Task, 'id' | 'programName'> & {programName?: string} = { // programName might be set by backend
      ...taskForm,
      deadline: taskForm.deadline ? new Date(taskForm.deadline).toISOString().split('T')[0] : undefined,
    };
    if(associatedProgram) newTaskData.programName = associatedProgram.name;


    try {
      const createdTask = await fetchData<Task>('/tasks', {
        method: 'POST',
        body: JSON.stringify(newTaskData),
      });
      if (createdTask && createdTask.id) {
        setTasks(prev => [...prev, createdTask]);
        setSuccessMessage("Task created successfully!");
        setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' }); 
        if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} created task: ${createdTask.title}.`);
      } else {
        setError("Failed to create task. Server did not confirm creation or returned unexpected data.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to create task.");
    }
  };

  const handleDeleteTask = async (taskId: string) => {
    clearMessages();
    try {
      const taskToDelete = tasks.find(t => t.id === taskId);
      await fetchData(`/tasks/${taskId}`, { method: 'DELETE' });
      setTasks(prev => prev.filter(t => t.id !== taskId));
      // Assignments might need to be re-fetched or updated
      const updatedAssignments = await fetchData<Assignment[]>('/assignments', {}, []);
      setAssignments(updatedAssignments || []);
      
      setSuccessMessage(`Task "${taskToDelete?.title}" deleted.`);
      if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} deleted task: ${taskToDelete?.title}.`);
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
    setError(null); 
    setAssignmentSuggestion(null);
    try {
      const suggestion = await getAssignmentSuggestion(task, usersEligibleForThisTask, programs, assignments);
      setAssignmentSuggestion(suggestion);
      if(suggestion && suggestion.suggestedPersonName){
        setInfoMessage(`AI Suggestion: ${suggestion.suggestedPersonName}. Justification: ${suggestion.justification}`);
      } else if (suggestion && suggestion.justification) {
        setInfoMessage(`AI: ${suggestion.justification}`);
      } else {
        setInfoMessage("AI could not provide a suggestion or no suitable person was found.");
      }
      if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} requested AI assignment suggestion for task: ${task.title}.`);
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

    const newAssignmentData: Omit<Assignment, 'idIfApplicable'> = { // Assuming backend generates ID if assignments have their own PK
      taskId: task.id,
      personId: person.id,
      taskTitle: task.title, 
      personName: person.displayName, 
      justification,
      status: 'pending_acceptance' as AssignmentStatus,
      deadline: specificDeadline || task.deadline,
    };

    try {
      const createdAssignment = await fetchData<Assignment>('/assignments', {
        method: 'POST',
        body: JSON.stringify(newAssignmentData),
      });

      if (createdAssignment && createdAssignment.taskId && createdAssignment.personId ) { // Check for core fields
        setAssignments(prev => [...prev, createdAssignment]); 
        setSuccessMessage(`Task "${task.title}" assigned to ${person.displayName}.`);
        setSelectedTaskForAssignment(null);
        setAssignmentSuggestion(null);
        setAssignmentForm({ specificDeadline: '' });
        
        if (person.notificationPreference === 'email' && person.email) {
          emailService.sendTaskProposalEmail(person.email, person.displayName, task.title, currentUser?.displayName || "Admin", createdAssignment.deadline);
        }
        if(currentUser) await addAdminLogEntry(`Admin ${currentUser.displayName} assigned task "${task.title}" to ${person.displayName}. Justification: ${justification}`);
      } else {
        setError("Failed to assign task. Server did not confirm creation or returned unexpected data.");
      }
    } catch (err:any) {
      setError(err.message || "Failed to assign task.");
    }
  };

  const updateAssignmentStatus = async (taskId: string, personId: string, newStatus: AssignmentStatus, additionalData: Record<string, any> = {}) => {
    if (!currentUser && newStatus !== 'pending_acceptance') return null; 
    clearMessages();

    const assignmentIdentifier = { taskId, personId }; // Assuming backend can identify by this composite key
    const payload = { ...assignmentIdentifier, status: newStatus, ...additionalData };
    
    try {
      // Assuming PATCH /assignments updates an existing assignment.
      // The backend needs to know which assignment to update.
      // If assignments have their own unique IDs, use PUT /assignments/:assignmentId
      const updatedAssignment = await fetchData<Assignment>(`/assignments`, { // Or a more specific endpoint
        method: 'PATCH', // Or PUT if replacing the whole resource
        body: JSON.stringify(payload),
      });

      if (updatedAssignment && updatedAssignment.taskId && updatedAssignment.personId) {
        setAssignments(prev => prev.map(a => (a.taskId === taskId && a.personId === personId) ? updatedAssignment : a));
        return updatedAssignment;
      } else {
        setError(`Failed to update task status to ${newStatus}. Server did not confirm update or returned unexpected data.`);
        return null;
      }
    } catch (err:any) {
      setError(err.message || `Failed to update task status to ${newStatus}.`);
      throw err; 
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
      if (!delayReason && assignmentToSubmitDelayReason === `${assignment.taskId}-${assignment.personId}`) { // Check specific assignment
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
            await addAdminLogEntry(`Admin ${currentUser.displayName} approved task completion for "${updatedAssignment.taskTitle}" by ${assignedUser?.displayName}.`);
        }
    } catch (e) { /* error already set by updateAssignmentStatus */ }
  };

  const addAdminLogEntry = async (logText: string, imagePreviewUrl?: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    const newLogData: Omit<AdminLogEntry, 'id'> = {
      adminId: currentUser.id, 
      adminDisplayName: currentUser.displayName, 
      timestamp: new Date().toISOString(), 
      logText,
      imagePreviewUrl
    };
    try {
        const createdLog = await fetchData<AdminLogEntry>('/admin-logs', {
          method: 'POST',
          body: JSON.stringify(newLogData),
        });
        if (createdLog && createdLog.id) {
          setAdminLogs(prev => [createdLog, ...prev]); 
        } else {
          console.error("Failed to save admin log to backend: No log returned or missing ID.");
          // setError("Failed to save admin log (server did not confirm)."); // Avoid overwriting more specific errors
        }
    } catch (error: any) {
        console.error("Failed to save admin log to backend:", error);
        // setError("Failed to save admin log: " + error.message); // Avoid overwriting
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
        try {
            // If backend handles image upload and returns a URL, that's better.
            // For now, sending base64, assuming backend can take it.
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
        setError("Failed to submit admin log: " + err.message);
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
        // The backend should handle checking if the user exists and sending the email.
        // The frontend just makes the request.
        await fetchData('/users/forgot-password', { // Example endpoint
            method: 'POST',
            body: JSON.stringify({ email: emailToReset }),
        });
        setInfoMessage(`If an account exists for ${emailToReset}, a password reset link has been sent to your email address.`);
    } catch (err: any) {
        // Even if the user doesn't exist, we might show a generic message for security.
        // The backend's response could guide this, or we stick to a generic one.
        console.error("Forgot password API call failed:", err);
        setInfoMessage(`If an account exists for ${emailToReset}, a password reset link has been sent. (Error: ${err.message})`);
        // Or more generically to avoid confirming emails:
        // setError("There was an issue processing your request. Please try again later.");
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


  if (isLoadingAppData && !currentUser) { 
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-bground p-4">
        <LoadingSpinner />
        <p className="mt-4 text-textlight">Loading application data...</p>
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
                disabled={isLoadingAppData}
              >
                {isLoadingAppData ? <LoadingSpinner /> : 'Sign In'}
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
              { 
                <div>
                  <label htmlFor="regRole" className="block text-sm font-medium text-textlight">Role</label>
                  <AuthFormSelect
                    id="regRole"
                    aria-label="Role for registration"
                    value={users.length === 0 ? 'admin' : newRegistrationForm.role}
                    onChange={(e) => setNewRegistrationForm({ ...newRegistrationForm, role: e.target.value as Role })}
                    disabled={users.length === 0} 
                  >
                    <option value="user">User</option>
                    {users.length === 0 && <option value="admin">Admin (First User)</option>}
                  </AuthFormSelect>
                  <p className="mt-1 text-xs text-neutral">
                    {users.length === 0 ? "First user will be registered as Admin." : "General registration is for 'User' role."}
                  </p>
                </div>
              }
              <button 
                type="submit" 
                className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
                disabled={isLoadingAppData}
              >
                {isLoadingAppData ? <LoadingSpinner/> : 'Register'}
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
           { !isLoadingAppData && users.length === 0 && authView === 'login' && (
            <div className="mt-6 p-4 bg-yellow-50 border border-yellow-300 rounded-md">
              <p className="text-sm text-yellow-700">
                <strong className="font-bold">First-time Setup:</strong> No admin accounts detected. The first user to register will become an administrator.
                Please <button type="button" onClick={() => { clearMessages(); setAuthView('register'); setNewRegistrationForm(f => ({...f, role: 'admin'})); }} className="font-medium text-authLink hover:underline">register as Admin</button> to initialize the system.
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
       {isLoadingAppData && !currentUser && <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-50 flex items-center justify-center z-50"><LoadingSpinner /><p className="text-white ml-2">Loading data...</p></div>}
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

            {/* Create/Edit User Form (Modal or Inline Section) */}
            {editingUserId || approvingPendingUser ? (
              <div className="bg-surface p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold text-accent mb-4">
                  {editingUserId ? 'Edit User' : (approvingPendingUser ? `Approve Pending User: ${approvingPendingUser.displayName}` : 'Create New User')}
                </h3>
                <form onSubmit={editingUserId ? handleAdminUpdateUser : (approvingPendingUser ? handleApprovePendingUser : handleCreateUserByAdmin)} className="space-y-4">
                  <FormInput label="Email" id="userMgmtEmail" type="email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required />
                  <FormInput label="System ID / Username" id="userMgmtUniqueId" type="text" value={userForm.uniqueId} onChange={e => setUserForm({...userForm, uniqueId: e.target.value})} required />
                  <FormInput label="Display Name" id="userMgmtDisplayName" type="text" value={userForm.displayName} onChange={e => setUserForm({...userForm, displayName: e.target.value})} required />
                  <FormInput label="Position / Role Title" id="userMgmtPosition" type="text" value={userForm.position} onChange={e => setUserForm({...userForm, position: e.target.value})} required />
                  <FormTextarea label="Skills & Interests" id="userMgmtUserInterests" value={userForm.userInterests} onChange={e => setUserForm({...userForm, userInterests: e.target.value})} />
                  <FormInput label="Phone (Optional)" id="userMgmtPhone" type="tel" value={userForm.phone} onChange={e => setUserForm({...userForm, phone: e.target.value})} />
                  <FormSelect label="Notification Preference" id="userMgmtNotificationPreference" value={userForm.notificationPreference} onChange={e => setUserForm({...userForm, notificationPreference: e.target.value as NotificationPreference})}>
                    <option value="email">Email</option>
                    <option value="phone">Phone (Not Implemented)</option>
                    <option value="none">None</option>
                  </FormSelect>
                  <FormSelect label="Role" id="userMgmtRole" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value as Role})}>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                  </FormSelect>
                  {!approvingPendingUser && ( // Don't show password fields if just approving, password is set from pending user
                    <div className="pt-4 border-t border-gray-200">
                        <h3 className="text-lg font-medium text-textlight mb-2">{editingUserId ? 'Reset Password (Optional)' : 'Set Password'}</h3>
                        <FormInput label="Password" id="userMgmtPassword" type="password" value={userForm.password} onChange={e => setUserForm({...userForm, password: e.target.value})} required={!editingUserId} description={passwordRequirementsText} autoComplete="new-password"/>
                        <FormInput label="Confirm Password" id="userMgmtConfirmPassword" type="password" value={userForm.confirmPassword} onChange={e => setUserForm({...userForm, confirmPassword: e.target.value})} required={!editingUserId} autoComplete="new-password" />
                    </div>
                  )}
                  <div className="flex space-x-3">
                    <button type="submit" className="btn-success">
                      {editingUserId ? 'Save Changes' : (approvingPendingUser ? 'Approve and Create User' : 'Create User')}
                    </button>
                    <button type="button" className="btn-neutral" onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); clearMessages(); }}>Cancel</button>
                  </div>
                </form>
              </div>
            ) : (
              <button onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); clearMessages(); /*This will effectively make the form 'create'*/ navigateTo(Page.UserManagement, {action: 'createUser'}); _setCurrentPageInternal(Page.UserManagement); /*Force re-render if already on page to show form*/ }} className="btn-primary mb-4 flex items-center"><PlusCircleIcon className="w-5 h-5 mr-2"/>Add New User</button>
            )}

            {/* Pre-registration Link Generator */}
             <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-3">Pre-registration Link</h3>
              <button onClick={handleGeneratePreRegistrationLink} className="btn-secondary flex items-center"><KeyIcon className="w-5 h-5 mr-2"/>Generate New Link</button>
              {generatedLink && (
                <div className="mt-3 p-3 bg-bground rounded">
                  <p className="text-sm text-textlight break-all">{generatedLink}</p>
                  <button onClick={() => copyToClipboard(generatedLink)} className="text-xs btn-neutral mt-2">Copy to Clipboard</button>
                </div>
              )}
            </div>


            {/* Pending User Approvals Table */}
            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Pending User Approvals ({pendingUsers.length})</h3>
              {pendingUsers.length === 0 ? <p className="text-neutral">No users awaiting approval.</p> : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-bground">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Display Name</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Email / System ID</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Role / Date</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="bg-surface divide-y divide-gray-200">
                      {pendingUsers.map(pu => (
                        <tr key={pu.id}>
                          <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{pu.displayName}</td>
                          <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{pu.email} ({pu.uniqueId})</td>
                          <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{pu.role} <br/><span className="text-xs text-neutral">{new Date(pu.submissionDate).toLocaleDateString()}</span></td>
                          <td className="px-4 py-3 whitespace-nowrap text-sm space-x-2">
                            <button
                              onClick={() => {
                                setApprovingPendingUser(pu);
                                setUserForm({
                                  email: pu.email,
                                  uniqueId: pu.uniqueId,
                                  displayName: pu.displayName,
                                  position: '', // Admin should set this
                                  userInterests: '',
                                  phone: '',
                                  notificationPreference: 'email',
                                  role: pu.role,
                                  password: '', // Password is not set here, it's from pu.password
                                  confirmPassword: '',
                                  referringAdminId: pu.referringAdminId || currentUser.id
                                });
                                setEditingUserId(null); 
                                navigateTo(Page.UserManagement, {action: 'approveUser', userId: pu.id});_setCurrentPageInternal(Page.UserManagement);
                                clearMessages();
                              }}
                              className="btn-success text-xs px-2 py-1"
                              aria-label={`Approve ${pu.displayName}`}
                            >
                              Approve
                            </button>
                            <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger text-xs px-2 py-1" aria-label={`Reject ${pu.displayName}`}>Reject</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Active Users Table */}
            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Active Users ({users.length})</h3>
              {users.length === 0 ? <p className="text-neutral">No active users found.</p> : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    {/* Table Header */}
                    <thead className="bg-bground">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Display Name</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Email / System ID</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Role / Position</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-neutral uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    {/* Table Body */}
                    <tbody className="bg-surface divide-y divide-gray-200">
                      {users.map(user => (
                        <tr key={user.id}>
                          <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-textlight">{user.displayName}</td>
                          <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight">{user.email}<br/><span className="text-xs text-neutral">{user.uniqueId}</span></td>
                          <td className="px-4 py-3 whitespace-nowrap text-sm text-textlight capitalize">{user.role}<br/><span className="text-xs text-neutral">{user.position}</span></td>
                          <td className="px-4 py-3 whitespace-nowrap text-sm space-x-2">
                            <button
                              onClick={() => {
                                setEditingUserId(user.id);
                                setUserForm({
                                    email: user.email, uniqueId: user.uniqueId, displayName: user.displayName,
                                    position: user.position, userInterests: user.userInterests || '', phone: user.phone || '',
                                    notificationPreference: user.notificationPreference || 'none', role: user.role,
                                    password: '', confirmPassword: '', referringAdminId: user.referringAdminId || ''
                                });
                                setApprovingPendingUser(null);
                                navigateTo(Page.UserManagement, {action: 'editUser', userId: user.id}); _setCurrentPageInternal(Page.UserManagement);
                                clearMessages();
                              }}
                              className="btn-info text-xs px-2 py-1"
                              aria-label={`Edit ${user.displayName}`}
                            >
                              Edit
                            </button>
                            {currentUser.id !== user.id && ( // Prevent admin from deleting self
                              <button onClick={() => handleDeleteUser(user.id)} className="btn-danger text-xs px-2 py-1" aria-label={`Delete ${user.displayName}`}>Delete</button>
                            )}
                          </td>
                        </tr>
                      ))}
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
            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Create New Program</h3>
              <form onSubmit={handleCreateProgram} className="space-y-4">
                <FormInput label="Program Name" id="programName" value={programForm.name} onChange={e => setProgramForm({...programForm, name: e.target.value})} required />
                <FormTextarea label="Program Description" id="programDescription" value={programForm.description} onChange={e => setProgramForm({...programForm, description: e.target.value})} required />
                <button type="submit" className="btn-primary">Create Program</button>
              </form>
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Existing Programs ({programs.length})</h3>
              {programs.length === 0 ? <p className="text-neutral">No programs created yet.</p> : (
                 <ul className="space-y-3">
                  {programs.map(program => (
                    <li key={program.id} className="p-4 bg-bground rounded-md shadow flex justify-between items-start">
                      <div>
                        <h4 className="font-semibold text-textlight">{program.name}</h4>
                        <p className="text-sm text-neutral">{program.description}</p>
                      </div>
                      <button onClick={() => handleDeleteProgram(program.id)} className="btn-danger text-xs px-2 py-1 self-start ml-4" aria-label={`Delete program ${program.name}`}><TrashIcon className="w-4 h-4"/></button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {currentPage === Page.ManageTasks && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Manage Tasks</h2>
             <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Create New Task</h3>
              <form onSubmit={handleCreateTask} className="space-y-4">
                <FormInput label="Task Title" id="taskTitle" value={taskForm.title} onChange={e => setTaskForm({...taskForm, title: e.target.value})} required />
                <FormTextarea label="Task Description" id="taskDescription" value={taskForm.description} onChange={e => setTaskForm({...taskForm, description: e.target.value})} required />
                <FormTextarea label="Required Skills (comma-separated)" id="taskRequiredSkills" value={taskForm.requiredSkills} onChange={e => setTaskForm({...taskForm, requiredSkills: e.target.value})} required placeholder="e.g., JavaScript, Project Management, Writing"/>
                <FormSelect label="Related Program (Optional)" id="taskProgramId" value={taskForm.programId} onChange={e => setTaskForm({...taskForm, programId: e.target.value})}>
                  <option value="">None</option>
                  {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </FormSelect>
                <FormInput label="Deadline (Optional)" id="taskDeadline" type="date" value={taskForm.deadline} onChange={e => setTaskForm({...taskForm, deadline: e.target.value})} />
                <button type="submit" className="btn-primary">Create Task</button>
              </form>
            </div>

            <div className="bg-surface p-6 rounded-lg shadow-md">
              <h3 className="text-xl font-semibold text-accent mb-4">Existing Tasks ({tasks.length})</h3>
              {tasks.length === 0 ? <p className="text-neutral">No tasks created yet.</p> : (
                <ul className="space-y-3">
                  {tasks.map(task => (
                    <li key={task.id} className="p-4 bg-bground rounded-md shadow">
                      <div className="flex justify-between items-start">
                        <div>
                            <h4 className="font-semibold text-textlight">{task.title}</h4>
                            <p className="text-sm text-neutral mt-1">{task.description}</p>
                            <p className="text-xs text-neutral mt-1"><strong>Skills:</strong> {task.requiredSkills}</p>
                            {task.programName && <p className="text-xs text-neutral mt-1"><strong>Program:</strong> {task.programName}</p>}
                            {task.deadline && <p className="text-xs text-neutral mt-1"><strong>Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>}
                        </div>
                        <button onClick={() => handleDeleteTask(task.id)} className="btn-danger text-xs px-2 py-1 self-start ml-4" aria-label={`Delete task ${task.title}`}><TrashIcon className="w-4 h-4"/></button>
                      </div>
                       {/* Mini assignment overview for this task */}
                        <div className="mt-2 pt-2 border-t border-gray-300">
                            <p className="text-xs font-medium text-neutral">Assigned to:</p>
                            <ul className="text-xs list-disc list-inside pl-2">
                                {assignments.filter(a => a.taskId === task.id).map(a => (
                                    <li key={`${a.taskId}-${a.personId}`} className="text-neutral">
                                        {a.personName} - <span className={`font-semibold ${
                                            a.status === 'completed_admin_approved' ? 'text-success' : 
                                            a.status === 'declined_by_user' ? 'text-danger' : 
                                            a.status === 'pending_acceptance' ? 'text-warning' : 'text-info'
                                        }`}>{a.status.replace(/_/g, ' ')}</span>
                                    </li>
                                ))}
                                {assignments.filter(a => a.taskId === task.id).length === 0 && <li className="text-neutral">Not assigned to anyone yet.</li>}
                            </ul>
                        </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {currentPage === Page.AssignWork && currentUser.role === 'admin' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">Assign Work</h2>
            <div className="bg-surface p-6 rounded-lg shadow-md">
              <FormSelect label="Select Task to Assign" id="selectTaskForAssignment" value={selectedTaskForAssignment || ''} onChange={e => { setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); clearMessages(); }}>
                <option value="">-- Select a Task --</option>
                {tasks.map(task => (
                  <option key={task.id} value={task.id}>{task.title}</option>
                ))}
              </FormSelect>
              
              {selectedTaskForAssignment && (
                <div className="mt-4 p-3 bg-bground rounded">
                    <h4 className="font-medium text-textlight">Selected Task Details:</h4>
                    <p className="text-sm text-neutral">{tasks.find(t=>t.id === selectedTaskForAssignment)?.description}</p>
                    <p className="text-xs text-neutral mt-1"><strong>Skills:</strong> {tasks.find(t=>t.id === selectedTaskForAssignment)?.requiredSkills}</p>
                    {tasks.find(t=>t.id === selectedTaskForAssignment)?.deadline && <p className="text-xs text-neutral mt-1"><strong>Default Deadline:</strong> {new Date(tasks.find(t=>t.id === selectedTaskForAssignment)!.deadline!).toLocaleDateString()}</p>}
                </div>
              )}

              <button onClick={handleGetAssignmentSuggestion} className="btn-accent mt-4 flex items-center" disabled={!selectedTaskForAssignment || isLoadingSuggestion}>
                {isLoadingSuggestion ? <LoadingSpinner /> : <><LightBulbIcon className="w-5 h-5 mr-2"/>Get AI Suggestion</>}
              </button>

              {assignmentSuggestion && (
                <div className={`mt-4 p-3 rounded shadow-sm ${assignmentSuggestion.suggestedPersonName ? 'bg-green-50 border border-green-200' : 'bg-yellow-50 border border-yellow-200'}`}>
                  <p className="text-sm font-medium">{assignmentSuggestion.suggestedPersonName ? `AI Suggests: ${assignmentSuggestion.suggestedPersonName}` : "AI Response:"}</p>
                  <p className="text-xs text-neutral">{assignmentSuggestion.justification}</p>
                </div>
              )}

              <form onSubmit={(e) => handleAssignTask(e, assignmentSuggestion?.suggestedPersonName)} className="mt-6 space-y-4">
                <FormSelect label="Assign to Person" id="assignPerson" name="assignPerson" required
                  defaultValue={assignmentSuggestion?.suggestedPersonName ? users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName)?.id : ""}
                >
                  <option value="">-- Select a Person --</option>
                  {users.filter(u => u.role === 'user' && !assignments.some(a => a.taskId === selectedTaskForAssignment && a.personId === u.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user'))).map(user => (
                    <option key={user.id} value={user.id}>{user.displayName} ({user.position})</option>
                  ))}
                </FormSelect>
                <FormInput label="Specific Deadline (Optional - overrides task default)" id="specificDeadline" name="specificDeadline" type="date" 
                    value={assignmentForm.specificDeadline} 
                    onChange={e => setAssignmentForm({...assignmentForm, specificDeadline: e.target.value})}
                />
                <button type="submit" className="btn-primary" disabled={!selectedTaskForAssignment}>Assign Task</button>
              </form>
            </div>
          </div>
        )}

        {currentPage === Page.ViewAssignments && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-primary mb-6">My Assignments</h2>
            {assignments.filter(a => currentUser.role === 'admin' || a.personId === currentUser.id).length === 0 ? (
              <p className="text-neutral bg-surface p-4 rounded-md shadow">
                {currentUser.role === 'admin' ? "No assignments found across the system." : "You have no tasks currently assigned to you."}
              </p>
            ) : (
              <ul className="space-y-4">
                {assignments
                  .filter(a => currentUser.role === 'admin' || a.personId === currentUser.id)
                  .sort((a,b) => (a.deadline && b.deadline) ? new Date(a.deadline).getTime() - new Date(b.deadline).getTime() : 0)
                  .map(assignment => {
                    const taskDetails = tasks.find(t => t.id === assignment.taskId);
                    const isLate = assignment.deadline && new Date() > new Date(assignment.deadline) && (assignment.status === 'pending_acceptance' || assignment.status === 'accepted_by_user');
                    const isSubmittedLate = assignment.status === 'submitted_late';
                    
                    return (
                      <li key={`${assignment.taskId}-${assignment.personId}`} className="bg-surface p-4 rounded-lg shadow-md">
                        <h3 className={`text-lg font-semibold ${isLate && !isSubmittedLate ? 'text-danger' : 'text-textlight'}`}>{assignment.taskTitle}</h3>
                        {currentUser.role === 'admin' && <p className="text-sm text-neutral">Assigned to: <strong>{assignment.personName}</strong></p>}
                        <p className="text-xs text-neutral mt-1">Status: <span className={`font-medium ${
                            assignment.status === 'completed_admin_approved' ? 'text-success' :
                            assignment.status === 'declined_by_user' ? 'text-danger' :
                            assignment.status.startsWith('submitted') ? 'text-info' :
                            assignment.status === 'pending_acceptance' ? 'text-warning' : 'text-blue-500' 
                        }`}>{assignment.status.replace(/_/g, ' ')}</span>
                        {isLate && !isSubmittedLate && <span className="text-danger text-xs font-bold ml-2">(OVERDUE)</span>}
                        {isSubmittedLate && <span className="text-warning text-xs font-bold ml-2">(SUBMITTED LATE)</span>}
                        </p>
                        {taskDetails && <p className="text-sm text-neutral mt-1">{taskDetails.description}</p>}
                        {taskDetails?.requiredSkills && <p className="text-xs text-neutral mt-1"><strong>Skills:</strong> {taskDetails.requiredSkills}</p>}
                        {assignment.deadline && <p className="text-xs text-neutral mt-1"><strong>Deadline:</strong> {new Date(assignment.deadline).toLocaleDateString()}</p>}
                        {assignment.justification && assignment.justification !== 'Manually assigned by admin.' && <p className="text-xs text-neutral mt-1"><em>AI Justification: {assignment.justification}</em></p>}
                        
                        {assignment.userSubmissionDate && <p className="text-xs text-neutral mt-1"><strong>Submitted on:</strong> {new Date(assignment.userSubmissionDate).toLocaleString()}</p>}
                        {assignment.userDelayReason && <p className="text-xs text-neutral mt-1"><strong>Reason for delay:</strong> {assignment.userDelayReason}</p>}

                        <div className="mt-3 pt-3 border-t border-gray-200 space-x-2 flex flex-wrap gap-y-2">
                          {assignment.status === 'pending_acceptance' && assignment.personId === currentUser.id && (
                            <>
                              <button onClick={() => handleUserAcceptTask(assignment.taskId)} className="btn-success text-sm">Accept Task</button>
                              <button onClick={() => handleUserDeclineTask(assignment.taskId)} className="btn-danger text-sm">Decline Task</button>
                            </>
                          )}
                          {assignment.status === 'accepted_by_user' && assignment.personId === currentUser.id && (
                            <>
                              {isLate && assignmentToSubmitDelayReason !== `${assignment.taskId}-${assignment.personId}` && (
                                 <button onClick={() => setAssignmentToSubmitDelayReason(`${assignment.taskId}-${assignment.personId}`)} className="btn-warning text-sm">Submit Task (Late)</button>
                              )}
                              {assignmentToSubmitDelayReason === `${assignment.taskId}-${assignment.personId}` && isLate && (
                                <div className="w-full space-y-2 my-2 p-2 border border-warning rounded-md bg-yellow-50">
                                  <FormTextarea label="Reason for Late Submission:" id={`delayReason-${assignment.taskId}`} value={userSubmissionDelayReason} onChange={e => setUserSubmissionDelayReason(e.target.value)} placeholder="Please provide a brief reason for the delay."/>
                                  <button onClick={() => handleUserSubmitTask(assignment.taskId, userSubmissionDelayReason)} className="btn-primary text-sm">Confirm Submission</button>
                                  <button onClick={() => { setAssignmentToSubmitDelayReason(null); setUserSubmissionDelayReason(''); }} className="btn-neutral text-sm ml-2">Cancel</button>
                                </div>
                              )}
                              {!isLate && (
                                <button onClick={() => handleUserSubmitTask(assignment.taskId)} className="btn-primary text-sm">Mark as Completed / Submit</button>
                              )}
                            </>
                          )}
                          {currentUser.role === 'admin' && (assignment.status === 'submitted_on_time' || assignment.status === 'submitted_late') && (
                            <button onClick={() => handleAdminApproveTaskCompletion(assignment.taskId, assignment.personId)} className="btn-success text-sm">Approve Completion</button>
                          )}
                        </div>
                      </li>
                    );
                  })}
              </ul>
            )}
          </div>
        )}
        
        {currentPage === Page.ViewTasks && (
            <div className="space-y-6">
                <h2 className="text-2xl font-semibold text-primary mb-6">Available Tasks Overview</h2>
                 {tasks.length === 0 ? (
                    <p className="text-neutral bg-surface p-4 rounded-md shadow">No tasks are currently defined in the system.</p>
                ) : (
                <ul className="space-y-4">
                    {tasks.map(task => {
                        const taskAssignments = assignments.filter(a => a.taskId === task.id);
                        const isFullyAssignedAndAcceptedOrCompleted = taskAssignments.length > 0 && taskAssignments.every(a => a.status === 'accepted_by_user' || a.status === 'completed_admin_approved' || a.status.startsWith('submitted'));
                        const isPendingAcceptanceByAnyone = taskAssignments.some(a => a.status === 'pending_acceptance');
                        
                        let availabilityStatus = "Available";
                        let statusColor = "text-success";
                        if (isFullyAssignedAndAcceptedOrCompleted) {
                            availabilityStatus = "Assigned / In Progress / Completed";
                            statusColor = "text-neutral";
                        } else if (isPendingAcceptanceByAnyone) {
                            availabilityStatus = "Pending Acceptance";
                            statusColor = "text-warning";
                        }

                        return (
                            <li key={task.id} className="bg-surface p-4 rounded-lg shadow-md">
                                <h3 className="text-lg font-semibold text-textlight">{task.title}</h3>
                                <p className="text-sm text-neutral mt-1">{task.description}</p>
                                <p className="text-xs text-neutral mt-1"><strong>Skills:</strong> {task.requiredSkills}</p>
                                {task.programName && <p className="text-xs text-neutral mt-1"><strong>Program:</strong> {task.programName}</p>}
                                {task.deadline && <p className="text-xs text-neutral mt-1"><strong>Deadline:</strong> {new Date(task.deadline).toLocaleDateString()}</p>}
                                <p className={`text-xs font-medium mt-2 ${statusColor}`}>Availability: {availabilityStatus}</p>
                                {currentUser.role === 'admin' && taskAssignments.length > 0 && (
                                  <div className="mt-2 pt-2 border-t border-gray-200">
                                    <p className="text-xs font-medium text-neutral">Current Assignees:</p>
                                    <ul className="text-xs list-disc list-inside pl-2">
                                      {taskAssignments.map(a => (
                                        <li key={`${a.taskId}-${a.personId}`} className="text-neutral">
                                          {a.personName} - <span className={`font-semibold ${
                                              a.status === 'completed_admin_approved' ? 'text-success' : 
                                              a.status === 'declined_by_user' ? 'text-danger' : 
                                              a.status === 'pending_acceptance' ? 'text-warning' : 'text-info'
                                          }`}>{a.status.replace(/_/g, ' ')}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                            </li>
                        );
                    })}
                </ul>
                )}
            </div>
        )}

      </main>
    </div>
  );
};
