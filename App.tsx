
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import * as emailService from './src/utils/emailService'; // Corrected path
import { validatePassword } from './src/utils/validation'; // Import password validation
import * as cloudDataService from './services/cloudDataService'; // Import the new service
import LoadingSpinner from './components/LoadingSpinner';
import { UsersIcon, ClipboardListIcon, LightBulbIcon, CheckCircleIcon, TrashIcon, PlusCircleIcon, KeyIcon, BriefcaseIcon, LogoutIcon, UserCircleIcon } from './components/Icons';
import PreRegistrationFormPage from './components/PreRegistrationFormPage';
import UserTour from './components/UserTour'; // Import the new UserTour component

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

const initialAdminRegistrationState = { // For the old admin flow (if kept separately)
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
  
  // State management with useState, data loaded from cloudDataService
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
  // preRegistrationForm still uses useLocalStorage for transient client-side state
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

  // Load initial data
  useEffect(() => {
    const loadData = async () => {
      setIsLoadingAppData(true);
      try {
        const [
          loadedUsers, loadedPendingUsers, loadedTasks, loadedPrograms, 
          loadedAssignments, loadedAdminLogs, loadedCurrentUser
        ] = await Promise.all([
          cloudDataService.loadUsersFromCloud(),
          cloudDataService.loadPendingUsersFromCloud(),
          const loadedTasks = await fetch("https://task-assignment-assistant-using-ai.onrender.com/").then(res => res.json());,
          cloudDataService.loadProgramsFromCloud(),
          cloudDataService.loadAssignmentsFromCloud(),
          cloudDataService.loadAdminLogsFromCloud(),
          cloudDataService.loadCurrentUserFromCloud()
        ]);
        setUsers(loadedUsers);
        setPendingUsers(loadedPendingUsers);
        setTasks(loadedTasks);
        setPrograms(loadedPrograms);
        setAssignments(loadedAssignments);
        setAdminLogs(loadedAdminLogs);
        setCurrentUser(loadedCurrentUser);
      } catch (err) {
        console.error("Failed to load app data:", err);
        setError("Could not load application data. Please try refreshing.");
      } finally {
        setIsLoadingAppData(false);
      }
    };
    loadData();
  }, []);

  // Wrapper for setPreRegistrationForm to persist to localStorage
  const setPreRegistrationForm = (value: React.SetStateAction<typeof initialPreRegistrationFormState>) => {
    setPreRegistrationFormInternal(value);
  };


  const clearMessages = useCallback(() => { setError(null); setSuccessMessage(null); setInfoMessage(null); }, []);
  const navigateTo = useCallback((page: Page, params?: Record<string, string>) => { let hash = `#${page}`; if (params && Object.keys(params).length > 0) { hash += `?${new URLSearchParams(params).toString()}`; } if (window.location.hash !== hash) { window.location.hash = hash; } else { _setCurrentPageInternal(page); /* Ensure internal state updates if hash is same */ } }, []);

  useEffect(() => {
    if (isLoadingAppData) return; // Don't process hash until data is loaded

    const processHash = () => {
      clearMessages();
      const hash = window.location.hash.substring(1);
      const [pagePath, paramsString] = hash.split('?');
      const params = new URLSearchParams(paramsString || '');
      const targetPageFromHashPath = pagePath.toUpperCase() as Page | string;

      if (targetPageFromHashPath === Page.PreRegistration) {
        const refAdminIdFromHash = params.get('refAdminId');
        if (refAdminIdFromHash) {
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

      // Logged-in user routing logic
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

      // User Tour Logic
      if (currentUser && currentUser.role === 'user' && !localStorage.getItem(`hasCompletedUserTour_${currentUser.id}`)) {
         setTimeout(() => {
            // Check currentPage from state, not from hash processing variables, as state might not have updated yet.
            if (currentPage !== Page.Login && currentPage !== Page.PreRegistration) { 
                setShowUserTour(true);
            }
        }, 500); // Small delay to allow page to render
      }
    };

    processHash();
    window.addEventListener('hashchange', processHash);

    return () => {
      window.removeEventListener('hashchange', processHash);
    };
  }, [currentUser, navigateTo, clearMessages, users, isLoadingAppData, _setCurrentPageInternal, currentPage]); // Added currentPage to dependencies


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

  // Helper to find an admin to notify
  const getAdminToNotify = useCallback((referringAdminId?: string): User | undefined => {
    if (referringAdminId) {
      const refAdmin = users.find(u => u.id === referringAdminId && u.role === 'admin');
      if (refAdmin) return refAdmin;
    }
    return users.find(u => u.role === 'admin'); // Fallback to any admin
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

    if (users.some(u => u.email === email) || pendingUsers.some(pu => pu.email === email)) {
      setError("This email address is already registered or pending approval. Please login or use a different email.");
      return;
    }
    
    // First user must be admin and is activated directly
    if (users.length === 0) {
        if (role !== 'admin') {
            setError("The first user registered must be an Administrator. Please select the 'Admin' role.");
            return;
        }
        const newAdminUser: User = {
            id: Date.now().toString(),
            email: email,
            uniqueId: email, 
            password: password,
            role: 'admin',
            displayName: name,
            position: 'Administrator',
            userInterests: '',
            phone: '',
            notificationPreference: 'email',
        };
        const updatedUsers = [...users, newAdminUser];
        setUsers(updatedUsers);
        await cloudDataService.saveUsersToCloud(updatedUsers);
        await emailService.sendWelcomeRegistrationEmail(newAdminUser.email, newAdminUser.displayName, newAdminUser.role);
        setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' });
        setSuccessMessage(`Administrator account for ${name} created successfully! Please login. (Email simulation in console)`);
        setAuthView('login');
        return;
    }

    // Subsequent admin registrations are also direct
    if (role === 'admin') {
        const newAdminUser: User = {
            id: Date.now().toString(),
            email: email,
            uniqueId: email,
            password: password,
            role: 'admin',
            displayName: name,
            position: 'Administrator',
        };
        const updatedUsers = [...users, newAdminUser];
        setUsers(updatedUsers);
        await cloudDataService.saveUsersToCloud(updatedUsers);
        await emailService.sendWelcomeRegistrationEmail(newAdminUser.email, newAdminUser.displayName, newAdminUser.role);
        setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' });
        setSuccessMessage(`New Administrator account for ${name} created! Please login. (Email simulation in console)`);
        setAuthView('login');
        return;
    }

    // General user registrations go to pending
    if (role === 'user') {
        const newPendingUser: PendingUser = {
            id: Date.now().toString(),
            uniqueId: email, 
            displayName: name,
            email: email,
            password: password,
            role: 'user',
            submissionDate: new Date().toISOString(),
            referringAdminId: "GENERAL_REGISTRATION" 
        };
        useEffect(() => {
        fetch("https://task-assignment-assistant-using-ai.onrender.com/")
            .then(res => res.json())
            .then(data => console.log("Backend tasks:", data))
            .catch(err => console.error("Error fetching from backend:", err));
        }, []);

        const updatedPendingUsers = [...pendingUsers, newPendingUser];
        setPendingUsers(updatedPendingUsers);
        await cloudDataService.savePendingUsersToCloud(updatedPendingUsers);
        
        await emailService.sendRegistrationPendingToUserEmail(newPendingUser.email, newPendingUser.displayName);
        
        const adminToInform = getAdminToNotify();
        if (adminToInform) {
            await emailService.sendNewPendingRegistrationToAdminEmail(adminToInform.email, adminToInform.displayName, newPendingUser.displayName, newPendingUser.email);
        }
        
        setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' });
        setSuccessMessage(`Registration for ${name} submitted! It's now pending administrator approval. (Email simulations in console)`);
        setAuthView('login'); 
    }
  };
  
  const handleLogin = async (e: React.FormEvent) => { 
    e.preventDefault(); 
    clearMessages(); 
    const emailToLogin = newLoginForm.email;
    const passwordToLogin = newLoginForm.password;

    if (!emailToLogin || !passwordToLogin) {
        setError("Email and password are required.");
        return;
    }

    const user = users.find(u => u.email === emailToLogin); 
    if (user) { 
      if (user.password === passwordToLogin) { 
        setCurrentUser(user); 
        await cloudDataService.saveCurrentUserToCloud(user);
        setNewLoginForm({ email: '', password: '' }); 
        setSuccessMessage(`Login successful! Welcome back, ${user.displayName}.`); 
        // Navigation and tour logic handled by useEffect based on currentUser update
      } else { 
        setError("Invalid password."); 
      } 
    } else { 
      setError("Email address not found or account not yet approved/created."); 
    } 
  };

  const handleForgotPassword = async () => { 
    clearMessages(); 
    if (!newLoginForm.email.trim()) { 
      setError("Please enter your Email Address first to check for password recovery options."); 
      return; 
    } 
    const userToCheck = users.find(u => u.email === newLoginForm.email); 
    if (userToCheck) { 
      await emailService.sendPasswordResetRequestEmail(userToCheck.email, userToCheck.displayName);
      setInfoMessage(`Password Recovery for '${userToCheck.displayName}': A simulated password reset link has been "sent" to ${userToCheck.email}. (Check console for email simulation)`); 
    } else { 
      setError("Email Address not found in the system."); 
    } 
  };
  
 const handlePreRegistrationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!preRegistrationForm.isReferralLinkValid || !preRegistrationForm.referringAdminId) {
        setError("Invalid pre-registration attempt. Please use a valid link from an administrator.");
        return;
    }
    if (!preRegistrationForm.uniqueId.trim() || !preRegistrationForm.displayName.trim() || !preRegistrationForm.email.trim() || !preRegistrationForm.password.trim()) {
        setError("Your Desired System ID, Display Name, Email, and Password are required.");
        return;
    }
    if (preRegistrationForm.password !== preRegistrationForm.confirmPassword) {
        setError("Passwords do not match.");
        return;
    }

    const passwordValidationResult = validatePassword(preRegistrationForm.password);
    if (!passwordValidationResult.isValid) {
      setError(passwordValidationResult.errors.join(' '));
      return;
    }

    if (users.some(u => u.uniqueId === preRegistrationForm.uniqueId) || pendingUsers.some(pu => pu.uniqueId === preRegistrationForm.uniqueId)) {
        setError("This System ID has already been used or is pending approval. Please choose a different one.");
        return;
    }
    if (users.some(u => u.email === preRegistrationForm.email) || pendingUsers.some(pu => pu.email === preRegistrationForm.email)) {
        setError("This email address is already in use or pending approval. Please use a different email.");
        return;
    }

    const newPendingUser: PendingUser = {
        id: Date.now().toString(),
        uniqueId: preRegistrationForm.uniqueId,
        displayName: preRegistrationForm.displayName,
        email: preRegistrationForm.email,
        password: preRegistrationForm.password, 
        role: 'user', 
        submissionDate: new Date().toISOString(),
        referringAdminId: preRegistrationForm.referringAdminId,
    };
    const updatedPendingUsers = [...pendingUsers, newPendingUser];
    setPendingUsers(updatedPendingUsers);
    await cloudDataService.savePendingUsersToCloud(updatedPendingUsers);

    await emailService.sendPreRegistrationSubmittedToUserEmail(
        newPendingUser.email!, 
        newPendingUser.displayName,
        preRegistrationForm.referringAdminDisplayName || "Administrator"
    );

    const referringAdmin = users.find(u => u.id === preRegistrationForm.referringAdminId);
    if (referringAdmin) {
        await emailService.sendPreRegistrationNotificationToAdminEmail(
            referringAdmin.email,
            referringAdmin.displayName,
            newPendingUser.displayName,
            newPendingUser.uniqueId
        );
    }

    setPreRegistrationForm(initialPreRegistrationFormState); 
    setSuccessMessage(`Pre-registration for ${newPendingUser.displayName} submitted successfully! It's now pending administrator approval. (Email simulations in console)`);
  };


  const handleLogout = async () => { 
      clearMessages(); 
      setCurrentUser(null); 
      await cloudDataService.saveCurrentUserToCloud(null);
      setNewLoginForm({ email: '', password: '' }); 
      setAuthView('login'); 
      setPreRegistrationForm(initialPreRegistrationFormState); 
      setShowUserTour(false); 
      setSuccessMessage("You have been logged out."); 
      navigateTo(Page.Login); 
  };
  
  const handleUpdateProfile = async (e: React.FormEvent) => { 
    e.preventDefault(); 
    if (!currentUser) return; 
    clearMessages(); 
    if (!userForm.displayName.trim()) { setError("Display name cannot be empty."); return; } 
    if (!userForm.email.trim() || !/\S+@\S+\.\S+/.test(userForm.email)) { setError("A valid email address is required."); return; } 
    if (userForm.email !== currentUser.email && users.some(u => u.email === userForm.email && u.id !== currentUser.id)) { setError("This email address is already in use by another account."); return; } 
    if (userForm.uniqueId !== currentUser.uniqueId && users.some(u => u.uniqueId === userForm.uniqueId && u.id !== currentUser.id)) { setError("This System ID is already in use by another account."); return; } 
    
    let newPassword = currentUser.password; 
    if (userForm.password) { 
      if (userForm.password !== userForm.confirmPassword) { setError("New passwords do not match."); return; } 
      const passwordValidationResult = validatePassword(userForm.password);
      if (!passwordValidationResult.isValid) {
        setError(passwordValidationResult.errors.join(' '));
        return;
      }
      newPassword = userForm.password; 
    } 
    
    const updatedUser: User = { 
      ...currentUser, 
      email: userForm.email, 
      uniqueId: currentUser.role === 'admin' ? userForm.uniqueId : currentUser.uniqueId, 
      displayName: userForm.displayName, 
      position: userForm.position, 
      userInterests: userForm.userInterests, 
      phone: userForm.phone, 
      notificationPreference: userForm.notificationPreference, 
      password: newPassword, 
    }; 
    const updatedUsers = users.map(u => (u.id === currentUser.id ? updatedUser : u));
    setUsers(updatedUsers); 
    await cloudDataService.saveUsersToCloud(updatedUsers);
    setCurrentUser(updatedUser); 
    await cloudDataService.saveCurrentUserToCloud(updatedUser);
    setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' })); 
    setSuccessMessage("Profile updated successfully."); 
    navigateTo(currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments); 
  };
  
  const handleSaveOrApproveUserByAdmin = async (e: React.FormEvent) => { 
    e.preventDefault(); 
    clearMessages(); 
    if (!userForm.email.trim() || !/\S+@\S+\.\S+/.test(userForm.email)) { setError("A valid email address is required."); return; } 
    if (!userForm.uniqueId.trim() || !userForm.displayName.trim() || !userForm.position.trim()) { setError("Email, System ID, Display Name, and Position are required."); return; } 
    
    const isEditing = !!editingUserId && !approvingPendingUser; 
    const isApproving = !!approvingPendingUser; 
    const isAddingNew = !isEditing && !isApproving; 

    let finalPassword = '';

    if (isAddingNew || isApproving) { 
        if (!userForm.password) { setError("Password is required for new/approved users."); return; }
        if (userForm.password !== userForm.confirmPassword) { setError("Passwords do not match."); return; } 
        const passwordValidationResult = validatePassword(userForm.password);
        if (!passwordValidationResult.isValid) {
          setError(passwordValidationResult.errors.join(' '));
          return;
        }
        finalPassword = userForm.password;
    } else if (isEditing) { 
        const userToUpdate = users.find(u => u.id === editingUserId);
        if (!userToUpdate) { setError("User not found for editing."); return; } 
        if (userForm.password) { 
          if (userForm.password !== userForm.confirmPassword) { 
              setError("New passwords do not match."); return; 
          } 
          const passwordValidationResult = validatePassword(userForm.password);
          if (!passwordValidationResult.isValid) {
            setError(passwordValidationResult.errors.join(' '));
            return;
          }
          finalPassword = userForm.password;
        } else {
          finalPassword = userToUpdate.password; 
        }
    }
     
    const targetId = editingUserId || approvingPendingUser?.id; 
    if (users.some(u => u.email === userForm.email && u.id !== targetId)) { setError("This email address is already in use by another account."); return;} 
    if (users.some(u => u.uniqueId === userForm.uniqueId && u.id !== targetId)) { setError("This System ID is already in use by another account."); return;} 
    if (isAddingNew && pendingUsers.some(pu => pu.uniqueId === userForm.uniqueId)) { 
        setError("This System ID is currently pending approval for another user. Please resolve the pending user or choose a different ID."); return; 
    }
    if (isAddingNew && pendingUsers.some(pu => pu.email === userForm.email)) { 
        setError("This Email is currently pending approval for another user. Please resolve the pending user or choose a different Email."); return; 
    }
    
    const adminActor = currentUser; 
    if (!adminActor) { setError("Admin session expired. Please re-login."); return; }

    if (isEditing) { 
      const userToUpdate = users.find(u => u.id === editingUserId); 
      if (!userToUpdate) { setError("User not found for editing."); return; } 
      const updatedUserRec: User = { 
        ...userToUpdate, 
        email: userForm.email, 
        uniqueId: userForm.uniqueId, 
        displayName: userForm.displayName, 
        position: userForm.position, 
        userInterests: userForm.userInterests, 
        phone: userForm.phone, 
        notificationPreference: userForm.notificationPreference, 
        role: userForm.role, 
        password: finalPassword, 
      }; 
      const newUsersList = users.map(u => u.id === editingUserId ? updatedUserRec : u);
      setUsers(newUsersList); 
      await cloudDataService.saveUsersToCloud(newUsersList);
      setSuccessMessage(`User '${updatedUserRec.displayName}' updated successfully.`); 
    } else { 
      const newUserRec: User = { 
          id: approvingPendingUser ? approvingPendingUser.id : Date.now().toString(), 
          email: userForm.email, 
          uniqueId: userForm.uniqueId, 
          password: finalPassword, 
          displayName: userForm.displayName, 
          position: userForm.position, 
          userInterests: userForm.userInterests, 
          phone: userForm.phone, 
          notificationPreference: userForm.notificationPreference, 
          role: userForm.role, 
          referringAdminId: approvingPendingUser ? approvingPendingUser.referringAdminId : currentUser?.id, 
      }; 
      const newUsersList = [...users, newUserRec];
      setUsers(newUsersList); 
      await cloudDataService.saveUsersToCloud(newUsersList);

      if (approvingPendingUser) { 
        const newPendingUsersList = pendingUsers.filter(pu => pu.id !== approvingPendingUser.id);
        setPendingUsers(newPendingUsersList); 
        await cloudDataService.savePendingUsersToCloud(newPendingUsersList);
        await emailService.sendAccountActivatedByAdminEmail(newUserRec.email, newUserRec.displayName, adminActor.displayName);
        setSuccessMessage(`User '${newUserRec.displayName}' approved from pending list. Account activated. (Email simulation in console)`); 
      } else { 
        await emailService.sendWelcomeRegistrationEmail(newUserRec.email, newUserRec.displayName, newUserRec.role); 
        await emailService.sendAccountActivatedByAdminEmail(newUserRec.email, newUserRec.displayName, adminActor.displayName);
        setSuccessMessage(`User '${newUserRec.displayName}' added directly by admin. Account activated. (Email simulation in console)`); 
      } 
    } 
    setUserForm(initialUserFormData); 
    setEditingUserId(null); 
    setApprovingPendingUser(null); 
  };

  const handleEditUserByAdmin = (user: User) => { setApprovingPendingUser(null); setEditingUserId(user.id); setUserForm({ email: user.email, uniqueId: user.uniqueId, displayName: user.displayName, position: user.position, userInterests: user.userInterests || '', phone: user.phone || '', notificationPreference: user.notificationPreference || 'none', role: user.role, password: '', confirmPassword: '', referringAdminId: user.referringAdminId || '' }); clearMessages(); };
  
  const handleInitiateApprovePendingUser = (pendingUser: PendingUser) => { 
    setEditingUserId(null); 
    setApprovingPendingUser(pendingUser); 
    setUserForm({ 
        ...initialUserFormData, 
        uniqueId: pendingUser.uniqueId, 
        displayName: pendingUser.displayName, 
        email: pendingUser.email || '', 
        password: pendingUser.password || '', 
        confirmPassword: pendingUser.password || '', 
        role: pendingUser.role || 'user', 
        referringAdminId: pendingUser.referringAdminId || '', 
    }); 
    clearMessages(); 
    let infoMsg = `Reviewing pending user: ${pendingUser.displayName} (ID: ${pendingUser.uniqueId}). `;
    if (pendingUser.email && pendingUser.password) {
        infoMsg += "Email, password, and role were provided by the user. Review other details. You may override the password if needed.";
    } else if (pendingUser.email) {
        infoMsg += "Email and role were provided by the user. Please set a password and review other details.";
    } else {
        infoMsg += "Please set their email, password, complete their profile, and assign a role.";
    }
    setInfoMessage(infoMsg);
  };

  const handleRejectPendingUser = async (pendingUserId: string) => { 
      const newPendingUsersList = pendingUsers.filter(pu => pu.id !== pendingUserId);
      setPendingUsers(newPendingUsersList); 
      await cloudDataService.savePendingUsersToCloud(newPendingUsersList);
      setSuccessMessage("Pending user request rejected."); 
      if (approvingPendingUser?.id === pendingUserId) { setApprovingPendingUser(null); setUserForm(initialUserFormData); } 
  };
  const handleDeleteUser = async (userId: string) => { 
      if (currentUser?.role !== 'admin') { setError("Only admins can delete users."); return; } 
      if (userId === currentUser?.id) { setError("You cannot delete your own account."); return; } 
      const newUsersList = users.filter(u => u.id !== userId);
      setUsers(newUsersList); 
      await cloudDataService.saveUsersToCloud(newUsersList);
      const newAssignmentsList = assignments.filter(a => a.personId !== userId);
      setAssignments(newAssignmentsList); 
      await cloudDataService.saveAssignmentsToCloud(newAssignmentsList);
      setSuccessMessage("User deleted successfully."); 
      if(editingUserId === userId) { setEditingUserId(null); setUserForm(initialUserFormData); } 
  };
  const handleAddProgram = async (e: React.FormEvent) => { 
      e.preventDefault(); clearMessages(); 
      if (!programForm.name.trim()) { setError("Program name cannot be empty."); return; } 
      const newProgramRec: Program = { ...programForm, id: Date.now().toString() }; 
      const newProgramsList = [...programs, newProgramRec];
      setPrograms(newProgramsList); 
      await cloudDataService.saveProgramsToCloud(newProgramsList);
      setProgramForm({ name: '', description: '' }); 
      setSuccessMessage(`Program "${newProgramRec.name}" added successfully.`); 
  };
  const handleDeleteProgram = async (id: string) => { 
      clearMessages(); 
      const isProgramInUse = tasks.some(task => task.programId === id); 
      let newTasksList = [...tasks];
      if (isProgramInUse) { 
          if (!window.confirm("This program is linked to tasks. Deleting it will unlink these tasks. Are you sure?")) { return; } 
          newTasksList = tasks.map(task => task.programId === id ? {...task, programId: undefined, programName: undefined } : task);
          setTasks(newTasksList);
          await cloudDataService.saveTasksToCloud(newTasksList);
      } 
      const newProgramsList = programs.filter(p => p.id !== id);
      setPrograms(newProgramsList); 
      await cloudDataService.saveProgramsToCloud(newProgramsList);
      setSuccessMessage("Program deleted successfully."); 
  };
  const handleAddTask = async (e: React.FormEvent) => { 
      e.preventDefault(); clearMessages(); 
      if (!taskForm.title.trim()) { setError("Task title cannot be empty."); return; } 
      const program = programs.find(p => p.id === taskForm.programId); 
      const newTaskRec: Task = { id: Date.now().toString(), title: taskForm.title, description: taskForm.description, requiredSkills: taskForm.requiredSkills, programId: taskForm.programId || undefined, programName: program ? program.name : undefined, deadline: taskForm.deadline || undefined }; 
      const newTasksList = [...tasks, newTaskRec];
      setTasks(newTasksList); 
      await cloudDataService.saveTasksToCloud(newTasksList);
      setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' }); 
      setSuccessMessage(`Task "${newTaskRec.title}" added successfully.`); 
  };
  const handleDeleteTask = async (id: string) => { 
      clearMessages(); 
      const newTasksList = tasks.filter(t => t.id !== id);
      setTasks(newTasksList); 
      await cloudDataService.saveTasksToCloud(newTasksList);
      const newAssignmentsList = assignments.filter(a => a.taskId !== id);
      setAssignments(newAssignmentsList);  
      await cloudDataService.saveAssignmentsToCloud(newAssignmentsList);
      setSuccessMessage("Task deleted successfully."); 
  };

  const fetchAssignmentSuggestion = useCallback(async () => { if (!selectedTaskForAssignment) { setError("Please select a task first."); return; } const task = tasks.find(t => t.id === selectedTaskForAssignment); if (!task) { setError("Selected task not found."); return; } const activeUserIdsWithTasks = assignments .filter(a => a.status === 'pending_acceptance' || a.status === 'accepted_by_user') .map(a => a.personId); const trulyAvailableUsers = users.filter(u => u.role === 'user' && !activeUserIdsWithTasks.includes(u.id)); if (trulyAvailableUsers.length === 0) { setError("No users available to assign tasks to (either no users, or all users have active tasks)."); setAssignmentSuggestion({ suggestedPersonName: null, justification: "No users (non-admin) available without active tasks in the system." }); return; } setIsLoadingSuggestion(true); clearMessages(); setAssignmentSuggestion(null); try { const suggestion = await getAssignmentSuggestion(task, trulyAvailableUsers, programs, assignments); setAssignmentSuggestion(suggestion); if (!suggestion?.suggestedPersonName && suggestion?.justification) { setInfoMessage(suggestion.justification); } } catch (err) { console.error("Error fetching suggestion:", err); const errorMessage = err instanceof Error ? err.message : "An unknown error occurred."; setError(errorMessage); setAssignmentSuggestion({ suggestedPersonName: null, justification: errorMessage }); } finally { setIsLoadingSuggestion(false); }  }, [selectedTaskForAssignment, tasks, users, programs, assignments, clearMessages]);
  
  const handleConfirmAssignmentByAdmin = async () => {  
    if (!selectedTaskForAssignment || !assignmentSuggestion || !assignmentSuggestion.suggestedPersonName) { setError("No valid AI suggestion to confirm."); return; } 
    if (!currentUser || currentUser.role !== 'admin') { setError("Admin action required."); return;}
    const task = tasks.find(t => t.id === selectedTaskForAssignment); 
    const person = users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName && u.role === 'user'); 
    if (!task || !person) { setError("Selected task or suggested user not found for AI assignment."); return; } 
    const personStillHasActiveTask = assignments.some( a => a.personId === person.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user') ); 
    if (personStillHasActiveTask) { setError(`${person.displayName} already has an active task. Cannot assign another until their current task is completed or declined.`); return; } 
    if (assignments.find(a => a.taskId === task.id && (a.status !== 'declined_by_user' && a.status !== 'completed_admin_approved'))) { if (!window.confirm(`Task "${task.title}" is already assigned or pending. Reassign to ${person.displayName} (pending their acceptance)? This will clear previous active assignment for this task.`)) { return; } } 
    const assignmentDeadline = assignmentForm.specificDeadline || task.deadline; 
    const newAssignmentRec: Assignment = { taskId: task.id, personId: person.id, taskTitle: task.title, personName: person.displayName, justification: assignmentSuggestion.justification, status: 'pending_acceptance', deadline: assignmentDeadline }; 
    const newAssignmentsList = [...assignments.filter(a => a.taskId !== task.id || (a.status === 'declined_by_user' || a.status === 'completed_admin_approved')), newAssignmentRec];
    setAssignments(newAssignmentsList); 
    await cloudDataService.saveAssignmentsToCloud(newAssignmentsList);
    
    await emailService.sendTaskProposalEmail(person.email, person.displayName, task.title, currentUser.displayName, assignmentDeadline);

    setAssignmentSuggestion(null); 
    setSelectedTaskForAssignment(null); 
    setAssignmentForm({ specificDeadline: '' }); 
    setSuccessMessage(`Task "${task.title}" proposed to ${person.displayName}. (Email simulation in console)`);  
  };
  
  const handleUserAssignmentResponse = async (assignment: Assignment, accepted: boolean) => { 
    clearMessages(); 
    if (!currentUser) return; 
    const assignmentIndex = assignments.findIndex(a => a.taskId === assignment.taskId && a.personId === currentUser.id); 
    if (assignmentIndex === -1) { setError("Assignment not found or action not permitted."); return; } 
    
    const adminToNotify = getAdminToNotify(assignment.personId ? users.find(u=>u.id === assignment.personId)?.referringAdminId : undefined);
    let adminNotificationMessage = '';
    let updatedAssignmentsList: Assignment[];

    if (accepted) { 
      updatedAssignmentsList = assignments.map((a, idx) => idx === assignmentIndex ? { ...a, status: 'accepted_by_user' as AssignmentStatus } : a ); 
      setSuccessMessage(`You have accepted the task: "${assignment.taskTitle}".`); 
      adminNotificationMessage = 'accepted';
    } else { 
      updatedAssignmentsList = assignments.map((a, idx) => idx === assignmentIndex ? { ...a, status: 'declined_by_user' as AssignmentStatus } : a ); 
      setSuccessMessage(`You have declined the task: "${assignment.taskTitle}".`); 
      adminNotificationMessage = 'declined';
    } 
    setAssignments(updatedAssignmentsList);
    await cloudDataService.saveAssignmentsToCloud(updatedAssignmentsList);

    if (adminToNotify && currentUser) {
        await emailService.sendTaskStatusUpdateToAdminEmail(adminToNotify.email, adminToNotify.displayName, currentUser.displayName, assignment.taskTitle, adminNotificationMessage);
        setInfoMessage(`Admin ${adminToNotify.displayName} would be notified. (Email simulation in console)`);
    }
  };
  
  const handleCompleteTaskByUser = async (assignment: Assignment, delayReason?: string) => { 
    clearMessages(); 
    if (!currentUser || currentUser.id !== assignment.personId) { setError("Action not permitted."); return; } 
    const submissionDate = new Date(); 
    const isLate = assignment.deadline ? submissionDate > new Date(new Date(assignment.deadline).setHours(23, 59, 59, 999)) : false; 
    const newStatus: AssignmentStatus = isLate ? 'submitted_late' : 'submitted_on_time'; 
    const updatedAssignmentsList = assignments.map(a => a.taskId === assignment.taskId && a.personId === currentUser.id ? { ...a, status: newStatus, userSubmissionDate: submissionDate.toISOString(), userDelayReason: isLate ? delayReason : undefined, } : a ); 
    setAssignments(updatedAssignmentsList); 
    await cloudDataService.saveAssignmentsToCloud(updatedAssignmentsList);
    
    const adminToNotify = getAdminToNotify(currentUser.referringAdminId);
    if (adminToNotify) {
        await emailService.sendTaskStatusUpdateToAdminEmail(adminToNotify.email, adminToNotify.displayName, currentUser.displayName, assignment.taskTitle, `submitted (${isLate ? 'late' : 'on time'})`);
    }
    
    setSuccessMessage(`Task "${assignment.taskTitle}" marked as completed. ${isLate ? 'It was submitted late.' : ''} (Email simulation in console)`); 
    setAssignmentToSubmitDelayReason(null); 
    setUserSubmissionDelayReason('');  
  };

  const handleAdminApproveCompletion = async (assignment: Assignment) => { 
    clearMessages(); 
    if (!currentUser || currentUser.role !== 'admin') { setError("Only admins can approve task completion."); return; } 
    const updatedAssignmentsList = assignments.map(a => a.taskId === assignment.taskId && a.personId === assignment.personId ? { ...a, status: 'completed_admin_approved' as AssignmentStatus } : a ); 
    setAssignments(updatedAssignmentsList); 
    await cloudDataService.saveAssignmentsToCloud(updatedAssignmentsList);
    
    const userToNotify = users.find(u => u.id === assignment.personId); 
    if (userToNotify) {
      await emailService.sendTaskCompletionApprovedToUserEmail(userToNotify.email, userToNotify.displayName, assignment.taskTitle, currentUser.displayName);
    }
    setSuccessMessage(`Submission for task "${assignment.taskTitle}" by ${assignment.personName} has been approved. (Email simulation in console)`); 
  };

  const handleAdminUnassignTask = async (assignmentToClear: Assignment) => { 
      if (!currentUser || currentUser.role !== 'admin') { setError("Action not permitted."); return; } 
      const newAssignmentsList = assignments.filter(a => !(a.taskId === assignmentToClear.taskId && a.personId === assignmentToClear.personId));
      setAssignments(newAssignmentsList); 
      await cloudDataService.saveAssignmentsToCloud(newAssignmentsList);
      setSuccessMessage(`Assignment "${assignmentToClear.taskTitle}" for ${assignmentToClear.personName} has been cleared/unassigned.`); 
  };
  const handleAddAdminLogEntry = async (e: React.FormEvent) => { 
      e.preventDefault(); 
      if (!adminLogText.trim() && !adminLogImageFile) { setError("Please provide some text or an image for the log entry."); return; } 
      if (!currentUser || currentUser.role !== 'admin') return; 
      setIsSubmittingLog(true); clearMessages(); 
      let imagePreviewUrl: string | undefined = undefined; 
      if (adminLogImageFile) { 
          try { 
              imagePreviewUrl = await new Promise((resolve, reject) => { 
                  const reader = new FileReader(); 
                  reader.onload = () => resolve(reader.result as string); 
                  reader.onerror = reject; 
                  reader.readAsDataURL(adminLogImageFile); 
              }); 
          } catch (err) { 
              console.error("Error reading image file:", err); 
              setError("Failed to read image file. Please try a different image or ensure it's not too large."); 
              setIsSubmittingLog(false); return; 
          } 
      } 
      const newLogEntryRec: AdminLogEntry = { id: Date.now().toString(), adminId: currentUser.id, adminDisplayName: currentUser.displayName, timestamp: new Date().toISOString(), logText: adminLogText.trim(), ...(imagePreviewUrl && { imagePreviewUrl }), }; 
      const newAdminLogsList = [newLogEntryRec, ...adminLogs];
      setAdminLogs(newAdminLogsList); 
      await cloudDataService.saveAdminLogsToCloud(newAdminLogsList);
      setAdminLogText(''); setAdminLogImageFile(null); 
      const fileInput = document.getElementById('admin-log-image-file') as HTMLInputElement; 
      if (fileInput) fileInput.value = ''; 
      setSuccessMessage("Log entry added successfully."); 
      setIsSubmittingLog(false); 
  };
  const handleDeleteAdminLogEntry = async (logId: string) => { 
      if (!currentUser || currentUser.role !== 'admin') return; 
      const newAdminLogsList = adminLogs.filter(log => log.id !== logId);
      setAdminLogs(newAdminLogsList); 
      await cloudDataService.saveAdminLogsToCloud(newAdminLogsList);
      setSuccessMessage("Log entry deleted."); 
  };

  const handleUserTourClose = (completed: boolean) => {
    if (currentUser && currentUser.role === 'user') {
        // This localStorage item is specific to the tour and not part of cloudDataService
        localStorage.setItem(`hasCompletedUserTour_${currentUser.id}`, 'true');
    }
    setShowUserTour(false);
    if (completed) {
        setSuccessMessage("You're all set! Explore the app at your own pace.");
    }
  };

  if (isLoadingAppData) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-bground">
        <LoadingSpinner />
        <p className="text-primary mt-2">Loading application data...</p>
      </div>
    );
  }

  const renderNewAuthLoginPage = () => (
    <div className="w-full max-w-sm space-y-6">
      <h2 className="text-center text-3xl font-bold text-textlight">LOGIN NOW</h2>
      <form onSubmit={handleLogin} className="space-y-6">
        <AuthFormInput 
          id="new-login-email" 
          type="email" 
          aria-label="Enter your email"
          placeholder="Enter your email" 
          value={newLoginForm.email} 
          onChange={e => setNewLoginForm(prev => ({...prev, email: e.target.value}))} 
          required 
          autoFocus
        />
        <AuthFormInput 
          id="new-login-password" 
          type="password" 
          aria-label="Enter your password"
          placeholder="Enter your password" 
          value={newLoginForm.password} 
          onChange={e => setNewLoginForm(prev => ({...prev, password: e.target.value}))} 
          required 
        />
        <button 
          type="submit" 
          className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
        >
          Login Now
        </button>
      </form>
      <div className="text-center">
        <button 
            type="button" 
            onClick={handleForgotPassword} 
            className="text-sm text-authLink hover:underline"
          >
            Forgot password?
          </button>
      </div>
      <p className="text-center text-sm text-textlight">
        don't have an account?{' '}
        <button 
          type="button" 
          onClick={() => { setAuthView('register'); clearMessages(); setNewLoginForm({email: '', password: ''}); }} 
          className="font-medium text-authLink hover:underline"
        >
          register now
        </button>
      </p>
    </div>
  );

  const renderNewAuthRegisterPage = () => (
     <div className="w-full max-w-sm space-y-5">
      <h2 className="text-center text-3xl font-bold text-textlight">REGISTER NOW</h2>
       {users.length === 0 && (
        <p className="text-center text-sm text-primary bg-blue-50 p-2 rounded-md">
          Welcome! As the first user, please register as an <strong>Admin</strong>.
        </p>
      )}
      <form onSubmit={handleNewRegistration} className="space-y-4">
        <AuthFormInput 
          id="new-reg-name" 
          type="text" 
          aria-label="Enter your name"
          placeholder="Enter your name" 
          value={newRegistrationForm.name} 
          onChange={e => setNewRegistrationForm(prev => ({...prev, name: e.target.value}))} 
          required 
          autoFocus
        />
        <AuthFormInput 
          id="new-reg-email" 
          type="email" 
          aria-label="Enter your email"
          placeholder="Enter your email" 
          value={newRegistrationForm.email} 
          onChange={e => setNewRegistrationForm(prev => ({...prev, email: e.target.value}))} 
          required 
        />
        <div>
            <AuthFormInput 
              id="new-reg-password" 
              type="password" 
              aria-label="Enter your password"
              placeholder="Enter your password" 
              value={newRegistrationForm.password} 
              onChange={e => setNewRegistrationForm(prev => ({...prev, password: e.target.value}))} 
              required 
            />
            <p className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
        </div>
        <AuthFormInput 
          id="new-reg-confirm-password" 
          type="password" 
          aria-label="Enter your confirm password"
          placeholder="Enter your confirm password" 
          value={newRegistrationForm.confirmPassword} 
          onChange={e => setNewRegistrationForm(prev => ({...prev, confirmPassword: e.target.value}))} 
          required 
        />
        <AuthFormSelect 
            id="new-reg-role" 
            aria-label="Select user type"
            value={newRegistrationForm.role} 
            onChange={e => setNewRegistrationForm(prev => ({...prev, role: e.target.value as Role}))}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </AuthFormSelect>
        <button 
          type="submit" 
          className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
        >
          Register Now
        </button>
      </form>
      <p className="text-center text-sm text-textlight">
        already have an account?{' '}
        <button 
          type="button" 
          onClick={() => { setAuthView('login'); clearMessages(); setNewRegistrationForm({name: '', email: '', password: '', confirmPassword: '', role: 'user'}); }} 
          className="font-medium text-authLink hover:underline"
        >
          login now
        </button>
      </p>
    </div>
  );
  
  const renderPage = () => {
    if (!currentUser) { 
      console.error("Error: renderPage called without currentUser, but auth/pre-reg flow should handle this.");
      // This path should ideally not be hit if routing logic is correct and data is loaded.
      // If hit, it might be during initial load or a state inconsistency.
      // Navigating to login or showing spinner is a safe fallback.
       if (window.location.hash !== `#${Page.Login}` && window.location.hash !== `#${Page.PreRegistration}`) {
         navigateTo(Page.Login);
       }
      return <LoadingSpinner />; 
    }
    
    switch (currentPage) {
      case Page.Dashboard: const isAdminDashboard = currentUser.role === 'admin'; return ( <div> <div className="text-center"> <h2 className="text-3xl font-semibold mb-4 text-primary">Welcome, {currentUser.displayName}!</h2> <p className="text-lg text-neutral">Select an option from the navigation to get started.</p> <p className="mt-2 text-md text-neutral">Your role: <span className="font-semibold capitalize">{currentUser.role}</span>. Position: <span className="font-semibold">{currentUser.position}</span></p> <p className="text-sm text-neutral">Logged in as: {currentUser.email} (System ID: {currentUser.uniqueId})</p> </div> {isAdminDashboard && ( <div className="mt-8 pt-6 border-t border-gray-300"> <h3 className="text-xl font-semibold mb-4 text-secondary flex items-center"> <ClipboardListIcon className="w-6 h-6 mr-2" /> Admin Activity Log </h3> <form onSubmit={handleAddAdminLogEntry} className="bg-surface shadow-md rounded-lg p-4 mb-6 space-y-3"> <FormTextarea id="admin-log-text" label="New Log Entry / Announcement" value={adminLogText} onChange={(e) => setAdminLogText(e.target.value)} placeholder="Enter log details, an announcement, or a note..." aria-label="New log entry text" /> <div> <label htmlFor="admin-log-image-file" className="block text-sm font-medium text-textlight">Attach Photo (Optional)</label> <input id="admin-log-image-file" type="file" accept="image/*" onChange={(e) => setAdminLogImageFile(e.target.files ? e.target.files[0] : null)} className="mt-1 block w-full text-sm text-neutral file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-primary file:text-white hover:file:bg-blue-600" aria-label="Attach photo to log entry" /> </div> {adminLogImageFile && ( <div className="mt-2 text-xs text-neutral">Selected file: {adminLogImageFile.name}</div> )} <button type="submit" className="btn-secondary" disabled={isSubmittingLog || (!adminLogText.trim() && !adminLogImageFile)}> {isSubmittingLog ? 'Adding Log...' : 'Add Log Entry'} </button> </form> {adminLogs.length === 0 ? ( <p className="text-neutral">No activity logs yet.</p> ) : ( <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow-inner"> {adminLogs.map(log => ( <div key={log.id} className="bg-surface shadow rounded-lg p-4 relative"> <button onClick={() => handleDeleteAdminLogEntry(log.id)} className="absolute top-2 right-2 text-danger hover:text-red-700 p-1 transition-colors" aria-label={`Delete log entry made on ${new Date(log.timestamp).toLocaleString()}`} > <TrashIcon className="w-4 h-4" /> </button> <p className="text-xs text-neutral mb-1"> Posted by: <strong className="text-textlight">{log.adminDisplayName}</strong> </p> <p className="text-xs text-neutral"> {new Date(log.timestamp).toLocaleString()} </p> {log.logText && <p className="text-textlight mt-2 whitespace-pre-wrap">{log.logText}</p>} {log.imagePreviewUrl && ( <div className="mt-3"> <img src={log.imagePreviewUrl} alt={`Log attachment by ${log.adminDisplayName} on ${new Date(log.timestamp).toLocaleDateString()}`} className="max-w-full h-auto rounded-md border border-gray-200" style={{ maxHeight: '300px' }} /> </div> )} </div> ))} </div> )} </div> )} </div> );
      case Page.UserProfile: 
        const referringAdmin = users.find(u => u.id === currentUser.referringAdminId); 
        return ( 
          <div> 
            <h2 className="text-2xl font-semibold mb-4 text-primary flex items-center"><UserCircleIcon className="w-7 h-7 mr-2" /> My Profile</h2> 
            <form onSubmit={handleUpdateProfile} className="bg-surface shadow-lg rounded-lg p-6 space-y-4 max-w-lg mx-auto"> 
              <FormInput id="profile-email" label="Email Address (Login)" type="email" value={userForm.email} onChange={e => setUserForm(prev => ({ ...prev, email: e.target.value }))} required />
              <FormInput id="profile-uniqueId" label="Username ID" type="text" value={userForm.uniqueId} onChange={e => setUserForm(prev => ({ ...prev, uniqueId: e.target.value }))} required disabled={currentUser.role !== 'admin'} title={currentUser.role !== 'admin' ? "System ID can only be changed by an administrator" : "Admin can change System ID"} />
              <FormInput id="profile-displayName" label="Display Name" type="text" value={userForm.displayName} onChange={e => setUserForm(prev => ({ ...prev, displayName: e.target.value }))} required /> 
              <FormInput id="profile-position" label="Position" type="text" value={userForm.position} onChange={e => setUserForm(prev => ({ ...prev, position: e.target.value }))} required={currentUser.role === 'admin'} disabled={currentUser.role !== 'admin'} /> 
              {referringAdmin && <FormInput id="profile-referringAdmin" label="Referring Administrator (Read-only)" type="text" value={`${referringAdmin.displayName} (${referringAdmin.uniqueId})`} readOnly disabled />} 
              <FormTextarea id="profile-userInterests" label="My Interests" value={userForm.userInterests || ''} onChange={e => setUserForm(prev => ({ ...prev, userInterests: e.target.value }))} placeholder="e.g., AI, Event Planning, Writing"/> 
              <FormInput id="profile-phone" label="Phone (Contact)" type="tel" value={userForm.phone || ''} onChange={e => setUserForm(prev => ({ ...prev, phone: e.target.value }))} /> 
              <FormSelect id="profile-notificationPreference" label="Notification Preference" value={userForm.notificationPreference} onChange={e => setUserForm(prev => ({...prev, notificationPreference: e.target.value as NotificationPreference}))}> <option value="none">None</option><option value="email">Email</option><option value="phone">Phone</option> </FormSelect> 
              <h3 className="text-md font-semibold pt-2 text-textlight">Change System Password (Optional)</h3> 
              <FormInput id="profile-password" label="New System Password" type="password" value={userForm.password} onChange={e => setUserForm(prev => ({ ...prev, password: e.target.value }))} placeholder="Leave blank to keep current" description={passwordRequirementsText} /> 
              <FormInput id="profile-confirmPassword" label="Confirm New Password" type="password" value={userForm.confirmPassword} onChange={e => setUserForm(prev => ({ ...prev, confirmPassword: e.target.value }))} placeholder="Confirm new password" /> 
              <button type="submit" className="w-full btn-primary">Update Profile</button> 
            </form> 
          </div> 
        );
      case Page.UserManagement: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; const adminManagedPendingUsers = pendingUsers.filter(pu => pu.referringAdminId === currentUser.id || users.find(u => u.id === pu.referringAdminId)?.role === 'admin' || pu.referringAdminId === "GENERAL_REGISTRATION"); const adminManagedActiveUsers = users.filter(u => u.referringAdminId === currentUser.id || u.role === 'admin' || users.find(adm => adm.id === u.referringAdminId && adm.role ==='admin')); const generateLinkForAdmin = () => { if (!currentUser || currentUser.role !== 'admin') return; const link = `${window.location.origin}${window.location.pathname}#${Page.PreRegistration}?refAdminId=${currentUser.id}`; setGeneratedLink(link); setSuccessMessage("Pre-registration link generated. Copy it below."); }; const copyLinkToClipboard = () => { if (!generatedLink) return; navigator.clipboard.writeText(generatedLink) .then(() => setSuccessMessage("Link copied to clipboard!")) .catch(err => setError("Failed to copy link: " + err)); }; return ( <div className="space-y-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-primary flex items-center"> <PlusCircleIcon className="w-7 h-7 mr-2" /> {editingUserId ? 'Edit Existing User' : approvingPendingUser ? `Approve Pending User: ${approvingPendingUser.displayName}` : 'Directly Add New User (Managed by You)'} </h2> <form onSubmit={handleSaveOrApproveUserByAdmin} className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormInput id="manage-email" label="Email Address (Login)" type="email" value={userForm.email} onChange={e => setUserForm(prev => ({...prev, email: e.target.value}))} required /> <FormInput id="manage-uniqueId" label="System ID / Username" type="text" value={userForm.uniqueId} onChange={e => setUserForm(prev => ({...prev, uniqueId: e.target.value}))} required readOnly={!!approvingPendingUser && !editingUserId && !!approvingPendingUser.uniqueId} /> <FormInput id="manage-displayName" label="Display Name" type="text" value={userForm.displayName} onChange={e => setUserForm(prev => ({...prev, displayName: e.target.value}))} required readOnly={!!approvingPendingUser && !editingUserId && !!approvingPendingUser.displayName} /> <FormInput id="manage-position" label="Position" type="text" value={userForm.position} onChange={e => setUserForm(prev => ({...prev, position: e.target.value}))} placeholder="e.g., Software Engineer" required /> <FormSelect id="manage-role" label="Role" value={userForm.role} onChange={e => setUserForm(prev => ({...prev, role: e.target.value as Role}))}><option value="user">User</option><option value="admin">Admin</option></FormSelect> <FormTextarea id="manage-userInterests" label="User Interests " value={userForm.userInterests} onChange={e => setUserForm(prev => ({...prev, userInterests: e.target.value}))} placeholder="e.g., Web Development, Event Organization"/> <FormInput id="manage-phone" label="Phone (Contact, Optional)" type="tel" value={userForm.phone} onChange={e => setUserForm(prev => ({...prev, phone: e.target.value}))} placeholder="e.g., +1234567890" /> <FormSelect id="manage-notificationPreference" label="Notification Preference" value={userForm.notificationPreference} onChange={e => setUserForm(prev => ({...prev, notificationPreference: e.target.value as NotificationPreference}))}> <option value="none">None</option> <option value="email">Email</option> <option value="phone">Phone</option> </FormSelect>  <FormInput id="manage-password" label={(editingUserId && !approvingPendingUser) ? "New System Password (Optional)" : "System Password"} type="password" value={userForm.password} onChange={e => setUserForm(prev => ({...prev, password: e.target.value}))} placeholder={(editingUserId && !approvingPendingUser) ? "Leave blank to keep current" : (approvingPendingUser && approvingPendingUser.password) ? "Password set by user (can override)" : "Set a password for the user"} required={!(editingUserId && !approvingPendingUser) && !(approvingPendingUser && approvingPendingUser.password)} description={passwordRequirementsText} /> <FormInput id="manage-confirmPassword" label="Confirm System Password" type="password" value={userForm.confirmPassword} onChange={e => setUserForm(prev => ({...prev, confirmPassword: e.target.value}))} placeholder="Confirm password" required={userForm.password !== '' || (!(editingUserId && !approvingPendingUser) && !(approvingPendingUser && approvingPendingUser.password))} /> <div className="flex space-x-2"> <button type="submit" className="flex-grow btn-primary">{editingUserId ? 'Save Changes' : approvingPendingUser ? 'Approve User & Set Up Account' : 'Add User'}</button> {(editingUserId || approvingPendingUser) && <button type="button" onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); clearMessages();}} className="btn-neutral">Cancel</button>}</div> </form> </div> <div className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <h2 className="text-xl font-semibold text-info flex items-center"><KeyIcon className="w-6 h-6 mr-2"/> Generate Pre-registration Link (for Regular Users)</h2> <p className="text-sm text-neutral">Share this link with regular users to allow them to pre-register under your administration. They will submit their desired System ID and Display Name.</p> <button onClick={generateLinkForAdmin} className="btn-info">Generate My Link</button> {generatedLink && ( <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded"> <p className="text-sm text-blue-700 break-all mb-2">{generatedLink}</p> <button onClick={copyLinkToClipboard} className="btn-secondary text-xs px-2 py-1">Copy to Clipboard</button> </div> )} </div> {pendingUsers.length > 0 && ( <div className="mt-8"> <h2 className="text-xl font-semibold mb-3 text-amber-600 flex items-center">Pending User Approvals ({pendingUsers.length})</h2> <div className="space-y-3 max-h-[40vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow"> {pendingUsers.map(pu => ( <div key={pu.id} className="bg-white border border-gray-200 rounded-lg p-3"> <div className="flex justify-between items-start"> <div> <h3 className="text-md font-semibold text-amber-700">{pu.displayName}</h3> <p className="text-xs text-gray-600">System ID: {pu.uniqueId}</p> <p className="text-xs text-gray-600">Email: {pu.email || "Not set"}</p> <p className="text-xs text-gray-600">Intended Role: {pu.role}</p> <p className="text-xs text-gray-500 mt-0.5">Submitted: {new Date(pu.submissionDate).toLocaleDateString()}</p> <p className="text-xs text-gray-500 mt-0.5">Ref. Admin ID: {pu.referringAdminId === "GENERAL_REGISTRATION" ? "General Registration" : pu.referringAdminId ? pu.referringAdminId.substring(0,8) + "..." : "N/A"}</p></div> <div className="flex space-x-2"> <button onClick={() => handleInitiateApprovePendingUser(pu)} className="btn-success text-xs px-2 py-1">Review & Approve</button> <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger text-xs px-2 py-1">Reject</button> </div> </div> </div> ))} </div> </div> )} <div className="mt-8"> <h2 className="text-xl font-semibold mb-3 text-primary flex items-center"><UsersIcon className="w-6 h-6 mr-2" /> Active Users ({users.length})</h2> {users.length === 0 ? <p className="text-neutral">No active users found.</p> : ( <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow"> {users.map(u => ( <div key={u.id} className="bg-white border border-gray-200 rounded-lg p-3"> <div className="flex justify-between items-start"> <div> <h3 className="text-md font-semibold text-texthighlight">{u.displayName} <span className="text-xs px-1.5 py-0.5 bg-accent text-white rounded-full align-middle">{u.role}</span></h3> <p className="text-xs text-gray-600">Email: {u.email}</p> <p className="text-xs text-gray-600">System ID: {u.uniqueId}</p> <p className="text-xs text-gray-500 mt-0.5">Position: {u.position || 'N/A'}</p> <p className="text-xs text-gray-500 mt-0.5 truncate" title={u.userInterests}>Interests: {u.userInterests || 'N/A'}</p> <p className="text-xs text-gray-500 mt-0.5">Phone: {u.phone || 'N/A'}</p> <p className="text-xs text-gray-500 mt-0.5">Notify via: {u.notificationPreference || 'none'}</p> </div> <div className="flex space-x-1"> <button onClick={() => handleEditUserByAdmin(u)} className="text-blue-500 hover:text-blue-700 p-1" aria-label={`Edit user ${u.displayName}`}><UserCircleIcon className="w-4 h-4"/> </button> {currentUser.id !== u.id && (<button onClick={() => handleDeleteUser(u.id)} className="text-red-500 hover:text-red-700 p-1" aria-label={`Delete user ${u.displayName}`}><TrashIcon className="w-4 h-4" /></button> )} </div> </div> </div> ))} </div> )} </div> </div> );
      case Page.ManagePrograms: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; return ( <div className="grid md:grid-cols-2 gap-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-info flex items-center"><PlusCircleIcon className="w-7 h-7 mr-2" /> Add New Program</h2> <form onSubmit={handleAddProgram} className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormInput id="programName" label="Program Name" type="text" value={programForm.name} onChange={e => setProgramForm(prev => ({ ...prev, name: e.target.value }))} required /> <FormTextarea id="programDescription" label="Description" value={programForm.description} onChange={e => setProgramForm(prev => ({ ...prev, description: e.target.value }))} /> <button type="submit" className="btn-primary">Add Program</button> </form> </div> <div> <h2 className="text-2xl font-semibold mb-4 text-info flex items-center"><BriefcaseIcon className="w-7 h-7 mr-2"/> Existing Programs ({programs.length})</h2> {programs.length === 0 ? <p className="text-neutral">No programs created yet.</p> : ( <div className="bg-surface shadow-lg rounded-lg p-4 space-y-3 max-h-[60vh] overflow-y-auto"> {programs.map(p => ( <div key={p.id} className="border border-gray-200 rounded-md p-3 hover:shadow-md transition-shadow"> <div className="flex justify-between items-start"> <h3 className="text-lg font-medium text-texthighlight">{p.name}</h3> <button onClick={() => handleDeleteProgram(p.id)} className="text-danger hover:text-red-700" aria-label={`Delete program ${p.name}`}><TrashIcon className="w-5 h-5"/></button> </div> <p className="text-sm text-neutral mt-1">{p.description}</p> </div> ))} </div> )} </div> </div> );
      case Page.ManageTasks: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; return ( <div className="grid md:grid-cols-2 gap-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-success flex items-center"><PlusCircleIcon className="w-7 h-7 mr-2" /> Add New Task</h2> <form onSubmit={handleAddTask} className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormInput id="taskTitle" label="Task Title" type="text" value={taskForm.title} onChange={e => setTaskForm(prev => ({ ...prev, title: e.target.value }))} required /> <FormTextarea id="taskDescription" label="Description" value={taskForm.description} onChange={e => setTaskForm(prev => ({ ...prev, description: e.target.value }))} /> <FormTextarea id="taskRequiredSkills" label="Required Skills" value={taskForm.requiredSkills} onChange={e => setTaskForm(prev => ({ ...prev, requiredSkills: e.target.value }))} /> <FormSelect id="taskProgram" label="Related Program (Optional)" value={taskForm.programId || ''} onChange={e => setTaskForm(prev => ({ ...prev, programId: e.target.value }))}> <option value="">None</option> {programs.map(p => <option key={p.id} value={p.id}>{p.name}</option>)} </FormSelect> <FormInput id="taskDeadline" label="Deadline (Optional)" type="date" value={taskForm.deadline || ''} onChange={e => setTaskForm(prev => ({ ...prev, deadline: e.target.value }))} /> <button type="submit" className="btn-primary">Add Task</button> </form> </div> <div> <h2 className="text-2xl font-semibold mb-4 text-success flex items-center"><ClipboardListIcon className="w-7 h-7 mr-2"/> Existing Tasks ({tasks.length})</h2> {tasks.length === 0 ? <p className="text-neutral">No tasks created yet.</p> : ( <div className="bg-surface shadow-lg rounded-lg p-4 space-y-3 max-h-[70vh] overflow-y-auto"> {tasks.map(t => ( <div key={t.id} className="border border-gray-200 rounded-md p-3 hover:shadow-md transition-shadow"> <div className="flex justify-between items-start"> <h3 className="text-lg font-medium text-texthighlight">{t.title}</h3> <button onClick={() => handleDeleteTask(t.id)} className="text-danger hover:text-red-700" aria-label={`Delete task ${t.title}`}><TrashIcon className="w-5 h-5"/></button> </div> {t.programName && <p className="text-xs text-info">Program: {t.programName}</p>} {t.deadline && <p className="text-xs text-warning">Deadline: {new Date(t.deadline).toLocaleDateString()}</p>} <p className="text-sm text-neutral mt-1">{t.description}</p> <p className="text-sm text-neutral mt-1"><strong className="text-textlight">Skills:</strong> {t.requiredSkills}</p> </div> ))} </div> )} </div> </div> );
      case Page.AssignWork: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; return ( <div className="grid md:grid-cols-2 gap-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-primary flex items-center"><LightBulbIcon className="w-7 h-7 mr-2" /> Suggest Assignment</h2> <div className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormSelect id="selectTaskForAssignment" label="Select Task to Assign" value={selectedTaskForAssignment || ''} onChange={e => {setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); clearMessages();}}> <option value="" disabled>-- Select a Task --</option> {tasks.map(t => <option key={t.id} value={t.id}>{t.title}</option>)} </FormSelect> <button onClick={fetchAssignmentSuggestion} disabled={!selectedTaskForAssignment || isLoadingSuggestion} className="btn-primary"> {isLoadingSuggestion ? 'Getting Suggestion...' : 'Get AI Suggestion'} </button> {isLoadingSuggestion && <LoadingSpinner />} {assignmentSuggestion && ( <div className="mt-4 p-4 border border-primary rounded-md bg-blue-50"> <h3 className="text-lg font-semibold text-texthighlight">AI Suggestion:</h3> {assignmentSuggestion.suggestedPersonName ? ( <> <p>Assign to: <strong className="text-primary">{assignmentSuggestion.suggestedPersonName}</strong></p> <p>Justification: <span className="text-neutral">{assignmentSuggestion.justification}</span></p> <FormInput id="assignmentSpecificDeadline" label="Specific Deadline for this Assignment (Optional, overrides task default)" type="date" value={assignmentForm.specificDeadline || ''} onChange={(e) => setAssignmentForm(prev => ({...prev, specificDeadline: e.target.value}))} /> <button onClick={handleConfirmAssignmentByAdmin} className="btn-success mt-2">Confirm & Propose to User</button> </> ) : ( <p className="text-neutral">{assignmentSuggestion.justification || "AI could not suggest a suitable person."}</p> )} </div> )} </div> </div> <div> <h2 className="text-2xl font-semibold mb-4 text-primary flex items-center"><ClipboardListIcon className="w-7 h-7 mr-2"/> Current Assignments Summary</h2> <div className="bg-surface shadow-lg rounded-lg p-4 space-y-3 max-h-[70vh] overflow-y-auto"> {assignments.length === 0 ? <p className="text-neutral">No tasks assigned yet.</p> : assignments .sort((a, b) => new Date(b.userSubmissionDate || 0).getTime() - new Date(a.userSubmissionDate || 0).getTime()) // Rough sort for demo
 .map(a => { const task = tasks.find(t => t.id === a.taskId); const person = users.find(u => u.id === a.personId); return ( <div key={`${a.taskId}-${a.personId}`} className="border border-gray-200 rounded-md p-3 hover:shadow-md transition-shadow"> <h3 className="text-md font-medium text-texthighlight">{a.taskTitle}</h3> <p className="text-sm text-neutral">Assigned to: {a.personName || person?.displayName || 'Unknown User'}</p> <p className={`text-sm font-semibold capitalize ${ a.status === 'completed_admin_approved' ? 'text-success' : a.status.startsWith('submitted') ? 'text-info' : a.status === 'accepted_by_user' ? 'text-amber-600' : a.status === 'pending_acceptance' ? 'text-warning' : 'text-danger' }`}> Status: {a.status.replace(/_/g, ' ')} </p> {a.deadline && <p className="text-xs text-neutral">Deadline: {new Date(a.deadline).toLocaleDateString()}</p>} {a.justification && <p className="text-xs text-neutral mt-1 italic">AI Suggestion: {a.justification}</p>} {(a.status === 'submitted_on_time' || a.status === 'submitted_late') && ( <button onClick={() => handleAdminApproveCompletion(a)} className="btn-success text-xs mt-2 px-2 py-1">Approve Completion</button> )} { (a.status === 'pending_acceptance' || a.status === 'accepted_by_user') && ( <button onClick={() => handleAdminUnassignTask(a)} className="btn-danger text-xs mt-2 ml-2 px-2 py-1">Unassign/Clear</button> )} </div> ); })} </div> </div> </div> );
      case Page.ViewAssignments: /* User's view of their assignments */ const myAssignments = assignments.filter(a => a.personId === currentUser.id); return ( <div className="space-y-6"> <h2 className="text-2xl font-semibold text-primary flex items-center"><ClipboardListIcon className="w-7 h-7 mr-2" />My Task Assignments</h2> {myAssignments.length === 0 ? ( <p className="text-neutral p-4 bg-surface rounded-lg shadow">You have no tasks currently assigned to you, or all your tasks have been completed and approved.</p> ) : ( myAssignments.map(assignment => { const taskDetails = tasks.find(t => t.id === assignment.taskId); const isLateForSubmission = assignment.deadline ? new Date() > new Date(new Date(assignment.deadline).setHours(23, 59, 59, 999)) : false; return ( <div key={assignment.taskId} className="bg-surface shadow-lg rounded-lg p-4"> <h3 className="text-lg font-medium text-texthighlight">{assignment.taskTitle}</h3> {taskDetails?.description && <p className="text-sm text-neutral mt-1">{taskDetails.description}</p>} {taskDetails?.requiredSkills && <p className="text-sm text-neutral mt-1"><strong className="text-textlight">Required Skills:</strong> {taskDetails.requiredSkills}</p>} {assignment.deadline && <p className="text-sm text-neutral mt-1"><strong className="text-textlight">Deadline:</strong> {new Date(assignment.deadline).toLocaleDateString()} {new Date(assignment.deadline) < new Date() && assignment.status !== 'completed_admin_approved' && assignment.status !== 'submitted_on_time' && assignment.status !== 'submitted_late' && <span className="text-danger font-semibold">(Past Due)</span>}</p>} <p className={`text-sm mt-1 font-semibold capitalize ${ assignment.status === 'completed_admin_approved' ? 'text-success' : assignment.status.startsWith('submitted') ? 'text-info' : assignment.status === 'accepted_by_user' ? 'text-amber-600' : assignment.status === 'pending_acceptance' ? 'text-warning' : 'text-danger' }`}> Status: {assignment.status.replace(/_/g, ' ')} </p> {assignment.status === 'pending_acceptance' && ( <div className="mt-3 space-x-2"> <button onClick={() => handleUserAssignmentResponse(assignment, true)} className="btn-success">Accept Task</button> <button onClick={() => handleUserAssignmentResponse(assignment, false)} className="btn-danger">Decline Task</button> </div> )} {assignment.status === 'accepted_by_user' && ( <div className="mt-3"> {assignmentToSubmitDelayReason === assignment.taskId && isLateForSubmission ? ( <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-md"> <FormTextarea id={`delay-reason-${assignment.taskId}`} label="Reason for Late Submission:" value={userSubmissionDelayReason} onChange={e => setUserSubmissionDelayReason(e.target.value)} placeholder="Please provide a brief explanation for the delay."/> <button onClick={() => { if (userSubmissionDelayReason.trim()) handleCompleteTaskByUser(assignment, userSubmissionDelayReason); else setError("Reason for delay is required if submitting late."); }} className="btn-primary mt-2">Submit with Reason</button> <button onClick={() => setAssignmentToSubmitDelayReason(null)} className="btn-neutral mt-2 ml-2">Cancel</button> </div> ) : ( <button onClick={() => { if (isLateForSubmission) { setAssignmentToSubmitDelayReason(assignment.taskId); setUserSubmissionDelayReason(''); } else { handleCompleteTaskByUser(assignment); } }} className="btn-primary">Mark as Completed / Submit</button> )} </div> )} {assignment.status === 'submitted_late' && assignment.userDelayReason && ( <p className="text-xs text-neutral mt-1 italic">Reason for delay: {assignment.userDelayReason}</p> )} </div> ); }) )} </div> );
      case Page.ViewTasks: /* User's view of all available tasks (not assigned to them) */ const unassignedTasks = tasks.filter(task => !assignments.some(a => a.taskId === task.id && (a.status !== 'declined_by_user' && a.status !== 'completed_admin_approved'))); return ( <div className="space-y-6"> <h2 className="text-2xl font-semibold text-primary flex items-center"><BriefcaseIcon className="w-7 h-7 mr-2" />Available Tasks</h2> {unassignedTasks.length === 0 ? <p className="text-neutral p-4 bg-surface rounded-lg shadow">No tasks are currently available or all tasks have been assigned.</p> : ( unassignedTasks.map(task => ( <div key={task.id} className="bg-surface shadow-lg rounded-lg p-4"> <h3 className="text-lg font-medium text-texthighlight">{task.title}</h3> {task.programName && <p className="text-xs text-info">Program: {task.programName}</p>} {task.deadline && <p className="text-xs text-warning">Deadline: {new Date(task.deadline).toLocaleDateString()}</p>} <p className="text-sm text-neutral mt-1">{task.description}</p> <p className="text-sm text-neutral mt-1"><strong className="text-textlight">Skills:</strong> {task.requiredSkills}</p> </div> )) )} </div> );
      default: return <p>Page not found.</p>;
    }
  };

  const renderAuthContainer = (children: React.ReactNode) => (
    <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
      <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-md">
        {(error || successMessage || infoMessage) && (
           <div className="mb-6 space-y-3">
            {error && <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow w-full" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
            {successMessage && <div className="p-3 bg-green-100 border border-green-400 text-green-700 rounded-md shadow w-full" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
            {infoMessage && <div className="p-3 bg-blue-100 border border-blue-400 text-blue-700 rounded-md shadow w-full" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
          </div>
        )}
        {children}
      </div>
      <footer className="text-center py-6 text-sm text-neutral mt-auto">
        <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by SHAIK MOHAMMED NAWAZ.</p>
      </footer>
    </div>
  );
  
  // Conditional rendering based on currentPage
  if (currentPage === Page.Login && !currentUser) {
    return renderAuthContainer(authView === 'login' ? renderNewAuthLoginPage() : renderNewAuthRegisterPage());
  }
  if (currentPage === Page.PreRegistration && !currentUser) {
    return (
      <PreRegistrationFormPage
        formState={preRegistrationForm}
        setFormState={setPreRegistrationForm}
        onSubmit={handlePreRegistrationSubmit}
        error={error}
        successMessage={successMessage}
        infoMessage={infoMessage}
        clearMessages={clearMessages}
        navigateToLogin={() => { clearMessages(); setAuthView('login'); navigateTo(Page.Login);}}
      />
    );
  }
  if (!currentUser) { 
    // This will show if not on Login/PreReg and no currentUser (e.g. after data load but before hash processing redirects)
    // Or if hash processing logic somehow fails to redirect to login when currentUser is null.
    return renderAuthContainer(renderNewAuthLoginPage());
  }
  
  // Main application layout for logged-in users
  const navItems = [
    { page: Page.Dashboard, label: 'Dashboard', icon: <LightBulbIcon className="w-5 h-5 mr-2" /> },
    { page: Page.UserProfile, label: 'My Profile', icon: <UserCircleIcon className="w-5 h-5 mr-2" /> },
    ...(currentUser.role === 'admin' ? [
      { page: Page.UserManagement, label: 'User Management', icon: <UsersIcon className="w-5 h-5 mr-2" /> },
      { page: Page.ManagePrograms, label: 'Programs', icon: <BriefcaseIcon className="w-5 h-5 mr-2" /> },
      { page: Page.ManageTasks, label: 'Tasks (Create)', icon: <PlusCircleIcon className="w-5 h-5 mr-2" /> },
      { page: Page.AssignWork, label: 'Assign Work (AI)', icon: <LightBulbIcon className="w-5 h-5 mr-2 text-accent" /> },
    ] : []),
    { page: Page.ViewAssignments, label: 'My Assignments', icon: <ClipboardListIcon className="w-5 h-5 mr-2" /> },
    { page: Page.ViewTasks, label: 'Available Tasks', icon: <BriefcaseIcon className="w-5 h-5 mr-2" /> },
  ];

  return (
    <div className="flex flex-col min-h-screen bg-bground main-app-scope">
       {showUserTour && currentUser && currentUser.role === 'user' && (
        <UserTour user={currentUser} onClose={handleUserTourClose} />
      )}
      <header className="bg-primary text-white shadow-md sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3 flex justify-between items-center">
          <h1 className="text-xl font-bold cursor-pointer" onClick={() => navigateTo(currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments)}>Task Assignment Assistant</h1>
          <nav className="flex items-center space-x-3">
            {navItems.map(item => (
              <button
                key={item.page}
                onClick={() => navigateTo(item.page)}
                className={`px-3 py-1.5 rounded-md text-sm font-medium flex items-center transition-colors
                  ${currentPage === item.page ? 'bg-blue-700 text-white' : 'text-blue-100 hover:bg-blue-600 hover:text-white'}`}
                aria-current={currentPage === item.page ? "page" : undefined}
              >
                {item.icon} {item.label}
              </button>
            ))}
            <button onClick={handleLogout} className="px-3 py-1.5 rounded-md text-sm font-medium bg-accent hover:bg-yellow-600 text-white flex items-center transition-colors">
              <LogoutIcon className="w-5 h-5 mr-1.5"/> Logout
            </button>
          </nav>
        </div>
      </header>
      <main className="container mx-auto p-6 flex-grow">
        {(error || successMessage || infoMessage) && (
          <div className="mb-6 space-y-3">
            {error && <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow w-full" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
            {successMessage && <div className="p-3 bg-green-100 border border-green-400 text-green-700 rounded-md shadow w-full" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
            {infoMessage && <div className="p-3 bg-blue-100 border border-blue-400 text-blue-700 rounded-md shadow w-full" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
          </div>
        )}
        {renderPage()}
      </main>
      <footer className="bg-neutral text-center py-4 text-sm text-gray-300">
        <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. All rights reserved.  Powered By SHAIK MOHAMMED NAWAZ.</p>
        <p className="text-xs text-gray-400 mt-1">Data is currently stored locally in your browser. For internet-accessible storage, integration with a backend service is required.</p>
      </footer>
    </div>
  );
};
