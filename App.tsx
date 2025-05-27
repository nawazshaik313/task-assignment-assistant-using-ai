import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, Role, Task, Assignment, Program, GeminiSuggestion, NotificationPreference, AssignmentStatus, PendingUser, AdminLogEntry } from './types';
import useLocalStorage from './hooks/useLocalStorage';
import { getAssignmentSuggestion } from './services/geminiService';
import LoadingSpinner from './components/LoadingSpinner';
import { UsersIcon, ClipboardListIcon, LightBulbIcon, CheckCircleIcon, TrashIcon, PlusCircleIcon, KeyIcon, BriefcaseIcon, LogoutIcon, UserCircleIcon } from './components/Icons';
import PreRegistrationFormPage from './components/PreRegistrationFormPage';
import Modal from './components/Modal';
import AdminLoginPage from './components/AdminLoginPage';
import { sendApprovalEmail } from './utils/emailService'; // ✅ updated path

// --- FORM COMPONENTS ---
const AuthFormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { id: string; 'aria-label': string }> = ({ id, ...props }) => (
  <input
    id={id}
    {...props}
    className="w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
  />
);

const AuthFormSelect: React.FC<
  React.SelectHTMLAttributes<HTMLSelectElement> & {
    id: string;
    'aria-label': string;
    children: React.ReactNode;
  }
> = ({ id, children, ...props }) => (
  <select
    id={id}
    {...props}
    className="w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight"
  >
    {children}
  </select>
);

const FormInput: React.FC<
  React.InputHTMLAttributes<HTMLInputElement> & { label: string; id: string }
> = ({ label, id, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">
      {label}
    </label>
    <input
      id={id}
      {...props}
      className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight"
    />
  </div>
);

const FormTextarea: React.FC<
  React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; id: string }
> = ({ label, id, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">
      {label}
    </label>
    <textarea
      id={id}
      {...props}
      rows={3}
      className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight"
    />
  </div>
);

const FormSelect: React.FC<
  React.SelectHTMLAttributes<HTMLSelectElement> & { label: string; id: string; children: React.ReactNode }
> = ({ label, id, children, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">
      {label}
    </label>
    <select
      id={id}
      {...props}
      className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-neutral focus:outline-none focus:ring-primary focus:border-primary sm:text-sm rounded-md bg-surface text-textlight"
    >
      {children}
    </select>
  </div>
);

// --- MAIN APP COMPONENT ---
const App: React.FC = () => {
  // Dummy initial states for demonstration purposes
  const initialUserFormData = {
    email: '',
    uniqueId: '',
    displayName: '',
    position: '',
    userInterests: '',
    phone: '',
    notificationPreference: 'none' as NotificationPreference,
    role: 'user' as Role,
    password: '',
    confirmPassword: '',
    referringAdminId: '',
  };

  const initialNewRegistrationForm = {
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'user' as Role,
  };

  const initialNewLoginForm = {
    email: '',
    password: '',
  };

  const [page, setPage] = useState<Page>('login');
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [isAdminLoggedIn, setIsAdminLoggedIn] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  const [preRegistrationForm, setPreRegistrationForm] = useState({
    email: '',
    uniqueId: '',
    displayName: '',
    password: '',
    confirmPassword: '',
    referringAdminId: '',
    referringAdminDisplayName: '',
    isReferralLinkValid: false
  });

  // State variables that were missing initialization
  const [users, setUsers] = useLocalStorage<User[]>('users', []);
  const [pendingUsers, setPendingUsers] = useLocalStorage<PendingUser[]>('pendingUsers', []);
  const [newRegistrationForm, setNewRegistrationForm] = useState(initialNewRegistrationForm);
  const [newLoginForm, setNewLoginForm] = useState(initialNewLoginForm);
  const [currentUser, setCurrentUser] = useLocalStorage<User | null>('currentUser', null);
  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [currentPage, _setCurrentPageInternal] = useState<Page>('login'); // Renamed to _setCurrentPageInternal to avoid conflict
  const [programs, setPrograms] = useLocalStorage<Program[]>('programs', []);
  const [tasks, setTasks] = useLocalStorage<Task[]>('tasks', []);
  const [assignments, setAssignments] = useLocalStorage<Assignment[]>('assignments', []);
  const [adminLogs, setAdminLogs] = useLocalStorage<AdminLogEntry[]>('adminLogs', []);


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
  const [generatedLink, setGeneratedLink] = useState<string>('');

  const [adminLogText, setAdminLogText] = useState('');
  const [adminLogImageFile, setAdminLogImageFile] = useState<File | null>(null);
  const [isSubmittingLog, setIsSubmittingLog] = useState(false);


  const clearMessages = useCallback(() => {
    setError(null);
    setSuccessMessage(null);
    setInfoMessage(null);
  }, []);

  const navigateTo = useCallback((targetPage: Page, params?: Record<string, string>) => {
    clearMessages();
    let hash = `#${targetPage}`;
    if (params && Object.keys(params).length > 0) {
      hash += `?${new URLSearchParams(params).toString()}`;
    }
    if (window.location.hash !== hash) {
      window.location.hash = hash;
    } else {
      _setCurrentPageInternal(targetPage); /* Ensure internal state updates if hash is same */
    }
  }, [clearMessages]);

  const filteredPendingUsers = pendingUsers.filter(user =>
    user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.uniqueId.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.displayName.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleApproveUser = async (id: string) => {
    const approvingUser = pendingUsers.find(pu => pu.id === id);
    if (approvingUser) {
      const newUser: User = {
        id: Date.now().toString(),
        email: approvingUser.email,
        uniqueId: approvingUser.uniqueId,
        displayName: approvingUser.displayName,
        password: approvingUser.password, // This password would typically be set by the admin or temporary
        role: 'user'
      };
      setUsers(prev => [...prev, newUser]);
      setPendingUsers(prev => prev.filter(pu => pu.id !== id));
      try {
        await sendApprovalEmail(approvingUser.email, approvingUser.displayName);
        setSuccessMessage(`User ${approvingUser.displayName} approved.`);
      } catch (err) {
        console.error('❌ Email error:', err);
        setError('User approved, but email failed.');
      }
      setShowSuccessModal(true);
    }
  };

  const handleRejectUser = (id: string) => {
    const rejectingUser = pendingUsers.find(pu => pu.id === id);
    setPendingUsers(prev => prev.filter(pu => pu.id !== id));
    setSuccessMessage(`User ${rejectingUser?.displayName || ''} rejected.`);
    setShowSuccessModal(true);
  };

  useEffect(() => {
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
            ...prev, // Keep existing values if any, then override
            referringAdminId: refAdminIdFromHash,
            referringAdminDisplayName: adminUser ? adminUser.displayName : 'Admin (Details from link)',
            isReferralLinkValid: true
          }));
        } else {
          setPreRegistrationForm(prev => ({ ...prev, isReferralLinkValid: false }));
          setError("Pre-registration link is invalid or missing administrator reference.");
        }
        _setCurrentPageInternal(Page.PreRegistration);
        return;
      }

      if (!currentUser) {
        _setCurrentPageInternal(Page.Login);
        if (targetPageFromHashPath && targetPageFromHashPath !== Page.Login.toUpperCase()) {
          if (window.location.hash !== `#${Page.Login}`) navigateTo(Page.Login);
        }
        return;
      }

      const defaultPageDetermination = currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
      let newPage = (targetPageFromHashPath || defaultPageDetermination) as Page;

      if ([Page.Login, Page.PreRegistration].includes(newPage as Page)) {
        newPage = defaultPageDetermination;
      }

      const currentTopLevelPagePath = window.location.hash.substring(1).split('?')[0].toUpperCase();
      const targetParams = paramsString ? Object.fromEntries(params) : undefined;

      if (newPage.toUpperCase() !== currentTopLevelPagePath) {
        navigateTo(newPage, targetParams);
      }
      _setCurrentPageInternal(newPage);
    };

    processHash();
    window.addEventListener('hashchange', processHash);

    return () => {
      window.removeEventListener('hashchange', processHash);
    };
  }, [currentUser, navigateTo, clearMessages, users]);

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

  const handleNewRegistration = (e: React.FormEvent) => {
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
    if (users.some(u => u.email === email)) {
      setError("This email address is already registered. Please login or use a different email.");
      return;
    }

    if (users.length === 0 && role !== 'admin') {
      setError("The first user registered must be an Administrator. Please select the 'Admin' role.");
      return;
    }

    const newUser: User = {
      id: Date.now().toString(),
      email: email,
      uniqueId: email,
      password: password,
      role: role,
      displayName: name,
      position: role === 'admin' ? 'Administrator' : 'Registered User',
      userInterests: '',
      phone: '',
      notificationPreference: 'email',
    };

    setUsers(prevUsers => [...prevUsers, newUser]);
    setNewRegistrationForm(initialNewRegistrationForm);
    setSuccessMessage(`Registration successful for ${name}! Please login.`);
    setAuthView('login');
  };

  const handleLogin = (e: React.FormEvent) => {
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
        setNewLoginForm(initialNewLoginForm);
        setSuccessMessage(`Login successful! Welcome back, ${user.displayName}.`);
        // Navigation will be handled by useEffect watching currentUser
      } else {
        setError("Invalid password.");
      }
    } else {
      setError("Email address not found or account not yet approved/created.");
    }
  };

  const handleForgotPassword = () => {
    clearMessages();
    if (!newLoginForm.email.trim()) {
      setError("Please enter your Email Address first to check for password recovery options.");
      return;
    }
    const userToCheck = users.find(u => u.email === newLoginForm.email);
    if (userToCheck) {
      setInfoMessage(`Password Recovery for '${userToCheck.displayName}': In a real system, a password reset link would be sent to ${userToCheck.email}. This demo doesn't send actual emails.`);
    } else {
      setError("Email Address not found in the system.");
    }
  };

  const handlePreRegistrationSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!preRegistrationForm.isReferralLinkValid || !preRegistrationForm.referringAdminId) {
      setError("Invalid pre-registration attempt. Please use a valid link from an administrator.");
      return;
    }
    if (!preRegistrationForm.uniqueId.trim() || !preRegistrationForm.displayName.trim()) {
      setError("Your Desired System ID and Display Name are required.");
      return;
    }
    if (users.some(u => u.uniqueId === preRegistrationForm.uniqueId) || pendingUsers.some(pu => pu.uniqueId === preRegistrationForm.uniqueId)) {
      setError("This System ID has already been used or is pending approval. Please choose a different one.");
      return;
    }
    const newPendingUser: PendingUser = {
      id: Date.now().toString(),
      uniqueId: preRegistrationForm.uniqueId,
      displayName: preRegistrationForm.displayName,
      submissionDate: new Date().toISOString(),
      referringAdminId: preRegistrationForm.referringAdminId,
      email: preRegistrationForm.email, // Assuming email is captured during pre-reg
      password: preRegistrationForm.password, // Assuming password is captured during pre-reg
    };
    setPendingUsers(prev => [...prev, newPendingUser]);
    setPreRegistrationForm({
      email: '',
      uniqueId: '',
      displayName: '',
      password: '',
      confirmPassword: '',
      referringAdminId: '',
      referringAdminDisplayName: '',
      isReferralLinkValid: false
    }); // Clear the form
    setSuccessMessage("Your ID submission has been received. An administrator will review it. You can log in after approval and full account setup (including email and password assignment by admin).");
    setAuthView('login');
    navigateTo(Page.Login); // Redirect to login page view
  };

  const handleLogout = () => {
    clearMessages();
    setCurrentUser(null);
    setNewLoginForm(initialNewLoginForm);
    setAuthView('login');
    setPreRegistrationForm({
      email: '',
      uniqueId: '',
      displayName: '',
      password: '',
      confirmPassword: '',
      referringAdminId: '',
      referringAdminDisplayName: '',
      isReferralLinkValid: false
    });
    setSuccessMessage("You have been logged out.");
    navigateTo(Page.Login);
  };

  const handleUpdateProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentUser) return;
    clearMessages();
    if (!userForm.displayName.trim()) {
      setError("Display name cannot be empty.");
      return;
    }
    if (!userForm.email.trim() || !/\S+@\S+\.\S+/.test(userForm.email)) {
      setError("A valid email address is required.");
      return;
    }
    if (userForm.email !== currentUser.email && users.some(u => u.email === userForm.email && u.id !== currentUser.id)) {
      setError("This email address is already in use by another account.");
      return;
    }
    if (userForm.uniqueId !== currentUser.uniqueId && users.some(u => u.uniqueId === userForm.uniqueId && u.id !== currentUser.id)) {
      setError("This System ID is already in use by another account.");
      return;
    }
    let newPassword = currentUser.password;
    if (userForm.password) {
      if (userForm.password !== userForm.confirmPassword) {
        setError("New passwords do not match.");
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
    setUsers(users.map(u => (u.id === currentUser.id ? updatedUser : u)));
    setCurrentUser(updatedUser);
    setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' }));
    setSuccessMessage("Profile updated successfully.");
    navigateTo(currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments);
  };

  const handleSaveOrApproveUserByAdmin = (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!userForm.email.trim() || !/\S+@\S+\.\S+/.test(userForm.email)) {
      setError("A valid email address is required.");
      return;
    }
    if (!userForm.uniqueId.trim() || !userForm.displayName.trim() || !userForm.position.trim()) {
      setError("Email, System ID, Display Name, and Position are required.");
      return;
    }
    const isEditing = !!editingUserId && !approvingPendingUser;
    const isApproving = !!approvingPendingUser;
    const isAddingNew = !isEditing && !isApproving;

    if (isAddingNew || isApproving) {
      if (!userForm.password) {
        setError("Password is required for new/approved users.");
        return;
      }
      if (userForm.password !== userForm.confirmPassword) {
        setError("Passwords do not match.");
        return;
      }
    } else if (isEditing) {
      if (userForm.password && userForm.password !== userForm.confirmPassword) {
        setError("New passwords do not match.");
        return;
      }
    }

    const targetId = editingUserId || approvingPendingUser?.id;
    if (users.some(u => u.email === userForm.email && u.id !== targetId)) {
      setError("This email address is already in use by another account.");
      return;
    }
    if (users.some(u => u.uniqueId === userForm.uniqueId && u.id !== targetId)) {
      setError("This System ID is already in use by another account.");
      return;
    }
    if (isAddingNew && pendingUsers.some(pu => pu.uniqueId === userForm.uniqueId && pu.id !== targetId)) {
      setError("This System ID is pending approval for another user. Resolve pending user or choose a different ID.");
      return;
    }

    if (isEditing) {
      const userToUpdate = users.find(u => u.id === editingUserId);
      if (!userToUpdate) {
        setError("User not found for editing.");
        return;
      }
      const updatedUser: User = {
        ...userToUpdate,
        email: userForm.email,
        uniqueId: userForm.uniqueId,
        displayName: userForm.displayName,
        position: userForm.position,
        userInterests: userForm.userInterests,
        phone: userForm.phone,
        notificationPreference: userForm.notificationPreference,
        role: userForm.role,
        password: userForm.password ? userForm.password : userToUpdate.password,
      };
      setUsers(users.map(u => u.id === editingUserId ? updatedUser : u));
      setSuccessMessage(`User '${updatedUser.displayName}' updated successfully.`);
    } else {
      const newUser: User = {
        id: approvingPendingUser ? approvingPendingUser.id : Date.now().toString(),
        email: userForm.email,
        uniqueId: userForm.uniqueId,
        password: userForm.password!,
        displayName: userForm.displayName,
        position: userForm.position,
        userInterests: userForm.userInterests,
        phone: userForm.phone,
        notificationPreference: userForm.notificationPreference,
        role: userForm.role,
        referringAdminId: approvingPendingUser ? approvingPendingUser.referringAdminId : currentUser?.id,
      };
      setUsers(prevUsers => [...prevUsers, newUser]);
      if (approvingPendingUser) {
        setPendingUsers(prevPending => prevPending.filter(pu => pu.id !== approvingPendingUser.id));
        setSuccessMessage(`User '${newUser.displayName}' (System ID: ${newUser.uniqueId}) approved with email ${newUser.email}, account activated, and password set. (Notification via ${newUser.notificationPreference || 'none'} would be sent.)`);
      } else {
        setSuccessMessage(`User '${newUser.displayName}' (System ID: ${newUser.uniqueId}) added with email ${newUser.email} and password.`);
      }
    }
    setUserForm(initialUserFormData);
    setEditingUserId(null);
    setApprovingPendingUser(null);
  };

  const handleEditUserByAdmin = (user: User) => {
    setApprovingPendingUser(null);
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
    clearMessages();
  };

  const handleInitiateApprovePendingUser = (pendingUser: PendingUser) => {
    setEditingUserId(null);
    setApprovingPendingUser(pendingUser);
    setUserForm({
      ...initialUserFormData,
      uniqueId: pendingUser.uniqueId,
      displayName: pendingUser.displayName,
      referringAdminId: pendingUser.referringAdminId,
      role: 'user',
    });
    clearMessages();
    setInfoMessage(`Reviewing pending user: ${pendingUser.displayName} (ID: ${pendingUser.uniqueId}). Please set their email, complete their profile, set a password, and assign a role.`);
  };

  const handleRejectPendingUser = (pendingUserId: string) => {
    setPendingUsers(prev => prev.filter(pu => pu.id !== pendingUserId));
    setSuccessMessage("Pending user request rejected.");
    if (approvingPendingUser?.id === pendingUserId) {
      setApprovingPendingUser(null);
      setUserForm(initialUserFormData);
    }
  };

  const handleDeleteUser = (userId: string) => {
    if (currentUser?.role !== 'admin') {
      setError("Only admins can delete users.");
      return;
    }
    if (userId === currentUser?.id) {
      setError("You cannot delete your own account.");
      return;
    }
    setUsers(users.filter(u => u.id !== userId));
    setAssignments(assignments.filter(a => a.personId !== userId));
    setSuccessMessage("User deleted successfully.");
    if (editingUserId === userId) {
      setEditingUserId(null);
      setUserForm(initialUserFormData);
    }
  };

  const handleAddProgram = (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!programForm.name.trim()) {
      setError("Program name cannot be empty.");
      return;
    }
    const newProgram: Program = { ...programForm, id: Date.now().toString() };
    setPrograms([...programs, newProgram]);
    setProgramForm({ name: '', description: '' });
    setSuccessMessage(`Program "${newProgram.name}" added successfully.`);
  };

  const handleDeleteProgram = (id: string) => {
    clearMessages();
    const isProgramInUse = tasks.some(task => task.programId === id);
    if (isProgramInUse) {
      if (!window.confirm("This program is linked to tasks. Deleting it will unlink these tasks. Are you sure?")) {
        return;
      }
      setTasks(tasks.map(task => task.programId === id ? { ...task, programId: undefined, programName: undefined } : task));
    }
    setPrograms(programs.filter(p => p.id !== id));
    setSuccessMessage("Program deleted successfully.");
  };

  const handleAddTask = (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();
    if (!taskForm.title.trim()) {
      setError("Task title cannot be empty.");
      return;
    }
    const program = programs.find(p => p.id === taskForm.programId);
    const newTask: Task = {
      id: Date.now().toString(),
      title: taskForm.title,
      description: taskForm.description,
      requiredSkills: taskForm.requiredSkills,
      programId: taskForm.programId || undefined,
      programName: program ? program.name : undefined,
      deadline: taskForm.deadline || undefined
    };
    setTasks([...tasks, newTask]);
    setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' });
    setSuccessMessage(`Task "${newTask.title}" added successfully.`);
  };

  const handleDeleteTask = (id: string) => {
    clearMessages();
    setTasks(tasks.filter(t => t.id !== id));
    setAssignments(assignments.filter(a => a.taskId !== id));
    setSuccessMessage("Task deleted successfully.");
  };

  const fetchAssignmentSuggestion = useCallback(async () => {
    if (!selectedTaskForAssignment) {
      setError("Please select a task first.");
      return;
    }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    if (!task) {
      setError("Selected task not found.");
      return;
    }
    const activeUserIdsWithTasks = assignments
      .filter(a => a.status === 'pending_acceptance' || a.status === 'accepted_by_user')
      .map(a => a.personId);
    const trulyAvailableUsers = users.filter(u => u.role === 'user' && !activeUserIdsWithTasks.includes(u.id));
    if (trulyAvailableUsers.length === 0) {
      setError("No users available to assign tasks to (either no users, or all users have active tasks).");
      setAssignmentSuggestion({ suggestedPersonName: null, justification: "No users (non-admin) available without active tasks in the system." });
      return;
    }
    setIsLoadingSuggestion(true);
    clearMessages();
    setAssignmentSuggestion(null);
    try {
      const suggestion = await getAssignmentSuggestion(task, trulyAvailableUsers, programs, assignments);
      setAssignmentSuggestion(suggestion);
      if (!suggestion?.suggestedPersonName && suggestion?.justification) {
        setInfoMessage(suggestion.justification);
      }
    } catch (err) {
      console.error("Error fetching suggestion:", err);
      const errorMessage = err instanceof Error ? err.message : "An unknown error occurred.";
      setError(errorMessage);
      setAssignmentSuggestion({ suggestedPersonName: null, justification: errorMessage });
    } finally {
      setIsLoadingSuggestion(false);
    }
  }, [selectedTaskForAssignment, tasks, users, programs, assignments, clearMessages]);

  const handleConfirmAssignmentByAdmin = () => {
    if (!selectedTaskForAssignment || !assignmentSuggestion || !assignmentSuggestion.suggestedPersonName) {
      setError("No valid AI suggestion to confirm.");
      return;
    }
    const task = tasks.find(t => t.id === selectedTaskForAssignment);
    const person = users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName && u.role === 'user');
    if (!task || !person) {
      setError("Selected task or suggested user not found for AI assignment.");
      return;
    }
    const personStillHasActiveTask = assignments.some(
      a => a.personId === person.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user')
    );
    if (personStillHasActiveTask) {
      setError(`${person.displayName} already has an active task. Cannot assign another until their current task is completed or declined.`);
      return;
    }
    if (assignments.find(a => a.taskId === task.id && (a.status !== 'declined_by_user' && a.status !== 'completed_admin_approved'))) {
      if (!window.confirm(`Task "${task.title}" is already assigned or pending. Reassign to ${person.displayName} (pending their acceptance)? This will clear previous active assignment for this task.`)) {
        return;
      }
    }
    const assignmentDeadline = assignmentForm.specificDeadline || task.deadline;
    const newAssignment: Assignment = {
      taskId: task.id,
      personId: person.id,
      taskTitle: task.title,
      personName: person.displayName,
      justification: assignmentSuggestion.justification,
      status: 'pending_acceptance',
      deadline: assignmentDeadline
    };
    setAssignments([...assignments.filter(a => a.taskId !== task.id || (a.status === 'declined_by_user' || a.status === 'completed_admin_approved')), newAssignment]);
    setAssignmentSuggestion(null);
    setSelectedTaskForAssignment(null);
    setAssignmentForm({ specificDeadline: '' });
    setSuccessMessage(`Task "${task.title}" proposed to ${person.displayName}. Waiting for their acceptance. (Notification via ${person.notificationPreference || 'none'} would be sent in a full system.)`);
  };

  const handleUserAssignmentResponse = (assignment: Assignment, accepted: boolean) => {
    clearMessages();
    if (!currentUser) return;
    const assignmentIndex = assignments.findIndex(a => a.taskId === assignment.taskId && a.personId === currentUser.id);
    if (assignmentIndex === -1) {
      setError("Assignment not found or action not permitted.");
      return;
    }
    const assignedUser = users.find(u => u.id === assignment.personId);
    let adminToNotify: User | undefined;
    if (assignedUser?.referringAdminId) {
      adminToNotify = users.find(u => u.id === assignedUser.referringAdminId && u.role === 'admin');
    }
    if (!adminToNotify) {
      adminToNotify = users.find(u => u.role === 'admin');
    }
    const adminNotificationNote = adminToNotify ? `(Admin ${adminToNotify.displayName} would be notified in a full system.)` : '(Admin would be notified in a full system.)';

    if (accepted) {
      const updatedAssignments = assignments.map((a, idx) => idx === assignmentIndex ? { ...a, status: 'accepted_by_user' as AssignmentStatus } : a);
      setAssignments(updatedAssignments);
      setSuccessMessage(`You have accepted the task: "${assignment.taskTitle}". ${adminNotificationNote}`);
    } else {
      const updatedAssignments = assignments.map((a, idx) => idx === assignmentIndex ? { ...a, status: 'declined_by_user' as AssignmentStatus } : a);
      setAssignments(updatedAssignments);
      setSuccessMessage(`You have declined the task: "${assignment.taskTitle}". ${adminNotificationNote}`);
    }
  };

  const handleCompleteTaskByUser = (assignment: Assignment, delayReason?: string) => {
    clearMessages();
    if (!currentUser || currentUser.id !== assignment.personId) {
      setError("Action not permitted.");
      return;
    }
    const submissionDate = new Date();
    const isLate = assignment.deadline ? submissionDate > new Date(new Date(assignment.deadline).setHours(23, 59, 59, 999)) : false;
    const newStatus: AssignmentStatus = isLate ? 'submitted_late' : 'submitted_on_time';
    const updatedAssignments = assignments.map(a => a.taskId === assignment.taskId && a.personId === currentUser.id ? {
      ...a,
      status: newStatus,
      userSubmissionDate: submissionDate.toISOString(),
      userDelayReason: isLate ? delayReason : undefined,
    } : a);
    setAssignments(updatedAssignments);
    const taskInfo = tasks.find(t => t.id === assignment.taskId);
    const adminToNotify = taskInfo ? users.find(u => u.role === 'admin') : undefined;
    const adminNotificationNote = adminToNotify ? `(Admin ${adminToNotify.displayName} would be notified in a full system.)` : '(Admin would be notified in a full system.)';
    setSuccessMessage(`Task "${assignment.taskTitle}" marked as completed. ${isLate ? 'It was submitted late.' : ''} ${adminNotificationNote}`);
    setAssignmentToSubmitDelayReason(null);
    setUserSubmissionDelayReason('');
  };

  const handleAdminApproveCompletion = (assignment: Assignment) => {
    clearMessages();
    if (!currentUser || currentUser.role !== 'admin') {
      setError("Only admins can approve task completion.");
      return;
    }
    const updatedAssignments = assignments.map(a => a.taskId === assignment.taskId && a.personId === assignment.personId ? { ...a, status: 'completed_admin_approved' as AssignmentStatus } : a);
    setAssignments(updatedAssignments);
    const userToNotify = users.find(u => u.id === assignment.personId);
    const userNotificationNote = userToNotify ? `(User ${userToNotify.displayName} would be notified via ${userToNotify.notificationPreference || 'none'} in a full system.)` : '';
    setSuccessMessage(`Submission for task "${assignment.taskTitle}" by ${assignment.personName} has been approved. ${userNotificationNote}`);
  };

  const handleAdminUnassignTask = (assignmentToClear: Assignment) => {
    if (!currentUser || currentUser.role !== 'admin') {
      setError("Action not permitted.");
      return;
    }
    setAssignments(assignments.filter(a => !(a.taskId === assignmentToClear.taskId && a.personId === assignmentToClear.personId)));
    setSuccessMessage(`Assignment "${assignmentToClear.taskTitle}" for ${assignmentToClear.personName} has been cleared/unassigned.`);
  };

  const handleAddAdminLogEntry = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminLogText.trim() && !adminLogImageFile) {
      setError("Please provide some text or an image for the log entry.");
      return;
    }
    if (!currentUser || currentUser.role !== 'admin') return;

    setIsSubmittingLog(true);
    clearMessages();

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
        setIsSubmittingLog(false);
        return;
      }
    }

    const newLogEntry: AdminLogEntry = {
      id: Date.now().toString(),
      adminId: currentUser.id,
      adminDisplayName: currentUser.displayName,
      timestamp: new Date().toISOString(),
      logText: adminLogText.trim(),
      ...(imagePreviewUrl && { imagePreviewUrl }),
    };

    setAdminLogs(prevLogs => [newLogEntry, ...prevLogs]);
    setAdminLogText('');
    setAdminLogImageFile(null);
    const fileInput = document.getElementById('admin-log-image-file') as HTMLInputElement;
    if (fileInput) fileInput.value = '';
    setSuccessMessage("Log entry added successfully.");
    setIsSubmittingLog(false);
  };

  const handleDeleteAdminLogEntry = (logId: string) => {
    if (!currentUser || currentUser.role !== 'admin') return;
    setAdminLogs(prevLogs => prevLogs.filter(log => log.id !== logId));
    setSuccessMessage("Log entry deleted.");
  };

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
          onChange={e => setNewLoginForm(prev => ({ ...prev, email: e.target.value }))}
          required
          autoFocus
        />
        <AuthFormInput
          id="new-login-password"
          type="password"
          aria-label="Enter your password"
          placeholder="Enter your password"
          value={newLoginForm.password}
          onChange={e => setNewLoginForm(prev => ({ ...prev, password: e.target.value }))}
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
          onClick={() => {
            setAuthView('register');
            clearMessages();
            setNewLoginForm(initialNewLoginForm);
          }}
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
          onChange={e => setNewRegistrationForm(prev => ({ ...prev, name: e.target.value }))}
          required
          autoFocus
        />
        <AuthFormInput
          id="new-reg-email"
          type="email"
          aria-label="Enter your email"
          placeholder="Enter your email"
          value={newRegistrationForm.email}
          onChange={e => setNewRegistrationForm(prev => ({ ...prev, email: e.target.value }))}
          required
        />
        <AuthFormInput
          id="new-reg-password"
          type="password"
          aria-label="Enter your password"
          placeholder="Enter your password"
          value={newRegistrationForm.password}
          onChange={e => setNewRegistrationForm(prev => ({ ...prev, password: e.target.value }))}
          required
        />
        <AuthFormInput
          id="new-reg-confirm-password"
          type="password"
          aria-label="Enter your confirm password"
          placeholder="Enter your confirm password"
          value={newRegistrationForm.confirmPassword}
          onChange={e => setNewRegistrationForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
          required
        />
        <AuthFormSelect
          id="new-reg-role"
          aria-label="Select your role"
          value={newRegistrationForm.role}
          onChange={e => setNewRegistrationForm(prev => ({ ...prev, role: e.target.value as Role }))}
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
          onClick={() => {
            setAuthView('login');
            clearMessages();
            setNewRegistrationForm(initialNewRegistrationForm);
          }}
          className="font-medium text-authLink hover:underline"
        >
          login now
        </button>
      </p>
    </div>
  );


  // Render the appropriate page based on the state
  const renderPage = () => {
    if (page === 'adminLogin') {
      return (
        <AdminLoginPage onLogin={() => {
          setIsAdminLoggedIn(true);
          setPage('userManagement');
        }} />
      );
    }

    if (page === 'preRegister') {
      return (
        <PreRegistrationFormPage
          formState={preRegistrationForm}
          setFormState={setPreRegistrationForm}
          onSubmit={handlePreRegistrationSubmit}
          error={error}
          successMessage={successMessage}
          infoMessage={infoMessage}
          clearMessages={clearMessages}
          navigateToLogin={() => navigateTo('login')}
        />
      );
    }

    if (page === 'userManagement') {
      if (!isAdminLoggedIn) {
        return <div className="text-center py-4">Please log in as an administrator to manage users.</div>;
      }
      return (
        <div className="p-4">
          <h2 className="text-xl font-bold mb-4">Pending User Approvals</h2>
          <input
            type="text"
            placeholder="Search by email, ID, or name"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="mb-4 border p-2 w-full"
          />
          {filteredPendingUsers.length === 0 ? (
            <p>No matching users found.</p>
          ) : (
            <ul className="space-y-4">
              {filteredPendingUsers.map(user => (
                <li key={user.id} className="border p-4 rounded-md bg-white shadow-sm">
                  <p><strong>Email:</strong> {user.email}</p>
                  <p><strong>System ID:</strong> {user.uniqueId}</p>
                  <p><strong>Display Name:</strong> {user.displayName}</p>
                  <div className="flex gap-2 mt-2">
                    <button onClick={() => handleApproveUser(user.id)} className="bg-green-600 text-white px-3 py-1 rounded">Approve</button>
                    <button onClick={() => handleRejectUser(user.id)} className="bg-red-500 text-white px-3 py-1 rounded">Reject</button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      );
    }

    if (!currentUser) {
      return (
        <div className="flex justify-center items-center h-full">
          {authView === 'login' ? renderNewAuthLoginPage() : renderNewAuthRegisterPage()}
        </div>
      );
    }

    // Default return for logged-in users, if no specific page is matched
    return <div className="text-center py-4">Welcome, {currentUser.displayName}!</div>;
  };


  return (
    <div className="min-h-screen bg-background text-textlight">
      <header className="bg-surface shadow-md">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-primary">TaskMaster</h1>
          </div>
          {currentUser && (
            <nav className="flex items-center space-x-4">
              {/* Navigation buttons would go here, based on currentPage and currentUser.role */}
              {/* Example for admin: */}
              {currentUser.role === 'admin' && (
                <>
                  <button onClick={() => navigateTo('userManagement')} className="text-textlight hover:text-primary">User Management</button>
                  <button onClick={() => navigateTo('managePrograms')} className="text-textlight hover:text-primary">Manage Programs</button>
                  <button onClick={() => navigateTo('manageTasks')} className="text-textlight hover:text-primary">Manage Tasks</button>
                  <button onClick={() => navigateTo('assignWork')} className="text-textlight hover:text-primary">Assign Work</button>
                  <button onClick={() => navigateTo('adminLogs')} className="text-textlight hover:text-primary">Admin Logs</button>
                </>
              )}
              {/* Example for user: */}
              {currentUser.role === 'user' && (
                <>
                  <button onClick={() => navigateTo('viewTasks')} className="text-textlight hover:text-primary">Available Tasks</button>
                  <button onClick={() => navigateTo('viewAssignments')} className="text-textlight hover:text-primary">My Assignments</button>
                </>
              )}
              <button onClick={handleLogout} className="text-textlight hover:text-primary">Logout</button>
            </nav>
          )}
        </div>
      </header>

      <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {renderPage()}
      </main>

      <footer className="text-center py-6 text-sm text-neutral border-t border-gray-200 mt-12">
        <p>&copy; 2023 TaskMaster. All rights reserved.</p>
      </footer>

      {showSuccessModal && (
        <Modal
          title="Action Successful"
          message={successMessage || "Operation completed successfully."}
          onClose={() => setShowSuccessModal(false)}
        />
      )}
      {error && (
        <Modal
          title="Error"
          message={error}
          onClose={() => setError(null)}
          isError={true}
        />
      )}
      {infoMessage && (
        <Modal
          title="Information"
          message={infoMessage}
          onClose={() => setInfoMessage(null)}
        />
      )}
    </div>
  );
};

export default App;