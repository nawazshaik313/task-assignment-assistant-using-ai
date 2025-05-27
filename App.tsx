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
const AuthFormSelect: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { id: string; 'aria-label': string; children: React.ReactNode }> = ({ id, children, ...props }) => (
<select
id={id}
{...props}
className="w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight"{children}
</select> );
const FormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label: string; id: string }> = ({
label,
id,
...props
}) => (

<div> <label htmlFor={id} className="block text-sm font-medium text-textlight"> {label} </label> <input id={id} {...props} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" /> </div> );
const FormTextarea: React.FC<
React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; id: string }

= ({ label, id, ...props }) => (

<div> <label htmlFor={id} className="block text-sm font-medium text-textlight"> {label} </label> <textarea id={id} {...props} rows={3} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" /> </div> );
const FormSelect: React.FC<
React.SelectHTMLAttributes<HTMLSelectElement> & { label: string; id: string; children: React.ReactNode }

= ({ label, id, children, ...props }) => (

<div> <label htmlFor={id} className="block text-sm font-medium text-textlight"> {label} </label> <select id={id} {...props} className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-neutral focus:outline-none focus:ring-primary focus:border-primary sm:text-sm rounded-md bg-surface text-textlight" > {children} </select> </div> );

const FormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label: string; id: string }> = ({ label, id, ...props }) => (

<div> <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label> <input id={id} {...props} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" /> </div> );
const FormTextarea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; id: string }> = ({ label, id, ...props }) => (

<div> <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label> <textarea id={id} {...props} rows={3} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" /> </div> );
const FormSelect: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { label: string; id: string; children: React.ReactNode }> = ({ label, id, children, ...props }) => (

<div> <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label> <select id={id} {...props} className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-neutral focus:outline-none focus:ring-primary focus:border-primary sm:text-sm rounded-md bg-surface text-textlight"> {children} </select> </div> );
// --- MAIN APP COMPONENT ---
const App: React.FC = () => {
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

const [users, setUsers] = useState<User[]>([]);
const [pendingUsers, setPendingUsers] = useState<PendingUser[]>([]);

const clearMessages = useCallback(() => {
setError(null);
setSuccessMessage(null);
setInfoMessage(null);
}, []);

const navigateTo = useCallback((targetPage: Page) => {
clearMessages();
setPage(targetPage);
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
password: approvingUser.password,
role: 'user'
};
setUsers(prev => [...prev, newUser]);
setPendingUsers(prev => prev.filter(pu => pu.id !== id));
try {
await sendApprovalEmail(approvingUser.email, approvingUser.displayName);
setSuccessMessage(User ${approvingUser.displayName} approved.);
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
setSuccessMessage(User ${rejectingUser?.displayName || ''} rejected.);
setShowSuccessModal(true);
};

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
onSubmit={() => {}}
error={error}
successMessage={successMessage}
infoMessage={infoMessage}
clearMessages={clearMessages}
navigateToLogin={() => navigateTo('login')}
/>
);
}

if (isAdminLoggedIn && page === 'userManagement') {
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

return <div className="text-center py-4">No content to display</div>;
};

export default App;




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
const FormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label: string; id: string; }> = ({ label, id, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <input id={id} {...props} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" />
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
  email: '',
  uniqueId: '',
  displayName: '',
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


  const clearMessages = useCallback(() => { setError(null); setSuccessMessage(null); setInfoMessage(null); }, []);
  const navigateTo = useCallback((page: Page, params?: Record<string, string>) => { let hash = `#${page}`; if (params && Object.keys(params).length > 0) { hash += `?${new URLSearchParams(params).toString()}`; } if (window.location.hash !== hash) { window.location.hash = hash; } else { _setCurrentPageInternal(page); /* Ensure internal state updates if hash is same */ } }, []);

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
          // For unauthenticated pre-reg, we primarily care about capturing the refAdminId.
          // DisplayName resolution can be basic or attempted if users list is available.
          const adminUser = users.find(u => u.id === refAdminIdFromHash && u.role === 'admin');
          setPreRegistrationForm(prev => ({
            ...initialPreRegistrationFormState, // Reset other fields
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
        // If not Page.PreRegistration and not logged in, default to Login page view.
        // The main App return will handle rendering Auth forms.
        _setCurrentPageInternal(Page.Login);
        if (targetPageFromHashPath && targetPageFromHashPath !== Page.Login.toUpperCase()) {
            // If there was a specific hash, redirect to login by changing hash
            // This ensures after login, user isn't stuck on an invalid pre-login hash.
            // Or, store intended path to redirect after login (more complex).
            // For now, just go to login.
           if(window.location.hash !== `#${Page.Login}`) navigateTo(Page.Login);
        }
        return;
      }

      // Logged-in user routing logic
      const defaultPageDetermination = currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments;
      let newPage = (targetPageFromHashPath || defaultPageDetermination) as Page;

      // For logged-in users, redirect away from auth/pre-reg pages
      if ([Page.Login, Page.PreRegistration, Page.AdminRegistrationEmail, Page.AdminRegistrationProfile, Page.InitialAdminSetup].includes(newPage as Page)) {
        newPage = defaultPageDetermination;
      }
      
      const currentTopLevelPagePath = window.location.hash.substring(1).split('?')[0].toUpperCase();
      const targetParams = paramsString ? Object.fromEntries(params) : undefined;

      if (newPage !== currentTopLevelPagePath) {
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
    setNewRegistrationForm({ name: '', email: '', password: '', confirmPassword: '', role: 'user' });
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
        setNewLoginForm({ email: '', password: '' }); 
        setSuccessMessage(`Login successful! Welcome back, ${user.displayName}.`); 
        // Navigation will be handled by useEffect watching currentUser
      } else { 
        setError("Invalid password."); 
      } 
    } else { 
      setError("Email address not found or account not yet approved/created."); 
    } 
  };

  const handleForgotPassword = () => { clearMessages(); if (!newLoginForm.email.trim()) { setError("Please enter your Email Address first to check for password recovery options."); return; } const userToCheck = users.find(u => u.email === newLoginForm.email); if (userToCheck) { setInfoMessage(`Password Recovery for '${userToCheck.displayName}': In a real system, a password reset link would be sent to ${userToCheck.email}. This demo doesn't send actual emails.`); } else { setError("Email Address not found in the system."); } };
  
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
      }; 
      setPendingUsers(prev => [...prev, newPendingUser]); 
      setPreRegistrationForm(initialPreRegistrationFormState); // Clear the form
      setSuccessMessage("Your ID submission has been received. An administrator will review it. You can log in after approval and full account setup (including email and password assignment by admin)."); 
      // Navigate to login page or show a message to check back later.
      // Forcing authView to login and navigateTo to Page.Login might be good UX.
      setAuthView('login');
      navigateTo(Page.Login); // Redirect to login page view
  };

  const handleLogout = () => { clearMessages(); setCurrentUser(null); setNewLoginForm({ email: '', password: '' }); setAuthView('login'); setPreRegistrationForm(initialPreRegistrationFormState); setSuccessMessage("You have been logged out."); navigateTo(Page.Login); };
  
  const handleUpdateProfile = (e: React.FormEvent) => { e.preventDefault(); if (!currentUser) return; clearMessages(); if (!userForm.displayName.trim()) { setError("Display name cannot be empty."); return; } if (!userForm.email.trim() || !/\S+@\S+\.\S+/.test(userForm.email)) { setError("A valid email address is required."); return; } if (userForm.email !== currentUser.email && users.some(u => u.email === userForm.email && u.id !== currentUser.id)) { setError("This email address is already in use by another account."); return; } if (userForm.uniqueId !== currentUser.uniqueId && users.some(u => u.uniqueId === userForm.uniqueId && u.id !== currentUser.id)) { setError("This System ID is already in use by another account."); return; } let newPassword = currentUser.password; if (userForm.password) { if (userForm.password !== userForm.confirmPassword) { setError("New passwords do not match."); return; } newPassword = userForm.password; } const updatedUser: User = { ...currentUser, email: userForm.email, uniqueId: currentUser.role === 'admin' ? userForm.uniqueId : currentUser.uniqueId, displayName: userForm.displayName, position: userForm.position, userInterests: userForm.userInterests, phone: userForm.phone, notificationPreference: userForm.notificationPreference, password: newPassword, }; setUsers(users.map(u => (u.id === currentUser.id ? updatedUser : u))); setCurrentUser(updatedUser); setUserForm(prev => ({ ...prev, password: '', confirmPassword: '' })); setSuccessMessage("Profile updated successfully."); navigateTo(currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments); };
  const handleSaveOrApproveUserByAdmin = (e: React.FormEvent) => { e.preventDefault(); clearMessages(); if (!userForm.email.trim() || !/\S+@\S+\.\S+/.test(userForm.email)) { setError("A valid email address is required."); return; } if (!userForm.uniqueId.trim() || !userForm.displayName.trim() || !userForm.position.trim()) { setError("Email, System ID, Display Name, and Position are required."); return; } const isEditing = !!editingUserId && !approvingPendingUser; const isApproving = !!approvingPendingUser; const isAddingNew = !isEditing && !isApproving; if (isAddingNew || isApproving) { if (!userForm.password) { setError("Password is required for new/approved users."); return; } if (userForm.password !== userForm.confirmPassword) { setError("Passwords do not match."); return; } } else if (isEditing) { if (userForm.password && userForm.password !== userForm.confirmPassword) { setError("New passwords do not match."); return; } } const targetId = editingUserId || approvingPendingUser?.id; if (users.some(u => u.email === userForm.email && u.id !== targetId)) { setError("This email address is already in use by another account."); return;} if (users.some(u => u.uniqueId === userForm.uniqueId && u.id !== targetId)) { setError("This System ID is already in use by another account."); return;} if (isAddingNew && pendingUsers.some(pu => pu.uniqueId === userForm.uniqueId && pu.id !== targetId)) { setError("This System ID is pending approval for another user. Resolve pending user or choose a different ID."); return; } if (isEditing) { const userToUpdate = users.find(u => u.id === editingUserId); if (!userToUpdate) { setError("User not found for editing."); return; } const updatedUser: User = { ...userToUpdate, email: userForm.email, uniqueId: userForm.uniqueId, displayName: userForm.displayName, position: userForm.position, userInterests: userForm.userInterests, phone: userForm.phone, notificationPreference: userForm.notificationPreference, role: userForm.role, password: userForm.password ? userForm.password : userToUpdate.password, }; setUsers(users.map(u => u.id === editingUserId ? updatedUser : u)); setSuccessMessage(`User '${updatedUser.displayName}' updated successfully.`); } else { const newUser: User = { id: approvingPendingUser ? approvingPendingUser.id : Date.now().toString(), email: userForm.email, uniqueId: userForm.uniqueId, password: userForm.password!, displayName: userForm.displayName, position: userForm.position, userInterests: userForm.userInterests, phone: userForm.phone, notificationPreference: userForm.notificationPreference, role: userForm.role, referringAdminId: approvingPendingUser ? approvingPendingUser.referringAdminId : currentUser?.id, }; setUsers(prevUsers => [...prevUsers, newUser]); if (approvingPendingUser) { setPendingUsers(prevPending => prevPending.filter(pu => pu.id !== approvingPendingUser.id)); setSuccessMessage(`User '${newUser.displayName}' (System ID: ${newUser.uniqueId}) approved with email ${newUser.email}, account activated, and password set. (Notification via ${newUser.notificationPreference || 'none'} would be sent.)`); } else { setSuccessMessage(`User '${newUser.displayName}' (System ID: ${newUser.uniqueId}) added with email ${newUser.email} and password.`); } } setUserForm(initialUserFormData); setEditingUserId(null); setApprovingPendingUser(null); };
  const handleEditUserByAdmin = (user: User) => { setApprovingPendingUser(null); setEditingUserId(user.id); setUserForm({ email: user.email, uniqueId: user.uniqueId, displayName: user.displayName, position: user.position, userInterests: user.userInterests || '', phone: user.phone || '', notificationPreference: user.notificationPreference || 'none', role: user.role, password: '', confirmPassword: '', referringAdminId: user.referringAdminId || '' }); clearMessages(); };
  const handleInitiateApprovePendingUser = (pendingUser: PendingUser) => { setEditingUserId(null); setApprovingPendingUser(pendingUser); setUserForm({ ...initialUserFormData, uniqueId: pendingUser.uniqueId, displayName: pendingUser.displayName, referringAdminId: pendingUser.referringAdminId, role: 'user', }); clearMessages(); setInfoMessage(`Reviewing pending user: ${pendingUser.displayName} (ID: ${pendingUser.uniqueId}). Please set their email, complete their profile, set a password, and assign a role.`); };
  const handleRejectPendingUser = (pendingUserId: string) => { setPendingUsers(prev => prev.filter(pu => pu.id !== pendingUserId)); setSuccessMessage("Pending user request rejected."); if (approvingPendingUser?.id === pendingUserId) { setApprovingPendingUser(null); setUserForm(initialUserFormData); } };
  const handleDeleteUser = (userId: string) => { if (currentUser?.role !== 'admin') { setError("Only admins can delete users."); return; } if (userId === currentUser?.id) { setError("You cannot delete your own account."); return; } setUsers(users.filter(u => u.id !== userId)); setAssignments(assignments.filter(a => a.personId !== userId)); setSuccessMessage("User deleted successfully."); if(editingUserId === userId) { setEditingUserId(null); setUserForm(initialUserFormData); } };
  const handleAddProgram = (e: React.FormEvent) => { e.preventDefault(); clearMessages(); if (!programForm.name.trim()) { setError("Program name cannot be empty."); return; } const newProgram: Program = { ...programForm, id: Date.now().toString() }; setPrograms([...programs, newProgram]); setProgramForm({ name: '', description: '' }); setSuccessMessage(`Program "${newProgram.name}" added successfully.`); };
  const handleDeleteProgram = (id: string) => { clearMessages(); const isProgramInUse = tasks.some(task => task.programId === id); if (isProgramInUse) { if (!window.confirm("This program is linked to tasks. Deleting it will unlink these tasks. Are you sure?")) { return; } setTasks(tasks.map(task => task.programId === id ? {...task, programId: undefined, programName: undefined } : task)); } setPrograms(programs.filter(p => p.id !== id)); setSuccessMessage("Program deleted successfully."); };
  const handleAddTask = (e: React.FormEvent) => { e.preventDefault(); clearMessages(); if (!taskForm.title.trim()) { setError("Task title cannot be empty."); return; } const program = programs.find(p => p.id === taskForm.programId); const newTask: Task = { id: Date.now().toString(), title: taskForm.title, description: taskForm.description, requiredSkills: taskForm.requiredSkills, programId: taskForm.programId || undefined, programName: program ? program.name : undefined, deadline: taskForm.deadline || undefined }; setTasks([...tasks, newTask]); setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' }); setSuccessMessage(`Task "${newTask.title}" added successfully.`); };
  const handleDeleteTask = (id: string) => { clearMessages(); setTasks(tasks.filter(t => t.id !== id)); setAssignments(assignments.filter(a => a.taskId !== id));  setSuccessMessage("Task deleted successfully."); };
  const fetchAssignmentSuggestion = useCallback(async () => { if (!selectedTaskForAssignment) { setError("Please select a task first."); return; } const task = tasks.find(t => t.id === selectedTaskForAssignment); if (!task) { setError("Selected task not found."); return; } const activeUserIdsWithTasks = assignments .filter(a => a.status === 'pending_acceptance' || a.status === 'accepted_by_user') .map(a => a.personId); const trulyAvailableUsers = users.filter(u => u.role === 'user' && !activeUserIdsWithTasks.includes(u.id)); if (trulyAvailableUsers.length === 0) { setError("No users available to assign tasks to (either no users, or all users have active tasks)."); setAssignmentSuggestion({ suggestedPersonName: null, justification: "No users (non-admin) available without active tasks in the system." }); return; } setIsLoadingSuggestion(true); clearMessages(); setAssignmentSuggestion(null); try { const suggestion = await getAssignmentSuggestion(task, trulyAvailableUsers, programs, assignments); setAssignmentSuggestion(suggestion); if (!suggestion?.suggestedPersonName && suggestion?.justification) { setInfoMessage(suggestion.justification); } } catch (err) { console.error("Error fetching suggestion:", err); const errorMessage = err instanceof Error ? err.message : "An unknown error occurred."; setError(errorMessage); setAssignmentSuggestion({ suggestedPersonName: null, justification: errorMessage }); } finally { setIsLoadingSuggestion(false); }  }, [selectedTaskForAssignment, tasks, users, programs, assignments, clearMessages]);
  const handleConfirmAssignmentByAdmin = () => {  if (!selectedTaskForAssignment || !assignmentSuggestion || !assignmentSuggestion.suggestedPersonName) { setError("No valid AI suggestion to confirm."); return; } const task = tasks.find(t => t.id === selectedTaskForAssignment); const person = users.find(u => u.displayName === assignmentSuggestion.suggestedPersonName && u.role === 'user'); if (!task || !person) { setError("Selected task or suggested user not found for AI assignment."); return; } const personStillHasActiveTask = assignments.some( a => a.personId === person.id && (a.status === 'pending_acceptance' || a.status === 'accepted_by_user') ); if (personStillHasActiveTask) { setError(`${person.displayName} already has an active task. Cannot assign another until their current task is completed or declined.`); return; } if (assignments.find(a => a.taskId === task.id && (a.status !== 'declined_by_user' && a.status !== 'completed_admin_approved'))) { if (!window.confirm(`Task "${task.title}" is already assigned or pending. Reassign to ${person.displayName} (pending their acceptance)? This will clear previous active assignment for this task.`)) { return; } } const assignmentDeadline = assignmentForm.specificDeadline || task.deadline; const newAssignment: Assignment = { taskId: task.id, personId: person.id, taskTitle: task.title, personName: person.displayName, justification: assignmentSuggestion.justification, status: 'pending_acceptance', deadline: assignmentDeadline }; setAssignments([...assignments.filter(a => a.taskId !== task.id || (a.status === 'declined_by_user' || a.status === 'completed_admin_approved')), newAssignment]); setAssignmentSuggestion(null); setSelectedTaskForAssignment(null); setAssignmentForm({ specificDeadline: '' }); setSuccessMessage(`Task "${task.title}" proposed to ${person.displayName}. Waiting for their acceptance. (Notification via ${person.notificationPreference || 'none'} would be sent in a full system.)`);  };
  const handleUserAssignmentResponse = (assignment: Assignment, accepted: boolean) => { clearMessages(); if (!currentUser) return; const assignmentIndex = assignments.findIndex(a => a.taskId === assignment.taskId && a.personId === currentUser.id); if (assignmentIndex === -1) { setError("Assignment not found or action not permitted."); return; } const assignedUser = users.find(u => u.id === assignment.personId); let adminToNotify: User | undefined; if (assignedUser?.referringAdminId) { adminToNotify = users.find(u => u.id === assignedUser.referringAdminId && u.role === 'admin'); } if (!adminToNotify) { adminToNotify = users.find(u => u.role === 'admin'); } const adminNotificationNote = adminToNotify ? `(Admin ${adminToNotify.displayName} would be notified in a full system.)` : '(Admin would be notified in a full system.)'; if (accepted) { const updatedAssignments = assignments.map((a, idx) => idx === assignmentIndex ? { ...a, status: 'accepted_by_user' as AssignmentStatus } : a ); setAssignments(updatedAssignments); setSuccessMessage(`You have accepted the task: "${assignment.taskTitle}". ${adminNotificationNote}`); } else { const updatedAssignments = assignments.map((a, idx) => idx === assignmentIndex ? { ...a, status: 'declined_by_user' as AssignmentStatus } : a ); setAssignments(updatedAssignments); setSuccessMessage(`You have declined the task: "${assignment.taskTitle}". ${adminNotificationNote}`); } };
  const handleCompleteTaskByUser = (assignment: Assignment, delayReason?: string) => { clearMessages(); if (!currentUser || currentUser.id !== assignment.personId) { setError("Action not permitted."); return; } const submissionDate = new Date(); const isLate = assignment.deadline ? submissionDate > new Date(new Date(assignment.deadline).setHours(23, 59, 59, 999)) : false; const newStatus: AssignmentStatus = isLate ? 'submitted_late' : 'submitted_on_time'; const updatedAssignments = assignments.map(a => a.taskId === assignment.taskId && a.personId === currentUser.id ? { ...a, status: newStatus, userSubmissionDate: submissionDate.toISOString(), userDelayReason: isLate ? delayReason : undefined, } : a ); setAssignments(updatedAssignments); const taskInfo = tasks.find(t => t.id === assignment.taskId); const adminToNotify = taskInfo ? users.find(u => u.role === 'admin') : undefined; const adminNotificationNote = adminToNotify ? `(Admin ${adminToNotify.displayName} would be notified in a full system.)` : '(Admin would be notified in a full system.)'; setSuccessMessage(`Task "${assignment.taskTitle}" marked as completed. ${isLate ? 'It was submitted late.' : ''} ${adminNotificationNote}`); setAssignmentToSubmitDelayReason(null); setUserSubmissionDelayReason('');  };
  const handleAdminApproveCompletion = (assignment: Assignment) => { clearMessages(); if (!currentUser || currentUser.role !== 'admin') { setError("Only admins can approve task completion."); return; } const updatedAssignments = assignments.map(a => a.taskId === assignment.taskId && a.personId === assignment.personId ? { ...a, status: 'completed_admin_approved' as AssignmentStatus } : a ); setAssignments(updatedAssignments); const userToNotify = users.find(u => u.id === assignment.personId); const userNotificationNote = userToNotify ? `(User ${userToNotify.displayName} would be notified via ${userToNotify.notificationPreference || 'none'} in a full system.)` : ''; setSuccessMessage(`Submission for task "${assignment.taskTitle}" by ${assignment.personName} has been approved. ${userNotificationNote}`); };
  const handleAdminUnassignTask = (assignmentToClear: Assignment) => { if (!currentUser || currentUser.role !== 'admin') { setError("Action not permitted."); return; } setAssignments(assignments.filter(a => !(a.taskId === assignmentToClear.taskId && a.personId === assignmentToClear.personId))); setSuccessMessage(`Assignment "${assignmentToClear.taskTitle}" for ${assignmentToClear.personName} has been cleared/unassigned.`); };
  const handleAddAdminLogEntry = async (e: React.FormEvent) => { e.preventDefault(); if (!adminLogText.trim() && !adminLogImageFile) { setError("Please provide some text or an image for the log entry."); return; } if (!currentUser || currentUser.role !== 'admin') return; setIsSubmittingLog(true); clearMessages(); let imagePreviewUrl: string | undefined = undefined; if (adminLogImageFile) { try { imagePreviewUrl = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result as string); reader.onerror = reject; reader.readAsDataURL(adminLogImageFile); }); } catch (err) { console.error("Error reading image file:", err); setError("Failed to read image file. Please try a different image or ensure it's not too large."); setIsSubmittingLog(false); return; } } const newLogEntry: AdminLogEntry = { id: Date.now().toString(), adminId: currentUser.id, adminDisplayName: currentUser.displayName, timestamp: new Date().toISOString(), logText: adminLogText.trim(), ...(imagePreviewUrl && { imagePreviewUrl }), }; setAdminLogs(prevLogs => [newLogEntry, ...prevLogs]); setAdminLogText(''); setAdminLogImageFile(null); const fileInput = document.getElementById('admin-log-image-file') as HTMLInputElement; if (fileInput) fileInput.value = ''; setSuccessMessage("Log entry added successfully."); setIsSubmittingLog(false); };
  const handleDeleteAdminLogEntry = (logId: string) => { if (!currentUser || currentUser.role !== 'admin') return; setAdminLogs(prevLogs => prevLogs.filter(log => log.id !== logId)); setSuccessMessage("Log entry deleted."); };

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
        <AuthFormInput 
          id="new-reg-password" 
          type="password" 
          aria-label="Enter your password"
          placeholder="Enter your password" 
          value={newRegistrationForm.password} 
          onChange={e => setNewRegistrationForm(prev => ({...prev, password: e.target.value}))} 
          required 
        />
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
      // This case should ideally not be reached if the App's top-level structure correctly shows 
      // the PreRegistrationFormPage or the new auth flow. This is a fallback.
      console.error("Error: renderPage called without currentUser, but auth/pre-reg flow should handle this.");
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
              <FormInput id="profile-password" label="New System Password" type="password" value={userForm.password} onChange={e => setUserForm(prev => ({ ...prev, password: e.target.value }))} placeholder="Leave blank to keep current" /> 
              <FormInput id="profile-confirmPassword" label="Confirm New Password" type="password" value={userForm.confirmPassword} onChange={e => setUserForm(prev => ({ ...prev, confirmPassword: e.target.value }))} placeholder="Confirm new password" /> 
              <button type="submit" className="w-full btn-primary">Update Profile</button> 
            </form> 
          </div> 
        );
      case Page.UserManagement: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; const adminManagedPendingUsers = pendingUsers.filter(pu => pu.referringAdminId === currentUser.id || users.find(u => u.id === pu.referringAdminId)?.role === 'admin'); const adminManagedActiveUsers = users.filter(u => u.referringAdminId === currentUser.id || u.role === 'admin' || users.find(adm => adm.id === u.referringAdminId && adm.role ==='admin')); const generateLinkForAdmin = () => { if (!currentUser || currentUser.role !== 'admin') return; const link = `${window.location.origin}${window.location.pathname}#${Page.PreRegistration}?refAdminId=${currentUser.id}`; setGeneratedLink(link); setSuccessMessage("Pre-registration link generated. Copy it below."); }; const copyLinkToClipboard = () => { if (!generatedLink) return; navigator.clipboard.writeText(generatedLink) .then(() => setSuccessMessage("Link copied to clipboard!")) .catch(err => setError("Failed to copy link: " + err)); }; return ( <div className="space-y-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-primary flex items-center"> <PlusCircleIcon className="w-7 h-7 mr-2" /> {editingUserId ? 'Edit Existing User' : approvingPendingUser ? `Approve Pending User: ${approvingPendingUser.displayName}` : 'Directly Add New User (Managed by You)'} </h2> <form onSubmit={handleSaveOrApproveUserByAdmin} className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormInput id="manage-email" label="Email Address (Login)" type="email" value={userForm.email} onChange={e => setUserForm(prev => ({...prev, email: e.target.value}))} required /> <FormInput id="manage-uniqueId" label="System ID / Username" type="text" value={userForm.uniqueId} onChange={e => setUserForm(prev => ({...prev, uniqueId: e.target.value}))} required readOnly={!!approvingPendingUser && !editingUserId} /> <FormInput id="manage-displayName" label="Display Name" type="text" value={userForm.displayName} onChange={e => setUserForm(prev => ({...prev, displayName: e.target.value}))} required readOnly={!!approvingPendingUser && !editingUserId} /> <FormInput id="manage-position" label="Position" type="text" value={userForm.position} onChange={e => setUserForm(prev => ({...prev, position: e.target.value}))} placeholder="e.g., Software Engineer" required /> <FormSelect id="manage-role" label="Role" value={userForm.role} onChange={e => setUserForm(prev => ({...prev, role: e.target.value as Role}))}><option value="user">User</option><option value="admin">Admin</option></FormSelect> <FormTextarea id="manage-userInterests" label="User Interests " value={userForm.userInterests} onChange={e => setUserForm(prev => ({...prev, userInterests: e.target.value}))} placeholder="e.g., Web Development, Event Organization"/> <FormInput id="manage-phone" label="Phone (Contact, Optional)" type="tel" value={userForm.phone} onChange={e => setUserForm(prev => ({...prev, phone: e.target.value}))} placeholder="e.g., +1234567890" /> <FormSelect id="manage-notificationPreference" label="Notification Preference" value={userForm.notificationPreference} onChange={e => setUserForm(prev => ({...prev, notificationPreference: e.target.value as NotificationPreference}))}> <option value="none">None</option> <option value="email">Email</option> <option value="phone">Phone</option> </FormSelect>  <FormInput id="manage-password" label={(editingUserId && !approvingPendingUser) ? "New System Password (Optional)" : "System Password"} type="password" value={userForm.password} onChange={e => setUserForm(prev => ({...prev, password: e.target.value}))} placeholder={(editingUserId && !approvingPendingUser) ? "Leave blank to keep current" : "Set a password for the user"} required={!(editingUserId && !approvingPendingUser)} /> <FormInput id="manage-confirmPassword" label="Confirm System Password" type="password" value={userForm.confirmPassword} onChange={e => setUserForm(prev => ({...prev, confirmPassword: e.target.value}))} placeholder="Confirm password" required={userForm.password !== '' || !(editingUserId && !approvingPendingUser)} /> <div className="flex space-x-2"> <button type="submit" className="flex-grow btn-primary">{editingUserId ? 'Save Changes' : approvingPendingUser ? 'Approve User & Set Up Account' : 'Add User'}</button> {(editingUserId || approvingPendingUser) && <button type="button" onClick={() => { setEditingUserId(null); setApprovingPendingUser(null); setUserForm(initialUserFormData); clearMessages();}} className="btn-neutral">Cancel</button>}</div> </form> </div> <div className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <h2 className="text-xl font-semibold text-info flex items-center"><KeyIcon className="w-6 h-6 mr-2"/> Generate Pre-registration Link (for Regular Users)</h2> <p className="text-sm text-neutral">Share this link with regular users to allow them to pre-register under your administration. They will submit their desired System ID and Display Name.</p> <button onClick={generateLinkForAdmin} className="btn-info">Generate My Link</button> {generatedLink && ( <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded"> <p className="text-sm text-blue-700 break-all mb-2">{generatedLink}</p> <button onClick={copyLinkToClipboard} className="btn-secondary text-xs px-2 py-1">Copy to Clipboard</button> </div> )} </div> {adminManagedPendingUsers.length > 0 && ( <div className="mt-8"> <h2 className="text-xl font-semibold mb-3 text-amber-600 flex items-center">Pending User Approvals ({adminManagedPendingUsers.length})</h2> <div className="space-y-3 max-h-[40vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow"> {adminManagedPendingUsers.map(pu => ( <div key={pu.id} className="bg-white border border-gray-200 rounded-lg p-3"> <div className="flex justify-between items-start"> <div> <h3 className="text-md font-semibold text-amber-700">{pu.displayName}</h3> <p className="text-xs text-gray-600">System ID: {pu.uniqueId}</p> <p className="text-xs text-gray-500 mt-0.5">Submitted: {new Date(pu.submissionDate).toLocaleDateString()}</p> <p className="text-xs text-gray-500 mt-0.5">Ref. Admin ID: {pu.referringAdminId.substring(0,8)}...</p></div> <div className="flex space-x-2"> <button onClick={() => handleInitiateApprovePendingUser(pu)} className="btn-success text-xs px-2 py-1">Review & Approve</button> <button onClick={() => handleRejectPendingUser(pu.id)} className="btn-danger text-xs px-2 py-1">Reject</button> </div> </div> </div> ))} </div> </div> )} <div className="mt-8"> <h2 className="text-xl font-semibold mb-3 text-primary flex items-center"><UsersIcon className="w-6 h-6 mr-2" /> Active Users ({adminManagedActiveUsers.length})</h2> {adminManagedActiveUsers.length === 0 ? <p className="text-neutral">No active users found.</p> : ( <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow"> {adminManagedActiveUsers.map(u => ( <div key={u.id} className="bg-white border border-gray-200 rounded-lg p-3"> <div className="flex justify-between items-start"> <div> <h3 className="text-md font-semibold text-texthighlight">{u.displayName} <span className="text-xs px-1.5 py-0.5 bg-accent text-white rounded-full align-middle">{u.role}</span></h3> <p className="text-xs text-gray-600">Email: {u.email}</p> <p className="text-xs text-gray-600">System ID: {u.uniqueId}</p> <p className="text-xs text-gray-500 mt-0.5">Position: {u.position || 'N/A'}</p> <p className="text-xs text-gray-500 mt-0.5 truncate" title={u.userInterests}>Interests: {u.userInterests || 'N/A'}</p> <p className="text-xs text-gray-500 mt-0.5">Phone: {u.phone || 'N/A'}</p> <p className="text-xs text-gray-500 mt-0.5">Notify via: {u.notificationPreference || 'none'}</p> </div> <div className="flex space-x-1"> <button onClick={() => handleEditUserByAdmin(u)} className="text-blue-500 hover:text-blue-700 p-1" aria-label={`Edit user ${u.displayName}`}><UserCircleIcon className="w-4 h-4"/> </button> {currentUser.id !== u.id && (<button onClick={() => handleDeleteUser(u.id)} className="text-red-500 hover:text-red-700 p-1" aria-label={`Delete user ${u.displayName}`}><TrashIcon className="w-4 h-4" /></button> )} </div> </div> </div> ))} </div> )} </div> </div> );
      case Page.ManagePrograms: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; return ( <div className="grid md:grid-cols-2 gap-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-info flex items-center"><PlusCircleIcon className="w-7 h-7 mr-2" /> Add New Program</h2> <form onSubmit={handleAddProgram} className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormInput id="programName" label="Program Name" type="text" value={programForm.name} onChange={e => setProgramForm(prev => ({ ...prev, name: e.target.value }))} required /> <FormTextarea id="programDescription" label="Description" value={programForm.description} onChange={e => setProgramForm(prev => ({ ...prev, description: e.target.value }))} /> <button type="submit" className="w-full btn-info">Add Program</button> </form> </div> <div> <h2 className="text-2xl font-semibold mb-4 text-info flex items-center"><BriefcaseIcon className="w-7 h-7 mr-2" /> Current Programs ({programs.length})</h2> {programs.length === 0 ? <p className="text-neutral">No programs.</p> : ( <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow"> {programs.map(p => ( <div key={p.id} className="bg-white border border-gray-200 rounded-lg p-3 flex justify-between items-start"> <div><h3 className="text-md font-semibold text-blue-600">{p.name}</h3><p className="text-xs text-gray-700 mt-0.5">{p.description || 'No description.'}</p></div> <button onClick={() => handleDeleteProgram(p.id)} className="text-red-500 hover:text-red-700 p-1" aria-label={`Delete program ${p.name}`}><TrashIcon className="w-4 h-4" /></button> </div>))} </div>)} </div> </div>);
      case Page.ManageTasks: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; return ( <div className="grid md:grid-cols-2 gap-8"> <div> <h2 className="text-2xl font-semibold mb-4 text-secondary flex items-center"><PlusCircleIcon className="w-7 h-7 mr-2" /> Add New Task</h2> <form onSubmit={handleAddTask} className="bg-surface shadow-lg rounded-lg p-6 space-y-4"> <FormInput id="taskTitle" label="Title" type="text" value={taskForm.title} onChange={e => setTaskForm(prev => ({ ...prev, title: e.target.value }))} required /> <FormTextarea id="taskDescription" label="Description" value={taskForm.description} onChange={e => setTaskForm(prev => ({ ...prev, description: e.target.value }))} /> <FormTextarea id="taskSkills" label="Required Skills for Task" value={taskForm.requiredSkills} onChange={e => setTaskForm(prev => ({ ...prev, requiredSkills: e.target.value }))} /> <FormSelect id="taskProgram" label="Associate with Program (Optional)" value={taskForm.programId || ''} onChange={e => setTaskForm(prev => ({...prev, programId: e.target.value || undefined }))}> <option value="">-- Select a Program --</option> {programs.map(prog => <option key={prog.id} value={prog.id}>{prog.name}</option>)} </FormSelect> <FormInput id="taskDeadline" label="Deadline (Optional)" type="date" value={taskForm.deadline || ''} onChange={e => setTaskForm(prev => ({ ...prev, deadline: e.target.value }))} /> <button type="submit" className="w-full btn-secondary">Add Task</button> </form> </div> <div> <h2 className="text-2xl font-semibold mb-4 text-secondary flex items-center"><ClipboardListIcon className="w-7 h-7 mr-2" /> Current Tasks ({tasks.length})</h2> {tasks.length === 0 ? <p className="text-neutral">No tasks.</p> : ( <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-2 bg-gray-50 p-4 rounded-lg shadow"> {tasks.map(t => ( <div key={t.id} className="bg-white border border-gray-200 rounded-lg p-3"> <div className="flex justify-between items-start"> <div> <h3 className="text-md font-semibold text-green-600">{t.title}</h3> {t.programName && <p className="text-xs text-blue-500 bg-blue-100 inline-block px-1.5 py-0.5 rounded-full my-0.5">Program: {t.programName}</p>} <p className="text-xs text-gray-700 mt-0.5">{t.description || 'No description.'}</p> <p className="text-xs text-gray-600 mt-0.5">Skills: {t.requiredSkills || 'N/A'}</p> {t.deadline && <p className="text-xs text-red-600 mt-0.5">Deadline: {new Date(t.deadline).toLocaleDateString()}</p>} </div> <button onClick={() => handleDeleteTask(t.id)} className="text-red-500 hover:text-red-700 p-1" aria-label={`Delete task ${t.title}`}><TrashIcon className="w-4 h-4" /></button> </div> </div> ))} </div>)} </div> </div>);
      case Page.ViewTasks: return ( <div> <h2 className="text-2xl font-semibold mb-6 text-secondary flex items-center"><ClipboardListIcon className="w-7 h-7 mr-2" /> Available Tasks ({tasks.length})</h2> {tasks.length === 0 ? <p className="text-neutral">No tasks currently available.</p> : ( <div className="space-y-4"> {tasks.map(t => ( <div key={t.id} className="bg-surface shadow-lg rounded-lg p-6"> <h3 className="text-lg font-semibold text-green-700">{t.title}</h3> {t.programName && <p className="text-sm text-blue-600 mt-1"><strong>Program:</strong> {t.programName}</p>} <p className="text-sm text-gray-700 mt-2">{t.description || 'No description.'}</p> <p className="text-sm text-gray-600 mt-2"><strong>Required Skills:</strong> {t.requiredSkills || 'N/A'}</p> {t.deadline && <p className="text-sm text-red-600 mt-2"><strong>Deadline:</strong> {new Date(t.deadline).toLocaleDateString()}</p>}</div>))} </div>)} </div>);
      case Page.AssignWork: if (currentUser.role !== 'admin') return <p>Access Denied.</p>; const assignableTasks = tasks.filter(task => !assignments.find(a => a.taskId === task.id && a.status !== 'declined_by_user' && a.status !== 'completed_admin_approved')); const selectedTaskDetails = selectedTaskForAssignment ? tasks.find(t => t.id === selectedTaskForAssignment) : null; const activeUserIdsCurrentlyWithTasks = assignments .filter(a => a.status === 'pending_acceptance' || a.status === 'accepted_by_user') .map(a => a.personId); const anyTrulyAvailableUsersForAISuggestion = users.some(u => u.role === 'user' && !activeUserIdsCurrentlyWithTasks.includes(u.id)); return ( <div> <h2 className="text-2xl font-semibold mb-6 text-accent flex items-center"><LightBulbIcon className="w-7 h-7 mr-2" /> Assign Work using AI</h2> <div className="bg-surface shadow-lg rounded-lg p-6 space-y-6"> <FormSelect id="selectTask" label="Select Task to Assign" value={selectedTaskForAssignment || ''} onChange={e => { setSelectedTaskForAssignment(e.target.value); setAssignmentSuggestion(null); setAssignmentForm({ specificDeadline: ''}); clearMessages();}} > <option value="" disabled>-- Select a Task --</option> {assignableTasks.map(task => ( <option key={task.id} value={task.id}>{task.title} {task.programName ? `(${task.programName})` : ''}</option> ))} </FormSelect> {selectedTaskDetails && selectedTaskDetails.deadline && (<p className="text-sm text-neutral">Default Task Deadline: {new Date(selectedTaskDetails.deadline).toLocaleDateString()}</p>)} <FormInput id="assignmentSpecificDeadline" label="Assignment Specific Deadline (Optional - Overrides Task Deadline)" type="date" value={assignmentForm.specificDeadline || ''} onChange={e => setAssignmentForm(prev => ({ ...prev, specificDeadline: e.target.value }))} disabled={!selectedTaskForAssignment} /> {assignableTasks.length === 0 && tasks.length > 0 && <p className="text-sm text-neutral mt-2">All tasks are currently assigned, pending acceptance, submitted, or completed.</p>} {tasks.length === 0 && <p className="text-sm text-neutral mt-2">No tasks available. Add tasks first.</p>} {!anyTrulyAvailableUsersForAISuggestion && users.filter(u=>u.role === 'user').length > 0 && ( <p className="text-sm text-warning mt-2">All available users currently have active tasks. Cannot suggest new assignments until tasks are completed.</p> )} <button onClick={fetchAssignmentSuggestion} disabled={!selectedTaskForAssignment || isLoadingSuggestion || !anyTrulyAvailableUsersForAISuggestion} className="w-full btn-accent disabled:bg-gray-300" > {isLoadingSuggestion ? 'Getting Suggestion...' : 'Get AI Suggestion'} </button> {isLoadingSuggestion && <LoadingSpinner />} {assignmentSuggestion && !isLoadingSuggestion && ( <div className={`mt-6 p-4 rounded-md ${assignmentSuggestion.suggestedPersonName ? 'bg-green-50 border-green-300' : 'bg-yellow-50 border-yellow-300'} border`}> <h3 className={`text-lg font-medium ${assignmentSuggestion.suggestedPersonName ? 'text-green-700' : 'text-yellow-700'}`}>AI Suggestion:</h3> {assignmentSuggestion.suggestedPersonName ? ( <> <p className="mt-1 text-sm text-green-600"><strong>Suggested Person:</strong> {assignmentSuggestion.suggestedPersonName}</p> <p className="mt-1 text-sm text-gray-600"><strong>Justification:</strong> {assignmentSuggestion.justification}</p> <button onClick={handleConfirmAssignmentByAdmin} className="mt-4 btn-success">Propose to User</button> </> ) : ( <p className="mt-1 text-sm text-yellow-600"><strong>Note:</strong> {assignmentSuggestion.justification || "AI could not find a suitable candidate or an error occurred."}</p>)} </div> )} </div> </div>);
      case Page.ViewAssignments: const assignmentsToShow = currentUser.role === 'admin' ? assignments : assignments.filter(a => a.personId === currentUser.id); return ( <div> <h2 className="text-2xl font-semibold mb-6 text-purple-600 flex items-center"><CheckCircleIcon className="w-7 h-7 mr-2" /> {currentUser.role === 'admin' ? 'All Assignments' : 'My Assignments'} ({assignmentsToShow.length})</h2> {assignmentsToShow.length === 0 ? <p className="text-neutral">No assignments found.</p> : ( <div className="space-y-4"> {assignmentsToShow.sort((a,b) => { const statusOrder = (s: AssignmentStatus) => { if (s === 'pending_acceptance' || s === 'accepted_by_user') return 1; if (s === 'submitted_late' || s === 'submitted_on_time') return 2; return 3; }; if (statusOrder(a.status) !== statusOrder(b.status)) return statusOrder(a.status) - statusOrder(b.status); if (a.deadline && b.deadline) return new Date(a.deadline).getTime() - new Date(b.deadline).getTime(); if (a.userSubmissionDate && b.userSubmissionDate) return new Date(b.userSubmissionDate).getTime() - new Date(a.userSubmissionDate).getTime(); return 0; }).map(a => { const task = tasks.find(t => t.id === a.taskId); let statusText = ''; let statusColorClass = 'bg-neutral'; const isOverdue = a.status === 'accepted_by_user' && a.deadline && new Date() > new Date(new Date(a.deadline).setHours(23,59,59,999)); switch(a.status) { case 'pending_acceptance': statusText = 'Pending Acceptance'; statusColorClass = 'bg-warning text-black'; break; case 'accepted_by_user': statusText = isOverdue ? 'Overdue - In Progress' : 'Accepted - In Progress'; statusColorClass = isOverdue ? 'bg-red-400' : 'bg-blue-500'; break; case 'declined_by_user': statusText = 'Declined by User'; statusColorClass = 'bg-danger'; break; case 'submitted_on_time': statusText = 'Submitted On Time'; statusColorClass = 'bg-green-500'; break; case 'submitted_late': statusText = 'Submitted Late'; statusColorClass = 'bg-orange-500'; break; case 'completed_admin_approved': statusText = 'Completed & Approved'; statusColorClass = 'bg-success'; break; default: statusText = 'Unknown Status'; } return ( <div key={`${a.taskId}-${a.personId}`} className={`bg-surface shadow-lg rounded-lg p-6 border-l-4 ${isOverdue && a.status === 'accepted_by_user' ? 'border-danger' : 'border-transparent'}`}> <div className="flex justify-between items-start"> <h3 className="text-lg font-semibold text-purple-700">{a.taskTitle}</h3> <span className={`text-xs px-2 py-1 rounded-full text-white ${statusColorClass}`}>{statusText}</span> </div> {task?.programName && <p className="text-xs text-blue-500 bg-blue-100 inline-block px-2 py-0.5 rounded-full my-1">Program: {task.programName}</p>} {currentUser.role === 'admin' && <p className="text-sm text-gray-700 mt-1"><strong>Assigned to:</strong> {a.personName}</p> } {a.deadline && <p className={`text-sm mt-1 ${isOverdue && a.status === 'accepted_by_user' ? 'text-danger font-semibold' : 'text-gray-600'}`}><strong>Deadline:</strong> {new Date(a.deadline).toLocaleDateString()}</p>} {a.justification && currentUser.role === 'admin' && <p className="text-xs text-gray-500 mt-2 italic"><strong>AI Justification:</strong> {a.justification}</p>} {a.userSubmissionDate && <p className="text-xs text-gray-500 mt-1"><strong>Submitted:</strong> {new Date(a.userSubmissionDate).toLocaleString()}</p>} {a.userDelayReason && <p className="text-xs text-gray-500 mt-1"><strong>Delay Reason:</strong> {a.userDelayReason}</p>} {currentUser.id === a.personId && a.status === 'pending_acceptance' && ( <div className="mt-4 pt-3 border-t border-gray-200"> <p className="text-sm font-medium text-textlight mb-2">Are you interested in this task?</p> <button onClick={() => handleUserAssignmentResponse(a, true)} className="btn-success mr-2">Yes, Accept Task</button> <button onClick={() => handleUserAssignmentResponse(a, false)} className="btn-danger">No, Decline Task</button> </div> )} {currentUser.id === a.personId && a.status === 'accepted_by_user' && ( <div className="mt-4 pt-3 border-t border-gray-200"> {assignmentToSubmitDelayReason === a.taskId && isOverdue && ( <div className="my-2"> <FormTextarea id={`delay-reason-${a.taskId}`} label="Reason for Late Submission:" value={userSubmissionDelayReason} onChange={(e) => setUserSubmissionDelayReason(e.target.value)} placeholder="Please explain the delay..." required /> </div> )} <button onClick={() => { clearMessages(); if (isOverdue) { if (assignmentToSubmitDelayReason !== a.taskId) { setAssignmentToSubmitDelayReason(a.taskId); setUserSubmissionDelayReason(''); setInfoMessage("Submission is overdue. Please provide a reason for the delay below and click submit again."); return; } else { if (!userSubmissionDelayReason.trim()) { setError("Reason for delay cannot be empty when submitting late."); return; } } } handleCompleteTaskByUser(a, isOverdue ? userSubmissionDelayReason : undefined); }} className="btn-primary" > Mark as Completed / Submit </button> {assignmentToSubmitDelayReason === a.taskId && isOverdue && ( <button onClick={() => { setAssignmentToSubmitDelayReason(null); setUserSubmissionDelayReason(''); clearMessages(); }} className="btn-neutral ml-2" > Cancel Delay Input </button> )} </div> )} {currentUser.role === 'admin' && (a.status === 'submitted_on_time' || a.status === 'submitted_late') && ( <div className="mt-4 pt-3 border-t border-gray-200"> <button onClick={() => handleAdminApproveCompletion(a)} className="btn-success">Approve & Close Task</button> </div> )} {currentUser.role === 'admin' && a.status !== 'completed_admin_approved' && ( <button onClick={() => handleAdminUnassignTask(a)} className="mt-3 text-sm text-red-500 hover:text-red-700 flex items-center"><TrashIcon className="w-4 h-4 mr-1" /> Unassign / Clear This Assignment</button> )} </div> )})} </div>)} </div>);
      default: 
        console.warn("Reached default case in renderPage, attempting to redirect.", currentPage); 
        navigateTo(currentUser ? (currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments) : Page.Login);
        return <LoadingSpinner />;
    }
  };

  const NavButton: React.FC<{ page?: Page; label: string; icon: React.ReactNode; action?: () => void; isCurrent?: boolean }> = ({ page, label, icon, action, isCurrent }) => ( <button onClick={() => { if(action) action(); else if (page) navigateTo(page); }} className={`flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors duration-150 whitespace-nowrap ${isCurrent ? 'bg-primary text-white shadow-md' : 'text-gray-700 hover:bg-gray-200'}`} aria-current={isCurrent ? 'page' : undefined} > {icon} <span className="ml-2">{label}</span> </button> );
  const UIMessages: React.FC = () => ( <> {error && <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-auto max-w-md p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>} {successMessage && <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-auto max-w-md p-3 bg-green-100 border border-green-400 text-green-700 rounded-md shadow-lg" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>} {infoMessage && <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-auto max-w-lg p-3 bg-blue-100 border border-blue-400 text-blue-700 rounded-md shadow-lg" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>} </> );


  if (currentPage === Page.PreRegistration && !currentUser) {
    return <PreRegistrationFormPage 
              formState={preRegistrationForm}
              setFormState={setPreRegistrationForm}
              onSubmit={handlePreRegistrationSubmit}
              error={error}
              successMessage={successMessage}
              infoMessage={infoMessage}
              clearMessages={clearMessages}
              navigateToLogin={() => {
                setAuthView('login'); 
                navigateTo(Page.Login);
              }}
           />;
  }

  if (!currentUser) {
    // New Authentication Flow UI (Login/Register)
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
        <UIMessages />
        <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-lg my-auto">
          {authView === 'login' ? renderNewAuthLoginPage() : renderNewAuthRegisterPage()}
        </div>
         <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by AI.</p>
          <p className="text-xs mt-1">Note: This is a demo application. Email/SMS notifications are simulated and not actually sent.</p>
        </footer>
      </div>
    );
  }

  // Logged-in User UI
  return (
    <div className="min-h-screen bg-bground main-app-scope">
      <UIMessages />
       <header className="bg-surface shadow-md sticky top-0 z-40">
          <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-3">
            <div className="flex flex-col sm:flex-row justify-between items-center">
              <h1 className="text-2xl sm:text-3xl font-bold text-primary mb-3 sm:mb-0">Task Assignment AI</h1>
              {currentUser && ( <div className="flex items-center space-x-2 sm:space-x-3"> <span className="text-sm text-neutral hidden md:inline">Welcome, {currentUser.displayName}! ({currentUser.role})</span> <button onClick={handleLogout} className="flex items-center px-3 py-2 text-sm font-medium rounded-md text-red-600 hover:bg-red-100 transition-colors duration-150" aria-label="Logout"> <LogoutIcon className="w-5 h-5"/><span className="ml-1 sm:ml-2">Logout</span> </button> </div> )}
            </div>
            {currentUser && ( <nav className="mt-3 flex space-x-1 sm:space-x-2 overflow-x-auto pb-2 sm:pb-0"> 
            {currentUser.role === 'admin' && <NavButton page={Page.Dashboard} label="Dashboard" icon={<KeyIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.Dashboard} />}
            <NavButton label="My Profile" icon={<UserCircleIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.UserProfile} action={() => { navigateTo(Page.UserProfile); }} /> 
            {currentUser.role === 'admin' && ( <> <NavButton page={Page.UserManagement} label="Users" icon={<UsersIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.UserManagement} action={() => { setUserForm(initialUserFormData); setEditingUserId(null); setApprovingPendingUser(null); setGeneratedLink(''); navigateTo(Page.UserManagement); }}/> <NavButton page={Page.ManagePrograms} label="Programs" icon={<BriefcaseIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.ManagePrograms} /> <NavButton page={Page.ManageTasks} label="Manage Tasks" icon={<ClipboardListIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.ManageTasks} action={() => {setTaskForm({ title: '', description: '', requiredSkills: '', programId: '', deadline: '' }); clearMessages(); navigateTo(Page.ManageTasks); }}/> <NavButton page={Page.AssignWork} label="Assign AI" icon={<LightBulbIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.AssignWork} action={() => {setSelectedTaskForAssignment(null); setAssignmentSuggestion(null); setAssignmentForm({ specificDeadline: ''}); clearMessages(); navigateTo(Page.AssignWork);}} /> </> )} 
            {currentUser.role === 'user' && ( <NavButton page={Page.ViewTasks} label="Available Tasks" icon={<ClipboardListIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.ViewTasks} /> )} 
            <NavButton page={Page.ViewAssignments} label={currentUser.role === 'admin' ? "All Assignments" : "My Assignments"} icon={<CheckCircleIcon className="w-4 h-4 sm:w-5 sm:h-5" />} isCurrent={currentPage === Page.ViewAssignments} action={() => { setUserSubmissionDelayReason(''); setAssignmentToSubmitDelayReason(null); clearMessages(); navigateTo(Page.ViewAssignments);}} /> </nav> )}
          </div>
        </header>
      
      <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {renderPage()}
      </main>
      
       <footer className="text-center py-6 text-sm text-neutral border-t border-gray-200 mt-12">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by SHAIK MOHAMMED NAWAZ.</p>
          
        </footer>
    </div>
  );

