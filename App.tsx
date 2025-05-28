// --- FORM COMPONENTS ---
import React, { useState, useEffect, useCallback } from 'react';
import { Page, User, PendingUser, GeminiSuggestion } from './types';
import PreRegistrationFormPage from './components/PreRegistrationFormPage';
import AdminLoginPage from './components/AdminLoginPage';
import { sendApprovalEmail } from './src/utils/emailService';


import Modal from './components/Modal';

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

const FormInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label: string; id: string }> = ({ label, id, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <input id={id} {...props} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" />
  </div>
);

const FormTextarea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; id: string }> = ({ label, id, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <textarea id={id} {...props} rows={3} className="mt-1 block w-full px-3 py-2 border border-neutral rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm bg-surface text-textlight" />
  </div>
);

const FormSelect: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { label: string; id: string; children: React.ReactNode }> = ({ label, id, children, ...props }) => (
  <div>
    <label htmlFor={id} className="block text-sm font-medium text-textlight">{label}</label>
    <select id={id} {...props} className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-neutral focus:outline-none focus:ring-primary focus:border-primary sm:text-sm rounded-md bg-surface text-textlight">
      {children}
    </select>
  </div>
);

// --- MAIN APP COMPONENT ---
const App: React.FC = () => {
  const [page, setPage] = useState<Page>('login');
  const [showSuccessModal, setShowSuccessModal] = useState<boolean>(false);
  const [isAdminLoggedIn, setIsAdminLoggedIn] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  const [preRegistrationForm, setPreRegistrationForm] = useState({
    email: '', uniqueId: '', displayName: '', password: '', confirmPassword: '',
    referringAdminId: '', referringAdminDisplayName: '', isReferralLinkValid: false,
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
        role: 'user',
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

  if (page === 'adminLogin') {
    return <AdminLoginPage onLogin={() => { setIsAdminLoggedIn(true); setPage('userManagement'); }} />;
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
