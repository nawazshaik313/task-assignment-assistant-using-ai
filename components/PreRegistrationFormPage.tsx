
import React from 'react';
import { Page } from '../types'; // Adjust path as needed
import LoadingSpinner from './LoadingSpinner';

interface PreRegistrationFormState {
  uniqueId: string;
  displayName: string;
  email: string; // Added
  password: string; // Added
  confirmPassword: string; // Added
  referringAdminId: string;
  referringAdminDisplayName: string;
  isReferralLinkValid: boolean;
}

interface PreRegistrationFormPageProps {
  formState: PreRegistrationFormState;
  setFormState: React.Dispatch<React.SetStateAction<PreRegistrationFormState>>;
  onSubmit: (e: React.FormEvent) => void;
  error: string | null;
  successMessage: string | null;
  infoMessage: string | null;
  clearMessages: () => void;
  navigateToLogin: () => void;
  isVerifyingLink: boolean;
}

const passwordRequirementsText = "Must be at least 8 characters and include an uppercase letter, a lowercase letter, a number, and a special character (e.g., !@#$%).";

export const PreRegistrationFormPage: React.FC<PreRegistrationFormPageProps> = ({
  formState,
  setFormState,
  onSubmit,
  error,
  successMessage,
  infoMessage,
  clearMessages,
  navigateToLogin,
  isVerifyingLink,
}) => {
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormState(prev => ({ ...prev, [name]: value }));
  };

  const UIMessages: React.FC = () => (
    <>
      {error && <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-md shadow-lg w-full" role="alert"><p><strong className="font-bold">Error:</strong> {error}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
      {successMessage && <div className="mb-4 p-3 bg-green-100 border-green-400 text-green-700 rounded-md shadow-lg w-full" role="alert"><p>{successMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
      {infoMessage && <div className="mb-4 p-3 bg-blue-100 border-blue-400 text-blue-700 rounded-md shadow-lg w-full" role="status"><p>{infoMessage}</p><button onClick={clearMessages} className="ml-2 text-sm font-bold">X</button></div>}
    </>
  );

  if (isVerifyingLink) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
        <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-lg text-center">
            <LoadingSpinner />
            <p className="mt-4 text-textlight">Verifying registration link...</p>
        </div>
      </div>
    );
  }

  if (!formState.isReferralLinkValid && !successMessage) { 
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
        <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-lg text-center">
          <UIMessages />
          <h2 className="text-2xl font-bold text-textlight mb-4">Pre-registration</h2>
          <p className="text-danger mb-6">{error || "This pre-registration link is invalid or has expired. Please request a new link from an administrator."}</p>
          <button
            onClick={navigateToLogin}
            className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
          >
            Go to Login
          </button>
        </div>
        <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by NN.</p>
        </footer>
      </div>
    );
  }
  
  if (successMessage) {
     return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
        <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-lg text-center">
          <UIMessages />
          <h2 className="text-2xl font-bold text-textlight mb-4">Pre-registration Submitted</h2>
           <p className="text-textlight mb-6">Your details have been sent for admin approval. You will be notified once your account is active.</p>
           <button
            onClick={navigateToLogin}
            className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
          >
            Return to Login Page
          </button>
        </div>
        <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by NN.</p>
        </footer>
      </div>
    );
  }


  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-authPageBg p-4">
      <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-lg">
        <UIMessages />
        <h2 className="text-center text-3xl font-bold text-textlight mb-2">User Pre-registration</h2>
        <p className="text-center text-sm text-neutral mb-6">
          You've been invited by <strong>{formState.referringAdminDisplayName || 'an administrator'}</strong>.
          Please provide your desired system identifier, display name, email, and set a password.
        </p>
        <form onSubmit={onSubmit} className="space-y-5">
          <div>
            <label htmlFor="preRegUniqueId" className="block text-sm font-medium text-textlight">Desired System ID / Username</label>
            <input
              id="preRegUniqueId"
              name="uniqueId"
              type="text"
              value={formState.uniqueId}
              onChange={handleInputChange}
              required
              className="mt-1 w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
              placeholder="e.g., jdoe23"
              aria-describedby="uniqueIdHelp"
            />
            <p id="uniqueIdHelp" className="mt-1 text-xs text-neutral">This will be your unique identifier in the system.</p>
          </div>
          <div>
            <label htmlFor="preRegDisplayName" className="block text-sm font-medium text-textlight">Your Full Name (Display Name)</label>
            <input
              id="preRegDisplayName"
              name="displayName"
              type="text"
              value={formState.displayName}
              onChange={handleInputChange}
              required
              className="mt-1 w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
              placeholder="e.g., Jane Doe"
            />
          </div>
           <div>
            <label htmlFor="preRegEmail" className="block text-sm font-medium text-textlight">Email Address</label>
            <input
              id="preRegEmail"
              name="email"
              type="email"
              value={formState.email}
              onChange={handleInputChange}
              required
              autoComplete="email"
              className="mt-1 w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
              placeholder="you@example.com"
            />
          </div>
          <div>
            <label htmlFor="preRegPassword" className="block text-sm font-medium text-textlight">Password</label>
            <input
              id="preRegPassword"
              name="password"
              type="password"
              value={formState.password}
              onChange={handleInputChange}
              required
              autoComplete="new-password"
              className="mt-1 w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
              placeholder="Create a password"
              aria-describedby="passwordHelpPreReg"
            />
            <p id="passwordHelpPreReg" className="mt-1 text-xs text-neutral">{passwordRequirementsText}</p>
          </div>
          <div>
            <label htmlFor="preRegConfirmPassword" className="block text-sm font-medium text-textlight">Confirm Password</label>
            <input
              id="preRegConfirmPassword"
              name="confirmPassword"
              type="password"
              value={formState.confirmPassword}
              onChange={handleInputChange}
              required
              autoComplete="new-password"
              className="mt-1 w-full p-3 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary text-sm text-textlight placeholder-neutral"
              placeholder="Confirm your password"
            />
          </div>
          <button
            type="submit"
            className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
          >
            Submit Pre-registration
          </button>
        </form>
        <p className="text-center text-sm text-textlight mt-6">
          Already have an account or submitted?{' '}
          <button
            type="button"
            onClick={navigateToLogin}
            className="font-medium text-authLink hover:underline"
          >
            Go to Login
          </button>
        </p>
      </div>
      <footer className="text-center py-6 text-sm text-neutral mt-auto">
        <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by NN.</p>
      </footer>
    </div>
  );
};
