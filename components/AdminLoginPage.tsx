
import React from 'react';

interface AdminLoginPageProps {
  onLogin: () => void;
}

const AdminLoginPage: React.FC<AdminLoginPageProps> = ({ onLogin }) => {
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    // Basic validation or data handling can be added here
    // For now, directly call onLogin as a placeholder
    onLogin();
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-authPageBg p-4">
      <div className="bg-surface p-8 rounded-xl shadow-2xl w-full max-w-md">
        <h2 className="text-2xl font-bold text-textlight mb-6 text-center">Admin Login</h2>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="admin-email" className="block text-sm font-medium text-textlight">
              Email Address
            </label>
            <input
              id="admin-email"
              name="email"
              type="email"
              autoComplete="email"
              required
              className="mt-1 block w-full px-3 py-2 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm text-textlight placeholder-neutral"
              placeholder="admin@example.com"
              defaultValue="admin@example.com" // Default for demo ease
            />
          </div>

          <div>
            <label htmlFor="admin-password" className="block text-sm font-medium text-textlight">
              Password
            </label>
            <input
              id="admin-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              className="mt-1 block w-full px-3 py-2 bg-authFormBg border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary sm:text-sm text-textlight placeholder-neutral"
              placeholder="password"
              defaultValue="password" // Default for demo ease
            />
          </div>

          <div>
            <button
              type="submit"
              className="w-full py-3 px-4 bg-authButton hover:bg-authButtonHover text-textlight font-semibold rounded-md shadow-sm transition-colors text-sm"
            >
              Sign in
            </button>
          </div>
        </form>
      </div>
      <footer className="text-center py-6 text-sm text-neutral mt-auto">
          <p>&copy; {new Date().getFullYear()} Task Assignment Assistant. Powered by SHAIK MOHAMMED NAWAZ.</p>
      </footer>
    </div>
  );
};

export default AdminLoginPage;
