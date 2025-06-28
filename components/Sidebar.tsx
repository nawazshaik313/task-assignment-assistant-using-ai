import React from 'react';
import { Page, User } from '../types'; // Adjust path as needed
import NavLink from './NavLink'; // Adjust path as needed
import {
  UsersIcon,
  ClipboardListIcon,
  LightBulbIcon,
  CheckCircleIcon,
  PlusCircleIcon,
  BriefcaseIcon,
  LogoutIcon,
  UserCircleIcon
} from './Icons'; // Adjust path as needed

interface SidebarProps {
  currentUser: User;
  currentPage: Page;
  navigateTo: (page: Page, params?: Record<string, string>) => void;
  handleLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ currentUser, currentPage, navigateTo, handleLogout }) => {
  return (
    <aside className="w-64 bg-surface text-textlight flex flex-col shadow-lg overflow-y-auto">
      <div className="p-4 border-b border-gray-200">
        <h1 className="text-2xl font-semibold text-primary flex items-center">
          <BriefcaseIcon className="w-7 h-7 mr-2 text-secondary" /> TAA
        </h1>
        <p className="text-xs text-neutral mt-1">Task Assignment Assistant</p>
      </div>
      <nav className="flex-grow p-3 space-y-1.5">
        {currentUser.role === 'admin' && (
          <>
            <NavLink page={Page.Dashboard} current={currentPage} icon={<LightBulbIcon />} navigateTo={navigateTo}>Dashboard</NavLink>
            <NavLink page={Page.UserManagement} current={currentPage} icon={<UsersIcon />} navigateTo={navigateTo}>User Management</NavLink>
            <NavLink page={Page.ManagePrograms} current={currentPage} icon={<ClipboardListIcon />} navigateTo={navigateTo}>Manage Programs</NavLink>
            <NavLink page={Page.ManageTasks} current={currentPage} icon={<CheckCircleIcon />} navigateTo={navigateTo}>Manage Tasks</NavLink>
            <NavLink page={Page.AssignWork} current={currentPage} icon={<PlusCircleIcon />} navigateTo={navigateTo}>Assign Work</NavLink>
          </>
        )}
        <NavLink page={Page.ViewAssignments} current={currentPage} icon={<ClipboardListIcon />} navigateTo={navigateTo}>My Assignments</NavLink>
        <NavLink page={Page.ViewTasks} current={currentPage} icon={<CheckCircleIcon />} navigateTo={navigateTo}>Available Tasks</NavLink>
        <NavLink page={Page.UserProfile} current={currentPage} icon={<UserCircleIcon />} navigateTo={navigateTo}>My Profile</NavLink>
      </nav>
      <div className="p-4 mt-auto border-t border-gray-200">
        <div className="flex items-center mb-3">
          <UserCircleIcon className="w-8 h-8 mr-2 text-neutral" />
          <div>
            <p className="text-sm font-medium text-textlight">{currentUser.displayName}</p>
            <p className="text-xs text-neutral capitalize">
              {currentUser.role} / {currentUser.position?.substring(0, 20)}{currentUser.position && currentUser.position.length > 20 ? '...' : ''}
            </p>
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
  );
};

export default Sidebar;
