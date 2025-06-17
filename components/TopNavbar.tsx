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

interface TopNavbarProps {
  currentUser: User;
  currentPage: Page;
  navigateTo: (page: Page, params?: Record<string, string>) => void;
  handleLogout: () => void;
}

const TopNavbar: React.FC<TopNavbarProps> = ({ currentUser, currentPage, navigateTo, handleLogout }) => {
  const navLinkBaseClass = "top-nav-link-style px-2 py-1.5 md:px-3 md:py-1.5"; // Added md prefix for slightly larger padding on medium screens
  const iconBaseClass = "w-4 h-4 md:w-5 md:h-5 mr-1 md:mr-1.5"; // Responsive icon size

  return (
    <header className="bg-primary text-white shadow-lg flex items-center justify-between p-3 sticky top-0 z-50">
      {/* Left Section: Logo and Title */}
      <div className="flex items-center flex-shrink-0">
        <BriefcaseIcon className="w-7 h-7 md:w-8 md:h-8 mr-2 text-white" />
        <h1 className="text-lg md:text-xl font-semibold text-white hidden sm:block">TAA</h1>
        <p className="text-xs text-blue-200 ml-2 hidden lg:block">Task Assignment Assistant</p>
      </div>

      {/* Center Section: Navigation Links */}
      <nav className="flex-grow flex justify-center items-center space-x-1 md:space-x-1.5 overflow-x-auto">
        {currentUser.role === 'admin' && (
          <>
            <NavLink page={Page.Dashboard} current={currentPage} icon={<LightBulbIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Dashboard</NavLink>
            <NavLink page={Page.UserManagement} current={currentPage} icon={<UsersIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Users</NavLink>
            <NavLink page={Page.ManagePrograms} current={currentPage} icon={<ClipboardListIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Programs</NavLink>
            <NavLink page={Page.ManageTasks} current={currentPage} icon={<CheckCircleIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Tasks</NavLink>
            <NavLink page={Page.AssignWork} current={currentPage} icon={<PlusCircleIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Assign</NavLink>
          </>
        )}
        <NavLink page={Page.ViewAssignments} current={currentPage} icon={<ClipboardListIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>My Assignments</NavLink>
        <NavLink page={Page.ViewTasks} current={currentPage} icon={<CheckCircleIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Available Tasks</NavLink>
        <NavLink page={Page.UserProfile} current={currentPage} icon={<UserCircleIcon className={iconBaseClass}/>} navigateTo={navigateTo} className={navLinkBaseClass}>Profile</NavLink>
      </nav>

      {/* Right Section: User Info and Logout */}
      <div className="flex items-center space-x-2 md:space-x-3 flex-shrink-0">
        <div className="text-right hidden md:block">
            <p className="text-sm font-medium text-white truncate max-w-[100px] lg:max-w-[150px]" title={currentUser.displayName}>{currentUser.displayName}</p>
            <p className="text-xs text-blue-200 capitalize truncate  max-w-[100px] lg:max-w-[150px]" title={currentUser.position}>{currentUser.position}</p>
        </div>
         <UserCircleIcon className="w-7 h-7 md:w-8 md:h-8 text-white block md:hidden" title={`${currentUser.displayName} (${currentUser.position})`}/>
        <button
          onClick={handleLogout}
          className="flex items-center justify-center p-1.5 md:px-3 md:py-1.5 border border-transparent rounded-md shadow-sm text-xs md:text-sm font-medium text-white bg-danger hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-primary focus:ring-danger transition-colors"
          aria-label="Logout"
          title="Logout"
        >
          <LogoutIcon className="w-4 h-4 md:w-5 md:h-5 md:mr-1.5" />
          <span className="hidden md:inline">Logout</span>
        </button>
      </div>
    </header>
  );
};

export default TopNavbar;