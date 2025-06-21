
import React, { useState, useEffect, useRef } from 'react';
import { Page, User } from '../types'; // Adjust path as needed
import {
  BriefcaseIcon,
  UserCircleIcon,
  LogoutIcon,
  Bars3Icon,
  XMarkIcon,
  LightBulbIcon, // Retained for consistency, though HomeIcon is used for Dashboard now
  UsersIcon,
  ClipboardListIcon,
  CheckCircleIcon,
  PlusCircleIcon,
  Cog6ToothIcon,
  HomeIcon // Added for Dashboard
} from './Icons'; // Corrected to relative path

interface TopNavbarProps {
  currentUser: User;
  currentPage: Page;
  navigateTo: (page: Page, params?: Record<string, string>) => void;
  handleLogout: () => void;
}

interface NavItem {
  page: Page;
  label: string;
  icon: JSX.Element;
  adminOnly?: boolean;
  userOnly?: boolean;
}

const TopNavbar: React.FC<TopNavbarProps> = ({ currentUser, currentPage, navigateTo, handleLogout }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  
  const userMenuRef = useRef<HTMLDivElement>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null); 
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
      if (mobileMenuButtonRef.current && !mobileMenuButtonRef.current.contains(event.target as Node)) {
         if (isMobileMenuOpen && mobileMenuRef.current && !mobileMenuRef.current.contains(event.target as Node)) {
            setIsMobileMenuOpen(false);
         }
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isMobileMenuOpen]);


  const navItems: NavItem[] = [
    { page: Page.Dashboard, label: "Dashboard", icon: <HomeIcon className="w-5 h-5" />, adminOnly: true },
    { page: Page.UserManagement, label: "Users", icon: <UsersIcon className="w-5 h-5" />, adminOnly: true },
    { page: Page.ManagePrograms, label: "Programs", icon: <ClipboardListIcon className="w-5 h-5" />, adminOnly: true },
    { page: Page.ManageTasks, label: "Manage Tasks", icon: <CheckCircleIcon className="w-5 h-5" />, adminOnly: true },
    { page: Page.AssignWork, label: "Assign Work", icon: <PlusCircleIcon className="w-5 h-5" />, adminOnly: true },
    { page: Page.ViewAssignments, label: "My Assignments", icon: <ClipboardListIcon className="w-5 h-5" /> },
    { page: Page.ViewTasks, label: "Available Tasks", icon: <CheckCircleIcon className="w-5 h-5" /> },
  ];

  const filteredNavItems = navItems.filter(item => {
    if (item.adminOnly && currentUser.role !== 'admin') return false;
    if (item.userOnly && currentUser.role !== 'user') return false;
    return true;
  });

  const desktopLinkClasses = (page: Page) => `
    flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors
    ${currentPage === page ? 'bg-primary text-white shadow-sm' : 'text-textlight hover:bg-bground hover:text-primary'}
  `;
  
  const mobileLinkClasses = (page: Page) => `
    flex items-center px-3 py-2 rounded-md text-base font-medium transition-colors
    ${currentPage === page ? 'bg-primary text-white shadow-sm' : 'text-textlight hover:bg-bground hover:text-primary'}
  `;

  return (
    <nav className="bg-surface shadow-lg sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Left side: Logo and Desktop Nav Links */}
          <div className="flex items-center">
            <button
              onClick={() => navigateTo(currentUser.role === 'admin' ? Page.Dashboard : Page.ViewAssignments)}
              className="flex-shrink-0 flex items-center text-primary hover:opacity-80 transition-opacity"
              aria-label="Go to dashboard"
            >
              <BriefcaseIcon className="block h-8 w-auto text-secondary" />
              <span className="ml-2 font-semibold text-xl text-textlight">TAA</span>
            </button>
            <div className="hidden md:ml-6 md:flex md:space-x-1 lg:space-x-3">
              {filteredNavItems.map(item => (
                <button
                  key={item.page}
                  onClick={() => navigateTo(item.page)}
                  className={desktopLinkClasses(item.page)}
                  aria-current={currentPage === item.page ? 'page' : undefined}
                >
                  {React.cloneElement(item.icon, { className: "mr-1.5 h-5 w-5 hidden sm:inline-block"})}
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          {/* Right side: User Menu and Mobile Menu Button */}
          <div className="flex items-center">
            <div className="relative ml-3" ref={userMenuRef}>
              <button
                type="button"
                className="max-w-xs bg-surface flex items-center text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-bground focus:ring-primary p-1"
                id="user-menu-button"
                aria-expanded={isUserMenuOpen}
                aria-haspopup="true"
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
              >
                <span className="sr-only">Open user menu</span>
                <UserCircleIcon className="h-8 w-8 text-neutral hover:text-primary transition-colors" />
                <span className="ml-2 hidden sm:inline text-sm text-textlight font-medium hover:text-primary transition-colors">{currentUser.displayName}</span>
              </button>
              {isUserMenuOpen && (
                <div
                  className="origin-top-right absolute right-0 mt-2 w-56 rounded-md shadow-xl py-1 bg-surface ring-1 ring-neutral ring-opacity-20 focus:outline-none"
                  role="menu"
                  aria-orientation="vertical"
                  aria-labelledby="user-menu-button"
                >
                  <div className="px-4 py-3 border-b border-bground">
                    <p className="text-sm font-medium text-textlight truncate">{currentUser.displayName}</p>
                    <p className="text-xs text-neutral truncate">{currentUser.email}</p>
                  </div>
                  <button
                    onClick={() => { navigateTo(Page.UserProfile); setIsUserMenuOpen(false); }}
                    className="w-full text-left px-4 py-2 text-sm text-textlight hover:bg-bground hover:text-primary transition-colors flex items-center"
                    role="menuitem"
                  >
                    <Cog6ToothIcon className="w-5 h-5 mr-2 text-neutral" /> My Profile
                  </button>
                  <button
                    onClick={() => { handleLogout(); setIsUserMenuOpen(false); }}
                    className="w-full text-left px-4 py-2 text-sm text-danger hover:bg-red-50 hover:text-red-700 transition-colors flex items-center"
                    role="menuitem"
                  >
                   <LogoutIcon className="w-5 h-5 mr-2" /> Logout
                  </button>
                </div>
              )}
            </div>

            <div className="ml-2 -mr-2 flex md:hidden">
              <button
                ref={mobileMenuButtonRef} 
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                type="button"
                className="bg-surface inline-flex items-center justify-center p-2 rounded-md text-neutral hover:text-primary hover:bg-bground focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary"
                aria-controls="mobile-menu"
                aria-expanded={isMobileMenuOpen}
                id="mobile-menu-button"
              >
                <span className="sr-only">Open main menu</span>
                {isMobileMenuOpen ? (
                  <XMarkIcon className="block h-6 w-6" aria-hidden="true" />
                ) : (
                  <Bars3Icon className="block h-6 w-6" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <div className="md:hidden border-t border-bground" id="mobile-menu" ref={mobileMenuRef}>
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            {filteredNavItems.map(item => (
              <button
                key={item.page}
                onClick={() => { navigateTo(item.page); setIsMobileMenuOpen(false); }}
                className={mobileLinkClasses(item.page)}
                aria-current={currentPage === item.page ? 'page' : undefined}
              >
                {React.cloneElement(item.icon, { className: "mr-3 h-5 w-5" })}
                {item.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </nav>
  );
};

export default TopNavbar;
