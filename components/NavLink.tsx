import React from 'react';
import { Page } from '../types'; // Adjust path as needed

interface NavLinkProps {
  page: Page;
  current: Page;
  icon?: React.ReactNode;
  children: React.ReactNode;
  navigateTo: (page: Page, params?: Record<string, string>) => void;
  params?: Record<string, string>;
  className?: string; // Allow custom classes for layout
}

const NavLink: React.FC<NavLinkProps> = ({ page, current, icon, children, navigateTo, params, className }) => {
  const baseClasses = "flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors duration-150 ease-in-out";
  const activeClasses = "bg-primary text-white shadow-md";
  const inactiveClasses = "text-textlight hover:bg-bground hover:text-primary";
  
  // Specific styling for topbar context
  const isTopBarLink = className?.includes('top-nav-link-style');
  const topBarActiveClasses = "bg-blue-700 text-white";
  const topBarInactiveClasses = "text-white hover:bg-blue-700 hover:text-white";


  let currentStyling = current === page ? activeClasses : inactiveClasses;
  if (isTopBarLink) {
    currentStyling = current === page ? topBarActiveClasses : topBarInactiveClasses;
  }


  return (
    <button
      onClick={() => navigateTo(page, params)}
      className={`${baseClasses} ${currentStyling} ${className || ''}`}
      aria-current={current === page ? 'page' : undefined}
    >
      {icon && <span className="flex-shrink-0 w-5 h-5">{icon}</span>}
      <span>{children}</span>
    </button>
  );
};

export default NavLink;