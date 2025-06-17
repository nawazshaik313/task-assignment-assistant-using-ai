import React from 'react';
import { Page } from '../types'; // Adjust path as needed

interface NavLinkProps {
  page: Page;
  current: Page;
  icon?: React.ReactNode;
  children: React.ReactNode;
  navigateTo: (page: Page, params?: Record<string, string>) => void;
  params?: Record<string, string>;
}

const NavLink: React.FC<NavLinkProps> = ({ page, current, icon, children, navigateTo, params }) => {
  return (
    <button
      onClick={() => navigateTo(page, params)}
      className={`flex items-center space-x-3 px-3 py-2.5 rounded-md text-sm font-medium w-full text-left transition-colors duration-150 ease-in-out
                  ${current === page ? 'bg-primary text-white shadow-md' : 'text-textlight hover:bg-bground hover:text-primary'}`}
      aria-current={current === page ? 'page' : undefined}
    >
      {icon && <span className="flex-shrink-0 w-5 h-5">{icon}</span>}
      <span>{children}</span>
    </button>
  );
};

export default NavLink;
