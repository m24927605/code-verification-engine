import React from 'react';
import { Navigate } from 'react-router-dom';

interface Props {
  isAuthenticated: boolean;
  children: React.ReactNode;
}

export const PrivateRoute: React.FC<Props> = ({ isAuthenticated, children }) => {
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
};
