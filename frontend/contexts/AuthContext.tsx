import React, { createContext, useState, useContext, useEffect } from 'react';
import { getUser } from '../services/api';

interface AuthContextType {
  user: any;
  token: string | null;
  setToken: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  setToken: () => {},
  logout: () => {},
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [token, setTokenState] = useState<string | null>(null);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (storedToken) {
      setTokenState(storedToken);
    }
  }, []);

  useEffect(() => {
    if (user) {
      console.log('user', user);
    }
  }, [user]);

  useEffect(() => {
    if (token) {
      localStorage.setItem('token', token);
      getUser(token).then(setUser).catch(console.error);
    } else {
      localStorage.removeItem('token');
      setUser(null);
    }
  }, [token]);

  const setToken = (newToken: string) => {
    setTokenState(newToken);
  };

  const logout = () => {
    setTokenState(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, setToken, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
