import React, { createContext, useContext, useState, useCallback } from 'react';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [token, setToken] = useState(localStorage.getItem('fw_token'));
  const [loginError, setLoginError] = useState('');

  const login = async (username, password) => {
    try {
      const res = await fetch('http://localhost:8000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('fw_token', data.access_token);
        setToken(data.access_token);
        setLoginError('');
      } else {
        const errorData = await res.json();
        setLoginError(errorData.detail || 'Invalid credentials');
      }
    } catch (e) {
      setLoginError('Could not connect to server');
    }
  };

  const logout = () => {
    localStorage.removeItem('fw_token');
    setToken(null);
  };

  const authFetch = useCallback(async (path, options = {}) => {
    const headers = {
      'Authorization': `Bearer ${token}`,
      ...options.headers
    };
    const res = await fetch(`http://localhost:8000${path}`, { ...options, headers });
    if (res.status === 401) {
      logout();
    }
    return res;
  }, [token]);

  return (
    <AuthContext.Provider value={{ token, login, logout, authFetch, loginError, setLoginError }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
