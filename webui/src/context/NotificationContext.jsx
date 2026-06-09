import React, { createContext, useContext, useState, useCallback } from 'react';
import { ToastNotification } from '@carbon/react';

const NotificationContext = createContext();

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);

  const addNotification = useCallback((kind, title, subtitle, timeout = 4500) => {
    const id = Date.now() + Math.random().toString(36).substr(2, 9);
    setNotifications(prev => [...prev, { id, kind, title, subtitle, timeout }]);
  }, []);

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  return (
    <NotificationContext.Provider value={{ addNotification }}>
      {children}
      <div style={{ position: 'fixed', top: '3rem', right: '1rem', zIndex: 9999, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {notifications.map(notif => (
          <ToastNotification
            key={notif.id}
            kind={notif.kind}
            title={notif.title}
            subtitle={notif.subtitle}
            timeout={notif.timeout}
            onCloseButtonClick={() => removeNotification(notif.id)}
            caption=""
            lowContrast={false}
          />
        ))}
      </div>
    </NotificationContext.Provider>
  );
}

export const useNotification = () => useContext(NotificationContext);
