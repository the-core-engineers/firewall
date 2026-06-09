import React, { createContext, useContext, useState, useCallback } from "react";
import { ToastNotification } from "@carbon/react";

const NotificationContext = createContext();

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);

  const addNotification = useCallback(
    (kind, title, subtitle, timeout = 3500) => {
      const id = Date.now();

      // Replace any existing notification
      setNotifications([
        {
          id,
          kind,
          title,
          subtitle,
          timeout,
        },
      ]);
    },
    [],
  );

  const removeNotification = useCallback((id) => {
    setNotifications((prev) =>
      prev.filter((notification) => notification.id !== id),
    );
  }, []);

  return (
    <NotificationContext.Provider value={{ addNotification }}>
      {children}

      <div
        style={{
          position: "fixed",
          top: "4rem",
          left: "50%",
          transform: "translateX(-50%)",
          zIndex: 9999,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "0.5rem",
          pointerEvents: "none",
        }}
      >
        {notifications.map((notification) => (
          <div
            key={notification.id}
            style={{
              width: "420px",
              maxWidth: "90vw",
              pointerEvents: "auto",
            }}
          >
            <ToastNotification
              kind={notification.kind}
              title={notification.title}
              subtitle={notification.subtitle}
              timeout={notification.timeout}
              onCloseButtonClick={() => removeNotification(notification.id)}
              caption=""
              lowContrast={false}
            />
          </div>
        ))}
      </div>
    </NotificationContext.Provider>
  );
}

export const useNotification = () => useContext(NotificationContext);
