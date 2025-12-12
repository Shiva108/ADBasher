// Toast notification utilities
import toast from "react-hot-toast";

/**
 * Show success toast notification
 */
export const showSuccess = (message) => {
  toast.success(message, {
    duration: 4000,
    position: "top-right",
    style: {
      background: "#064e3b",
      color: "#d1fae5",
      border: "1px solid #047857",
    },
  });
};

/**
 * Show error toast notification
 */
export const showError = (message) => {
  toast.error(message, {
    duration: 5000,
    position: "top-right",
    style: {
      background: "#7f1d1d",
      color: "#fecaca",
      border: "1px solid #991b1b",
    },
  });
};

/**
 * Show warning toast notification
 */
export const showWarning = (message) => {
  toast(
    (t) => (
      <div className="flex items-center">
        <span className="text-amber-400 mr-2">⚠️</span>
        <span>{message}</span>
      </div>
    ),
    {
      duration: 4500,
      position: "top-right",
      style: {
        background: "#78350f",
        color: "#fef3c7",
        border: "1px solid #92400e",
      },
    }
  );
};

/**
 * Show info toast notification
 */
export const showInfo = (message) => {
  toast(
    (t) => (
      <div className="flex items-center">
        <span className="text-blue-400 mr-2">ℹ️</span>
        <span>{message}</span>
      </div>
    ),
    {
      duration: 4000,
      position: "top-right",
      style: {
        background: "#1e3a8a",
        color: "#dbeafe",
        border: "1px solid #1e40af",
      },
    }
  );
};

/**
 * Show loading toast (returns toast ID for dismissal)
 */
export const showLoading = (message) => {
  return toast.loading(message, {
    position: "top-right",
    style: {
      background: "#1e293b",
      color: "#e2e8f0",
      border: "1px solid #334155",
    },
  });
};

/**
 * Dismiss a specific toast
 */
export const dismissToast = (toastId) => {
  toast.dismiss(toastId);
};

/**
 * Show validation error toast
 */
export const showValidationError = (field, message) => {
  showError(`${field}: ${message}`);
};
