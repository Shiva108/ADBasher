// API and WebSocket configuration
// Supports environment variables for different deployment scenarios

const API_BASE_URL = import.meta.env.VITE_API_URL || "/api";
const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || window.location.origin;

export { API_BASE_URL, SOCKET_URL };
