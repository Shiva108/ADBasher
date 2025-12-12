// API client using native Fetch API (replaces axios)
const DEFAULT_HEADERS = {
  "Content-Type": "application/json",
};

class APIClient {
  constructor(baseURL = "") {
    this.baseURL = baseURL;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;

    const config = {
      headers: {
        ...DEFAULT_HEADERS,
        ...options.headers,
      },
      ...options,
    };

    // Automatically stringify body if it's an object
    if (config.body && typeof config.body === "object") {
      config.body = JSON.stringify(config.body);
    }

    try {
      const response = await fetch(url, config);

      // Handle HTTP errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.error || response.statusText || `HTTP ${response.status}`
        );
      }

      // Handle empty responses
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        return response;
      }

      return await response.json();
    } catch (error) {
      // Network errors or parsing errors
      if (error.name === "TypeError" && error.message === "Failed to fetch") {
        throw new Error("Network error: Unable to reach server");
      }
      throw error;
    }
  }

  // Convenience methods
  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: "GET" });
  }

  post(endpoint, data, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: "POST",
      body: data,
    });
  }

  put(endpoint, data, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: "PUT",
      body: data,
    });
  }

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: "DELETE" });
  }

  patch(endpoint, data, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: "PATCH",
      body: data,
    });
  }
}

// Create default instance
const api = new APIClient("/api");

export default api;
export { APIClient };
