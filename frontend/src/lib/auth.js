export const getToken = () => localStorage.getItem("accessToken");
export const isAuthenticated = () => !!getToken();