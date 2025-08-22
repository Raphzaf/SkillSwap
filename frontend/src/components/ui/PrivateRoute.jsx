import { Navigate, Outlet } from "react-router-dom";
import { isAuthenticated } from "../lib/auth";
export default function PrivateRoute() {
  return isAuthenticated() ? <Outlet/> : <Navigate to="/onboarding" replace />;}