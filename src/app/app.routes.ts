import { Routes } from '@angular/router';
import { SigninComponent } from './signin/signin';
import { RegistrationComponent } from './registration/registration';
import { DashboardComponent } from './dashboard/dashboard';
import { authGuard } from './guards/auth.guard';
import { signedOutGuard } from './guards/signed-out.guard';

export const routes: Routes = [
  // Redirect root to sign-in
  { path: '', pathMatch: 'full', redirectTo: 'sign-in' },

  // Sign In route
  { path: 'sign-in', component: SigninComponent, canActivate: [signedOutGuard] },

  // Registration route
  { path: 'register', component: RegistrationComponent },

  // Dashboard (protected)
  { path: 'dashboard', component: DashboardComponent, canActivate: [authGuard] },

  // Wildcard
  { path: '**', redirectTo: 'sign-in' },
];
