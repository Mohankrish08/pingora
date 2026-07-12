import { Routes } from '@angular/router';

export const routes: Routes = [
    { path: '', redirectTo: 'login', pathMatch: 'full' },
    { path: 'login', 
        loadComponent: () => import('./features/auth/login/loginComponent').then(m => m.LoginComponent),
    },
    { path: 'register', 
        loadComponent: () => import('./features/auth/register/register').then(m => m.RegisterComponent),
    }
];
